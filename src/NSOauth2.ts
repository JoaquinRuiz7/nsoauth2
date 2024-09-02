import {exec} from "child_process";
import {createServer} from "http";
import {parse} from "node:url";
import * as crypto from 'crypto';
import {createHash} from "node:crypto";
import axios from "axios";
import fs from "fs";
import path from "path";
import os from "os";
import {OAuth2TokenDTO} from "./types/OAuth2TokenDTO";
import {GrantType} from "./types/GrantType";
import {Config} from "./types/Config";
import {Scope} from "./types/Scope";

export class NSOauth2 {
    private readonly REVOKE_TOKEN_URL: string = 'https://${accountId}.suitetalk.api.netsuite.com/services/rest/auth/oauth2/v1/revoke';
    private readonly GENERIC_AUTHORIZE_URL: string = 'https://system.netsuite.com/app/login/oauth2/authorize.nl';
    private readonly AUTHORIZE_URL: string = 'https://${accountId}.app.netsuite.com/app/login/oauth2/authorize.nl';
    private readonly PLATFORMS: Record<string, string> = {'darwin': 'open', 'win32': 'start'};
    private readonly TOKENS_PATH: string = path.join(os.homedir(), '.nsoauth2', 'tokens.json');
    private readonly TOKEN_URL: string = 'https://${accountId}.suitetalk.api.netsuite.com/services/rest/auth/oauth2/v1/token';

    private readonly clientId: string;
    private readonly scopes: Scope[];
    private readonly clientSecret: string;
    private readonly accountId?: number;
    private readonly redirectUrl: string;

    constructor(config: Config) {
        this.clientId = config.clientId;
        this.scopes = config.scopes;
        this.clientSecret = config.clientSecret;
        this.accountId = config.accountId;
        this.redirectUrl = config.redirectUrl;
    }

    public async getAccessToken(tokenName: string) {
        const tokens: Record<string, OAuth2TokenDTO> = this.getTokens();

        if (!tokens) {
            await this.generateAccessToken(tokenName);
            return;
        }

        const token: OAuth2TokenDTO = tokens[tokenName];

        if (!token) {
            await this.generateAccessToken(tokenName);
            return;
        }

        const isTokenExpired: boolean = this.isAccessTokenExpired(token);
        if (!isTokenExpired) {
            console.log(`Access token ${tokenName} still valid.`);
            return tokens[tokenName].access_token;
        }

        await this.refreshAccessToken(tokenName);
    }

    public async revokeRefreshToken(tokenName: string) {
        const tokens: Record<string, OAuth2TokenDTO> = this.getTokens();
        if (!tokens) {
            console.log('No tokens generated yet.')
            return;
        }

        const token: OAuth2TokenDTO = tokens[tokenName];
        const params: Map<string, string> = new Map();
        params.set('token', token.refresh_token);

        await this.performPostRequest(token.account, params, this.REVOKE_TOKEN_URL);
        this.deleteToken(tokenName);
        console.log(`Token ${tokenName} revoked successfully`);
    }

    private isAccessTokenExpired(token: OAuth2TokenDTO): boolean {
        const currentTime: number = Date.now();
        const expiresAt: number = token.issued_at + (token.expires_in * 1000);
        return currentTime >= expiresAt;
    }

    private async generateAccessToken(tokenName: string) {
        const codeVerifier: string = await this.authorizeOAuth2();
        const response: any = await this.startServer();
        await this.getAuthorizedToken(tokenName, response.company, response.code, codeVerifier);
    }

    private async authorizeOAuth2(): Promise<string> {
        const url: URL = new URL(this.accountId ? this.AUTHORIZE_URL.replace('${accountId}', this.accountId + '') : this.GENERIC_AUTHORIZE_URL);
        const searchParams: URLSearchParams = new URLSearchParams();

        searchParams.append('response_type', 'code');
        searchParams.append('client_id', this.clientId);
        searchParams.append('redirect_uri', this.redirectUrl);
        searchParams.append('scope', this.scopes.join(' '));
        searchParams.append('state', this.generateState());

        const codeVerifier = this.generateCodeVerifier();
        const codeChallenge = this.generateCodeChallenge(codeVerifier);

        searchParams.append('code_challenge', codeChallenge);
        searchParams.append('code_challenge_method', 'S256');

        url.search = searchParams.toString();
        const command: string = this.getOpenCommand();
        const fullCommand: string = `${command} "${url.toString()}"`;

        exec(fullCommand).on('error', (err) => {
            console.error('Error opening browser:', err);
        });

        console.log('Please authorize the token in your browser.');
        return codeVerifier;
    }

    private async performPostRequest(accountId: string, params: Map<string, string>, url: string): Promise<any> {
        const urlParams: URLSearchParams = new URLSearchParams();

        params.forEach((value, key) => {
            urlParams.append(key, value);
        });

        const credentials: string = `${this.clientId}:${this.clientSecret}`;
        const encodedCredentials: string = Buffer.from(credentials).toString('base64');

        try {
            return await axios.post(
                url.replace('${accountId}', accountId),
                urlParams.toString(),
                {
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'Authorization': `Basic ${encodedCredentials}`
                    }
                }
            );
        } catch (error) {
            console.error('Error performing POST request:', error.response?.data || error.message);
            console.log(`Data: \n ${urlParams}`)
            throw new Error('POST request failed');
        }
    }

    private async getAuthorizedToken(tokenName: string, account: string, code: string, codeVerifier: string): Promise<OAuth2TokenDTO> {

        const params: Map<string, string> = new Map();
        params.set('code', code);
        params.set('grant_type', GrantType.AUTHORIZATION_TOKEN);
        params.set('redirect_uri', this.redirectUrl);
        params.set('code_verifier', codeVerifier);

        try {
            const response = await this.performPostRequest(account, params, this.TOKEN_URL);
            const token: OAuth2TokenDTO = {
                account: account,
                access_token: response.data.access_token,
                refresh_token: response.data.refresh_token,
                expires_in: response.data.expires_in,
                issued_at: Date.now()
            };

            this.saveToken(tokenName, token)
            return token
        } catch (error) {
            console.error('Error exchanging code for token:', error);
            throw new Error('Error getting oauth2 refresh token');
        }
    }

    private async refreshAccessToken(tokenName: string) {
        try {
            console.log('Requesting new access token');

            const token: OAuth2TokenDTO = this.getTokens()[tokenName];
            const params: Map<string, string> = new Map();

            params.set('grant_type', GrantType.REFRESH_TOKEN);
            params.set('refresh_token', token.refresh_token);
            const response = await this.performPostRequest(token.account, params, this.TOKEN_URL);


            token.access_token = response.data.access_token;
            token.expires_in = response.data.expires_in;
            token.issued_at = Date.now();

            this.saveToken(tokenName, token);

        } catch (e) {
            console.error('Error getting new access token', e);
            throw new Error('Error  refreshing access token');
        }
    }

    private generateState(length: number = 22): string {
        return crypto.randomBytes(length).toString('hex');
    }

    private generateCodeVerifier(): string {
        const length: number = Math.floor(Math.random() * (128 - 43 + 1)) + 43;
        const validChars: string = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~';
        let verifier: string = '';

        for (let i = 0; i < length; i++) {
            const randomIndex = Math.floor(Math.random() * validChars.length);
            verifier += validChars[randomIndex];
        }

        return verifier.trim();
    }

    private generateCodeChallenge(codeVerifier: string): string {
        return createHash('sha256')
            .update(codeVerifier)
            .digest('base64url');
    }

    private async startServer(): Promise<unknown> {
        return new Promise((resolve, reject) => {
            const server = createServer((req, res) => {
                const {pathname, query} = parse(req.url || '', true);

                if (pathname === '/callback') {
                    const receivedCode: string = query.code as string;
                    const company: string = query.company as string;

                    if (receivedCode) {
                        res.writeHead(200, {'Content-Type': 'text/plain'});
                        res.end('Authorization successful. You can close this window.');
                        server.close();
                        resolve({
                            code: receivedCode.trim(),
                            company: company.trim()
                        });
                    } else {
                        res.writeHead(400, {'Content-Type': 'text/plain'});
                        res.end('Authorization code not found.');
                        reject(new Error('Authorization code not found.'));
                    }
                } else {
                    res.writeHead(404, {'Content-Type': 'text/plain'});
                    res.end('Not Found');
                }
            });

            server.listen(3000, () => {
                console.log('Server listening on http://localhost:3000');
            });
        });
    }

    private getOpenCommand(): string {
        return this.PLATFORMS[process.platform] || 'xdg-open';
    }

    private ensureDirectoryExists(filePath: string): void {
        const directory = path.dirname(filePath);
        if (!fs.existsSync(directory)) {
            fs.mkdirSync(directory, {recursive: true});
        }
    }

    private getTokens(): Record<string, OAuth2TokenDTO> | null {
        try {
            if (fs.existsSync(this.TOKENS_PATH)) {
                const data = fs.readFileSync(this.TOKENS_PATH, 'utf8');
                return JSON.parse(data);
            }
            return {};
        } catch (error) {
            console.error('Error reading tokens file:', error);
            return null;
        }
    }

    private saveToken(name: string, content: OAuth2TokenDTO): void {
        try {
            this.ensureDirectoryExists(this.TOKENS_PATH);

            const tokens: Record<string, OAuth2TokenDTO> = this.getTokens() || {};
            tokens[name] = content;

            fs.writeFileSync(this.TOKENS_PATH, JSON.stringify(tokens, null, 2), {mode: 0o700});
            console.log(`Token saved under the name "${name}".`);
        } catch (error) {
            console.error('Error saving token:', error);
        }
    }

    private deleteToken(name: string): void {
        try {
            this.ensureDirectoryExists(this.TOKENS_PATH);

            const tokens: Record<string, OAuth2TokenDTO> = this.getTokens() || {};

            if (tokens[name]) {
                delete tokens[name];

                fs.writeFileSync(this.TOKENS_PATH, JSON.stringify(tokens, null, 2), {mode: 0o700});
                console.log(`Token "${name}" deleted.`);
            } else {
                console.log(`Token "${name}" not found.`);
            }
        } catch (error) {
            console.error('Error deleting token:', error);
            throw new Error('Token deletion failed');
        }
    }

}