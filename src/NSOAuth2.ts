import {exec} from "child_process";
import * as http from "http";
import {createServer} from "http";
import {parse} from "node:url";
import {createHash} from "node:crypto";
import fs from "fs";
import path from "path";
import os from "os";
import {OAuth2TokenDTO} from "./types/OAuth2TokenDTO";
import {GrantType} from "./types/GrantType";
import {Config} from "./types/Config";
import {Scope} from "./types/Scope";
import * as https from "https";

export class NSOAuth2 {
    private readonly REVOKE_TOKEN_URL: string = 'https://${accountId}.suitetalk.api.netsuite.com/services/rest/auth/oauth2/v1/revoke';
    private readonly GENERIC_AUTHORIZE_URL: string = 'https://system.netsuite.com/app/login/oauth2/authorize.nl';
    private readonly AUTHORIZE_URL: string = 'https://${accountId}.app.netsuite.com/app/login/oauth2/authorize.nl';
    private readonly PLATFORMS: Record<string, string> = {'darwin': 'open', 'win32': 'start ""'};
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

    public async generateAccessToken(): Promise<OAuth2TokenDTO> {
        const codeVerifier: string = await this.authorizeOAuth2();
        const response: any = await this.startServer();
        return await this.getAuthorizedToken(response.company, response.code, codeVerifier);
    }

    public async refreshAccessToken(token: OAuth2TokenDTO): Promise<OAuth2TokenDTO> {
        try {
            console.log('Requesting new access token');
            const params: Map<string, string> = new Map();

            params.set('grant_type', GrantType.REFRESH_TOKEN);
            params.set('refresh_token', token.refresh_token);
            const response = await this.performPostRequest(token.account, params, this.TOKEN_URL);


            token.access_token = response.access_token;
            token.expires_in = response.expires_in;
            token.issued_at = Date.now();

            return token;
        } catch (e) {
            console.error('Error getting new access token', e);
            throw new Error('Error  refreshing access token');
        }
    }

    public async revokeRefreshToken(token: OAuth2TokenDTO) {
        const params: Map<string, string> = new Map();
        params.set('token', token.refresh_token);
        await this.performPostRequest(token.account, params, this.REVOKE_TOKEN_URL);
        console.log(`Token revoked successfully`);
    }

    private isAccessTokenExpired(token: OAuth2TokenDTO): boolean {
        const currentTime: number = Date.now();
        const expiresAt: number = token.issued_at + (token.expires_in * 1000);
        return currentTime >= expiresAt;
    }


    private async authorizeOAuth2(): Promise<string> {
        const url: URL = new URL(this.accountId ? this.AUTHORIZE_URL.replace('${accountId}', this.accountId + '') : this.GENERIC_AUTHORIZE_URL);
        const searchParams: URLSearchParams = new URLSearchParams();

        searchParams.append('response_type', 'code');
        searchParams.append('client_id', this.clientId);
        searchParams.append('redirect_uri', this.redirectUrl);
        searchParams.append('scope', this.scopes.join(' '));
        searchParams.append('state', this.generateRandomHex());

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

        const urlWithAccountId = url.replace('${accountId}', accountId);
        const urlObj = new URL(urlWithAccountId);
        const isHttps = urlObj.protocol === 'https:';
        const options = {
            hostname: urlObj.hostname,
            path: urlObj.pathname + urlObj.search,
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': `Basic ${encodedCredentials}`,
            },
        };

        return new Promise((resolve, reject) => {
            const req = (isHttps ? https : http).request(options, (res) => {
                let data = '';

                res.on('data', (chunk) => {
                    data += chunk;
                });

                res.on('end', () => {
                    if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
                        resolve(JSON.parse(data));
                    } else {
                        reject(new Error(`POST request failed with status code ${res.statusCode}: ${data}`));
                    }
                });
            });

            req.on('error', (error) => {
                console.error('Error performing POST request:', error.message);
                console.log(`Data: \n ${urlParams}`);
                reject(new Error('POST request failed'));
            });

            req.write(urlParams.toString());
            req.end();
        });
    }

    private async getAuthorizedToken(account: string, code: string, codeVerifier: string): Promise<OAuth2TokenDTO> {

        const params: Map<string, string> = new Map();
        params.set('code', code);
        params.set('grant_type', GrantType.AUTHORIZATION_TOKEN);
        params.set('redirect_uri', this.redirectUrl);
        params.set('code_verifier', codeVerifier);

        try {
            const response = await this.performPostRequest(account, params, this.TOKEN_URL);
            return {
                account: account,
                access_token: response.access_token,
                refresh_token: response.refresh_token,
                expires_in: response.expires_in,
                issued_at: Date.now()
            }
        } catch (error) {
            console.error('Error exchanging code for token:', error);
            throw new Error('Error getting oauth2 refresh token');
        }
    }

    private generateRandomHex(length: number = 22): string {
        const hexChars = '0123456789abcdef';
        let result = '';
        for (let i = 0; i < length * 2; i++) {
            result += hexChars[Math.floor(Math.random() * hexChars.length)];
        }
        return result;
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
                const url: URL = new URL(this.redirectUrl);
                if (pathname === url.pathname) {
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

}