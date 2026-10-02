import * as http from "http";
import {createHash} from "node:crypto";
import {OAuth2TokenDTO} from "./types/OAuth2TokenDTO";
import {GrantType} from "./types/GrantType";
import {Config} from "./types/Config";
import {Scope} from "./types/Scope";
import * as https from "https";

export class NSOAuth2 {
    private readonly REVOKE_TOKEN_URL: string = 'https://${accountId}.suitetalk.api.netsuite.com/services/rest/auth/oauth2/v1/revoke';
    private readonly GENERIC_AUTHORIZE_URL: string = 'https://system.netsuite.com/app/login/oauth2/authorize.nl';
    private readonly AUTHORIZE_URL: string = 'https://${accountId}.app.netsuite.com/app/login/oauth2/authorize.nl';
    private readonly TOKEN_URL: string = 'https://${accountId}.suitetalk.api.netsuite.com/services/rest/auth/oauth2/v1/token';

    private readonly clientId: string;
    private readonly scopes: Scope[];
    private readonly clientSecret: string;
    private readonly accountId?: string;
    private readonly redirectUrl: string;

    constructor(config: Config) {
        this.clientId = config.clientId;
        this.scopes = config.scopes;
        this.clientSecret = config.clientSecret;
        this.accountId = config.accountId;
        this.redirectUrl = config.redirectUrl;
    }

    /**
     * Step 1: builds the authorization URL.
     * Open it anywhere, then pass the `code` and `company` from the redirect to `exchangeAuthorizationCode`.
     */
    public getAuthorizationUrl(): { url: string, codeVerifier: string, state: string } {
        return this.buildAuthorizationRequest();
    }

    /** Step 2: exchanges an authorization code for tokens. */
    public async exchangeAuthorizationCode(account: string, code: string, codeVerifier: string): Promise<OAuth2TokenDTO> {
        return await this.getAuthorizedToken(account, code, codeVerifier);
    }

    /**
     * Gets a fresh access token from a refresh token obtained once and kept as a secret.
     */
    public async accessTokenFromRefreshToken(account: string, refreshToken: string): Promise<OAuth2TokenDTO> {
        return await this.refreshAccessToken({
            account,
            access_token: '',
            refresh_token: refreshToken,
            expires_in: 0,
            issued_at: 0
        });
    }

    public async refreshAccessToken(token: OAuth2TokenDTO): Promise<OAuth2TokenDTO> {
        try {
            const params: Map<string, string> = new Map();

            params.set('grant_type', GrantType.REFRESH_TOKEN);
            params.set('refresh_token', token.refresh_token);
            const response = await this.performPostRequest(token.account, params, this.TOKEN_URL);


            token.access_token = response.access_token;
            token.expires_in = response.expires_in;
            token.issued_at = Date.now();

            return token;
        } catch (e) {
            throw new Error('Error  refreshing access token');
        }
    }

    public async revokeRefreshToken(token: OAuth2TokenDTO) {
        const params: Map<string, string> = new Map();
        params.set('token', token.refresh_token);
        await this.performPostRequest(token.account, params, this.REVOKE_TOKEN_URL);
    }

    private buildAuthorizationRequest(): { url: string, codeVerifier: string, state: string } {
        const url: URL = new URL(this.accountId ? this.AUTHORIZE_URL.replace('${accountId}', this.accountId + '') : this.GENERIC_AUTHORIZE_URL);
        const searchParams: URLSearchParams = new URLSearchParams();
        const state: string = this.generateRandomHex();

        searchParams.append('response_type', 'code');
        searchParams.append('client_id', this.clientId);
        searchParams.append('redirect_uri', this.redirectUrl);
        searchParams.append('scope', this.scopes.join(' '));
        searchParams.append('state', state);

        const codeVerifier = this.generateCodeVerifier();
        const codeChallenge = this.generateCodeChallenge(codeVerifier);

        searchParams.append('code_challenge', codeChallenge);
        searchParams.append('code_challenge_method', 'S256');

        url.search = searchParams.toString();
        return {url: url.toString(), codeVerifier, state};
    }

    private async performPostRequest(accountId: string, params: Map<string, string>, url: string): Promise<any> {
        const urlParams: URLSearchParams = new URLSearchParams();

        params.forEach((value, key) => {
            urlParams.append(key, value);
        });

        const credentials: string = `${this.clientId}:${this.clientSecret}`;
        const encodedCredentials: string = Buffer.from(credentials).toString('base64');

        const urlWithAccountId = url.replace('${accountId}', accountId);
        const urlAux: URL = new URL(urlWithAccountId);
        const isHttps: boolean = urlAux.protocol === 'https:';
        const path: string = urlAux.pathname + (urlAux.search ? encodeURI(urlAux.search) : '')
        const options = {
            hostname: urlAux.hostname,
            path,
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

}