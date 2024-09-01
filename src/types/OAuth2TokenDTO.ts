export interface OAuth2TokenDTO {
    account: string;
    access_token: string;
    refresh_token: string;
    expires_in: number;
    issued_at?: number;
}