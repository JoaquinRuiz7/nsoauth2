# NetSuite OAuth2 Library

## Overview

This library simplifies the process of handling OAuth2 authentication for NetSuite APIs. It allows you to easily obtain
and manage access tokens, making it straightforward to integrate with NetSuite's RESTlets, REST Web Services and suite
analytics.

### How to use

Create an `NSOAuth2` instance with your config. The library never opens a browser or starts a server, so it works the
same on a laptop, a server or CI.

``` ts
import { NSOAuth2, Scope, OAuth2TokenDTO } from 'netsuiteoauth2';

const oauth2Client: NSOAuth2 = new NSOAuth2({
    clientId: '<your_client_id>', // NetSuite Client ID
    clientSecret: '<your_client_secret>', // NetSuite Client Secret
    redirectUrl: '<your_redirect_url>', // Redirect URL specified in your NetSuite application
    scopes: [Scope.RESTLETS, Scope.REST_WEB_SERVICES], // Scopes for API access
    accountId: '<your_account_id>' // Optional: NetSuite account id
});
```

#### 1. Authorization code flow (PKCE)

``` ts
// Step 1: build the authorization URL. Keep codeVerifier (and state) for step 2.
const { url, codeVerifier, state } = oauth2Client.getAuthorizationUrl();
// redirect the user to `url`

// Step 2: in your redirect handler, check that the `state` query param matches, then exchange the code.
// `code` and `company` (the account id) are query params of the redirect.
const token: OAuth2TokenDTO = await oauth2Client.exchangeAuthorizationCode(company, code, codeVerifier);
```

The resulting token DTO contains:

- `account: string;`
- `access_token: string;`
- `refresh_token: string;`
- `expires_in: number;`
- `issued_at: number;`

#### 2. Refresh tokens (CI / servers)

Authorize once, store the `refresh_token` as a secret, and get access tokens from it without any interaction:

```ts
const token: OAuth2TokenDTO = await oauth2Client.accessTokenFromRefreshToken(account, refreshToken);
// or, with an existing token DTO:
const refreshed: OAuth2TokenDTO = await oauth2Client.refreshAccessToken(token);
```

#### 3. Revoke

``` ts
await oauth2Client.revokeRefreshToken(token);
```

### Notes

- **Security:** Ensure that sensitive information, such as `clientId`, `clientSecret`, and `account`, is stored securely
  and not exposed in your codebase. Utilize environment variables to safeguard these credentials.