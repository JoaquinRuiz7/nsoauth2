# NetSuite OAuth2 Library

## Overview

This library simplifies the process of handling OAuth2 authentication for NetSuite APIs. It allows you to easily obtain
and manage access tokens, making it straightforward to integrate with NetSuite's RESTlets, REST Web Services and suite
analytics.

### How to use

To use the library simple create a new NSOAuth2 object instance and pass the config
as a parameters.

``` ts
import { NSOAuth2, Scope } from 'netsuiteoauth2';

// Initialize the OAuth2 client with configuration options
const oauth2Client: NSOAuth2 = new NSOAuth2({
    clientId: '<your_client_id>', // NetSuite Client ID
    clientSecret: '<your_client_secret>', // NetSuite Client Secret
    redirectUrl: '<your_redirect_url>', // Redirect URL specified in your NetSuite application
    scopes: [Scope.RESTLETS, Scope.REST_WEB_SERVICES], // Scopes for API access
    account: '<your_account_id>' // Optional: NetSuite account id
});

// Retrieve the access token
const token: OAuth2TokenDTO = oauth2Client.generateAccessToken();

// Access token is now ready to use
console.log('Access token:', token);


```

This process will complete the OAuth2 flow and retrieve a new access token. The resulting token DTO contains the
following information:

- `account: string;`
- `access_token: string;`
- `refresh_token: string;`
- `expires_in: number;`
- `issued_at: number;`

To obtain a new access token using a refresh token, use the following method:

```ts
const refreshedToken: OAuth2TokenDTO = oauth2Client.refreshAccessToken(token); // token is type OAuth2TokenDTO
```

Finally to revoke an token use this method:

``` ts
oauth2Client.revokeRefreshToken(token); // token is type OAuth2TokenDTO
```

### Notes

- **Security:** Ensure that sensitive information, such as `clientId`, `clientSecret`, and `account`, is stored securely
  and not exposed in your codebase. Utilize environment variables to safeguard these credentials.