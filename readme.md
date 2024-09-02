# NetSuite OAuth2 Library

## Overview

This library simplifies the process of handling OAuth2 authentication for NetSuite APIs. It allows you to easily obtain
and manage access tokens, making it straightforward to integrate with NetSuite's RESTlets, REST Web Services and suite
analytics.

### How to use

To use the library simple create a new NSOAuth2 object instance and pass the config
as a parameters.

``` ts
const oauth2Client: NSOAuth2 = new NSOAuth2({
    clientId: <your_client_id>, // Your NetSuite Client ID
    clientSecret: <your_client_secret>, // Your NetSuite Client Secret
    redirectUrl: <your_redirect_url>, // The redirect URL specified in your NetSuite application
    scopes: [Scope.RESTLETS, Scope.REST_WEB_SERVICES], // Scopes to specify the APIs you wish to access
    account: <your_account_number>, // Optional: Your NetSuite account number
});

oauth2Client.getAccessToken('foo'); // The parameter is the token name you want to set.
```

This will complete the OAuth2 flow, retrieve a new access token, and save it under the specified name. Once saved, the
token will be reused until it expires. No new access token will be requested until the existing one has expired.

To revoke an existing token, use the following method:

``` ts
oauth2Client.revokeRefreshToken('foo'); //The parameter is the token name you want to revoke.
```

### Notes

- Token Management: The library automatically handles token expiration and renewal. It will request a new access token
  when the current one expires.
- Security: Ensure that sensitive information like clientId, clientSecret, and account is stored securely and not
  exposed in your codebase.