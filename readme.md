# NetSuite OAuth2 Library

## Overview

This library simplifies the process of handling OAuth2 authentication for NetSuite APIs. It allows you to easily obtain
and manage access tokens, making it straightforward to integrate with NetSuite's RESTlets, REST Web Services and suite
analytics.

### How to use

To use the library simple create a new NSOAuth2 object instance and pass the config
as a parameters.

``` ts
// Import necessary components from your OAuth2 library
import { NSOAuth2, Scope } from 'netsuiteoauth2';

// Initialize the OAuth2 client with configuration options
const oauth2Client: NSOAuth2 = new NSOAuth2({
    clientId: '<your_client_id>', // NetSuite Client ID
    clientSecret: '<your_client_secret>', // NetSuite Client Secret
    redirectUrl: '<your_redirect_url>', // Redirect URL specified in your NetSuite application
    scopes: [Scope.RESTLETS, Scope.REST_WEB_SERVICES], // Scopes for API access
    account: '<your_account_number>' // Optional: NetSuite account number
});

// Retrieve the access token
const token: string = oauth2Client.getAccessToken('foo'); // 'foo' is the name of the token you want to set

// Access token is now ready to use
console.log('Access token:', token);


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