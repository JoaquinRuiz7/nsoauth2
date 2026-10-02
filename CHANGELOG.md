### Version 3.0.0

- BREAKING: removed `generateAccessToken()`, which opened a browser and started a local server (unusable on CI/servers).
- Added `getAuthorizationUrl()` and `exchangeAuthorizationCode()` for a standard authorization code (PKCE) flow.
- Added `accessTokenFromRefreshToken()` for non-interactive use.

### Version 2.2.3 - 2024-09-07

- Minor change, removed debug console logs.
- Added changelog