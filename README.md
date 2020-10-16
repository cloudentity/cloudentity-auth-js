## Cloudentity Web Auth

Cloudentity Web Auth client for Javascript Single Page Apps.

## Import

### Script tag

    <script src="cloudentity-web-auth.js"></script>

### Node.js style

    const CloudentityWebAuth = require('cloudentity-web-auth');

### ES6 import

    import CloudentityWebAuth from 'cloudentity-web-auth';


## Usage

1. First – create and configure CloudentityWebAuth:

        var cloudentity = new CloudentityWebAuth({
            domain: 'your-domain', // e.g. 'example.demo.cloudentity.com'
            tenantId: 'your-tenant-id',
            authorizationServerId: 'your-authorization-server-id',
            clientId: 'your-client-id',
            redirectUri: 'window.location.href',
            scopes: ['profile', 'email', 'openid', 'revoke_tokens'] // 'revoke_tokens' scope must be present for 'logout' action to revoke token! Without it, token will only be deleted from browser's local storage.
            accessTokenName: 'your_org_access_token' // optional; defaults to '{tenantId}_{authorizationServerId}_access_token'
            idTokenName: 'your_org_access_token' // optional; defaults to '{tenantId}_{authorizationServerId}_id_token'
        });

Note: By default, PKCE authorization flow is used. Implicit flow can be used by including `{implicit: true}` in the configuration object passed into CloudentityWebAuth (this is not recommended).

2. To check if there's an OAuth response and parse it:

        cloudentity.getAuth().then(
          function (authResponse) {
            // use oauth data, etc.
            // access token (and id token, if present) are automatically set in browser's local storage, so there may be no need to handle response
          },

          function (errorResponse) {
            // user is not authorized
          }
        );

3. If not (e.g. this is the initial app load), to initialize OAuth2 PKCE flow:

        cloudentity.authorize(); // redirects to authorization service


4. For logout (make sure that the `revoke_tokens` scope is present):


        cloudentity.revokeAuth(); // revokes token, and clears access/id tokens from browser's local storage


To use with SPAs that must support IE11:
You must polyfill `Promise`, `TextEncoder`, and `fetch` in your SPA code for this library to work in IE11.
