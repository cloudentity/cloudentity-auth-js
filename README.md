## Cloudentity Auth JS

Cloudentity Auth JS client for Javascript Single Page Apps.

## Import

### Script tag

```
<script src="cloudentity-auth.js"></script>
```

### Node.js style

```javascript
const CloudentityAuth = require('@cloudentity/auth');
```

### ES6 import

```javascript
import CloudentityAuth from '@cloudentity/auth';
```

## Usage

1. First – create and configure CloudentityAuth:

  ```javascript
  var cloudentity = new CloudentityAuth({
      responseType: ['code'] // required, array with a list of OAuth 2 respose types
      domain: 'your-domain', // e.g. 'example.demo.cloudentity.com.' Recommended; always generates URLs with 'https' protocol.
      // baseUrl: optional alternative to 'domain.' Protocol required, e.g. 'https://example.demo.cloudentity.com.'
      // In situations where protocol may dynamically resolve to 'http' rather than 'https' (for example in dev mode), use 'baseUrl' rather than 'domain'.
      tenantId: 'your-tenant-id',
      authorizationServerId: 'your-authorization-server-id',
      clientId: 'your-client-id',
      redirectUri: 'window.location.href',
      silentAuthRedirectUri: 'window.location.href' + '/silent', // optional setting to redirect to a different endpoint following successful silent auth flow
      userInfoUri: 'your-user-info-uri', // optional, for fetching user info via API
      scopes: ['profile', 'email', 'openid', 'revoke_tokens'], // 'revoke_tokens' scope must be present for 'logout' action to revoke token! Without it, token will only be deleted from browser's local storage.
      accessTokenName: 'your_org_access_token', // optional; defaults to '{tenantId}_{authorizationServerId}_access_token'
      idTokenName: 'your_org_access_token', // optional; defaults to '{tenantId}_{authorizationServerId}_id_token'
  });
  ```

  In most cases, either `domain` **or** `baseUrl` can be used to generate all required URLs. However, it is possible to supply the full URL in the config for each use case:
  - Authorization: `authorizationUri`
  - Token: `tokenUri`
  - User Info: `userInfoUri`
  - Logout via Revoke Token: `logoutUri`

  Be aware that if using these custom URL values, neither `domain` nor `baseUrl` values should be supplied in the config; otherwise, they will take priority (`domain` takes highest priority in such cases).

  > Note: By default, PKCE authorization flow is used. Implicit flow can be used by including `{implicit: true}` in the configuration object passed into CloudentityAuth (this is not recommended).

2. To check if there's an OAuth response and parse it:

  ```javascript
  cloudentity.getAuth().then(
    function (authResponse) {
      // set authenticated state in client app, use oauth data, etc.
      // access token (and id token, if present) are automatically set in browser's local storage,
      // so there may be no need for the client app to handle the response data, unless there are custom requirements
    },

    function (errorResponse) {
      // user is not authorized
      // set unauthenticated state, redirect to login, etc.
    }
  );
  ```

3. If not (e.g. this is the initial app load), to initialize OAuth2 PKCE flow:

  ```javascript
  cloudentity.authorize(); // redirects to authorization service
  ```

  If passing dynamic scope values during authorization flow:

  ```javascript
  // e.g. fetching scopes dynamically from an API response
  fetchSomeDynamicData().then(response => {
    // e.g. value of response.scopes is ['foo', 'bar']
    cloudentity.authorize({scopes: response.scopes});
    // redirects to authorization service with dynamic scopes overriding initial config
  });
  ```

  It's possible to pass `prompt` param to authorization request:

  ```javascript
    cloudentity.authorize({prompt: 'login'});
  ```

4. For simple logout:

  ```javascript
  cloudentity.logout(); // tokens are cleared from browser's local storage, but access token is not revoked
  // (synchronous, no return value)
  ```

5. For logout using `revokeAuth` method (make sure that the `revoke_tokens` scope is present):

  ```javascript
  cloudentity.revokeAuth(); // revokes token, and clears access/id tokens from browser's local storage
  // tokens cleared from local storage regardless of whether API call to revoke access token succeeds
  // (async, returns Promise)
  ```

## Additional methods

- To initiate silent auth, call the `silentAuthentication` method with a 'timeout ratio factor' number as the argument (must be a number greater than `0` and less than `1`; defaults to `0.75`).

  During the silent auth flow, an iframe that initiates an authorization request is appended to the client app body. After the success or failure of this request, the iframe is removed.

  The 'timeout ratio factor' number determines how close to the access token expiration time the silent auth flow will be triggered. The number 0 represents the ratio of time to expiration elapsed of a newly issued access token, and 1 represents the ratio at the moment the token expires. To configure the `silentAuthentication` method to run the silent auth flow only if the token is at least 3/4 through its time to expiration, `0.75` would need to be passed as the argument:

  ```javascript
  cloudentity.silentAuthentication(0.75); // initiates silent auth flow
  // (async, has no return value)
  ```

  In other words, if the token was valid for one hour when issued, calling the `silentAuthentication` method with this ratio value would only initiate silent auth if the token was still valid for 15 min or less. Calling the method during the first 45 minutes after the token was issued will result in no action. This way, the client application can, for example, set an interval using this method to occasionally poll whether the access token is close to expiring, and initiate silent auth if it is close to expiring, as defined by the timeout ratio factor.

  When calling the `getAuth` method as part of a silent authentication flow (for example, on redirecting to a silent-auth-specific redirect URI), include a `silent` flag as an argument:

  ```javascript
  cloudentity.getAuth({silent: true}).then(
    // resolve, reject handlers
  );
  ```

  This ensures that the iframe created during the silent auth flow is removed when the flow is complete.

- To fetch user info (via API, rather than by reading ID token JWT; `userInfoUri` value required in main options):

  ```javascript
  cloudentity.userInfo(); // fetch user info via API
  // (async, returns Promise)
  ```

- To fetch raw value of access token from local storage:

  ```javascript
  cloudentity.getAccessToken(); // get value of access token, if present, from browser's local storage
  // (synchronous, returns String if token is present and not expired; otherwise returns null)
  ```

  - In some cases, the client app developer may want to set multiple access tokens for the same user based on custom logic, e.g. to set action-specific access tokens associated with specific scopes, in addition to the access token initially set during authentication. To do this, disable the library setting access tokens in the auth config:

  ```javascript
  var cloudentity = new CloudentityAuth({
      // other settings...
      //
      letClientSetAccessToken: true // with this flag enabled, client app must handle setting all access tokens based on auth response
      accessTokenName: 'your_org_access_token', // it is still possible to specify an access token key value that will always be deleted on logout
  });
  ```

  - To make a token exchange request:

  ```javascript
  cloudentity.tokenExchange({
    subjectToken: 'token', // required, this is usually the current access_token
    // clientId: 'client-id', // optional, not necessary unless using different token exchange client than globally configured client
    // clientSecret: 'client-secret', // optional, ONLY use on server-side application where secret is not exposed in browser
    customFields: { // optional, but usually necessary to configure for common use cases
      custom_field_1: 'value1', // except for 'scope', values for custom fields must be string
      custom_field_2: 'value2',
      scope: ['scope1', 'scope2'] // value of 'scope' can be an array of strings, OR can be a string with spaces separating scopes, e.g. 'scope1 scope2'
    },
    customHeaders: { // optional, adds custom http headers to outgoing request
      'example-header': 'value'
    },
    setAccessToken: false, // optional, defaults to 'false'. If set to 'true', access token resulting from token exchange request will replace previous access_token in browser local storage.
    setIdToken: false // optional, defaults to 'false'. If set to 'true', ID token resulting from token exchange request will replace previous id_token in browser local storage.
  });
  ```

  Note: Client ID value is sourced from the global config by default. `clientId` config can be added to request as shown above to use a different ID than that of the global client. Only if token exchange request is used in server-side application, add config for `clientSecret` as well; if used on UI client side, do NOT add `clientSecret`, but ensure that feature flag for token exchange requests on client side is enabled in your ACP tenant.

### Legacy browser support

To use with SPAs that must support Microsoft IE11 or Edge Legacy:
- You must polyfill `Promise` and `fetch` in your client app code.
  - `Promise` is commonly polyfilled using catch-all polyfill libraries such as `@babel/polyfill`.
  - `fetch` can be polyfilled with a library such as `whatwg-fetch`.
