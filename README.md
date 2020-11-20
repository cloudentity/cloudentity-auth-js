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
      domain: 'your-domain', // e.g. 'example.demo.cloudentity.com'
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

### Legacy browser support

To use with SPAs that must support Microsoft IE11 or Edge Legacy:
- You must polyfill `Promise`, `TextEncoder`, and `fetch` in your client app code.
  - `Promise` is commonly polyfilled using catch-all polyfill libraries such as `@babel/polyfill`.
  - `TextEncoder` can be polyfilled with a library such as `fast-text-encoding`.
  - `fetch` can be polyfilled with a library such as `whatwg-fetch`.
