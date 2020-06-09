// PKCE flow implemented based on https://github.com/aaronpk/pkce-vanilla-js by Aaron Parecki
import {stringOrEmptyArray, notEmptyString, validateObject} from './utils/validators';
import {generateRandomString, pkceChallengeFromVerifier} from './utils/pkce.utils';
import throttle from './utils/throttle';

const ERRORS = {
  UNAUTHORIZED: 'Unauthorized',
  EXPIRED: 'Session expired',
  ERROR: 'Error'
};
const SILENT_AUTH_SUCCESS_MESSAGE = 'silentAuthSuccess';
const SILENT_AUTH_ERROR_MESSAGE = 'silentAuthFailure';

const optionsSpec = {
  clientId: [
    {test: notEmptyString, message: '\'cliendId\' [non-empty string] option is required'}
  ],
  tenantId: [],
  authorizationServerId: [],
  domain: [],
  authorizationUri: [],
  tokenUri: [],
  userInfoUri: [],
  logoutUri: [],
  redirectUri: [
    {test: notEmptyString, message: '\'redirectUri\' [non-empty string] option is required'}
  ],
  silentAuthRedirectUri: [],
  scopes: [
    {test: stringOrEmptyArray, message: '\'scopes\' [array of strings or empty array] option is required'}
  ],
  timeoutRatioFactor: [],
  tokenExpirationRatioCheckInterval: []
};

const validateOptions = validateObject(optionsSpec);

/**
 * Cloudentity OAuth2 implicit flow client for Javascript SPAs
 */
class CloudentityWebAuth {
  /**
   * Creates CloudentityWebAuth client to handle OAuth2 implicit flow
   *
   * @param {Object} options
   */
  constructor (options) {
    this.options = CloudentityWebAuth._parseOptions(options);

    const {clientId, redirectUri, authorizationUri, scopes} = this.options;
  }

  /**
   * Initiates OAuth2 PKCE flow (redirecting to Cloudentity authorization page)
   */
  authorize () {
    CloudentityWebAuth._calcAuthorizationUrl(this.options)
      .then(authorizationUri => {
        global.window.location.href = authorizationUri;
      });
   }

  /**
   * Gets user profile information
   * @param accessToken OAuth2 access token string
   *
   * @returns {Promise}
   */
  userInfo () {
    let token = global.window.localStorage.getItem('access_token');
    if (!token) {
      return Promise.reject({error: ERRORS.UNAUTHORIZED});
    }
    return global.window.fetch(this.options.userInfoUri, {
      headers: {
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + token
      }
    })
    .then(CloudentityWebAuth._handleApiResponse)
    .then(data => data)
    .catch(err => Promise.reject(err));
  }

  /**
   * Gets authorization data from URL hash after OAuth redirection as a promise.
   *
   * @returns {Promise}
   */
  getAuth () {
    const queryString = CloudentityWebAuth._parseQueryString(global.window.location.search.substring(1));
    const cleanUpPkceLocalStorageItems = () => {
      global.window.localStorage.removeItem(`${this.options.tenantId}_${this.options.authorizationServerId}_pkce_state`);
      global.window.localStorage.removeItem(`${this.options.tenantId}_${this.options.authorizationServerId}_pkce_code_verifier`);
    };

    if (queryString.code) {
      if (global.window.localStorage.getItem(`${this.options.tenantId}_${this.options.authorizationServerId}_pkce_state`) != queryString.state) {
        cleanUpPkceLocalStorageItems();
        return Promise.reject({error: ERRORS.UNAUTHORIZED});
      } else {
        const verificationData = 'grant_type=authorization_code'
          + '&code=' + encodeURIComponent(queryString.code)
          + '&client_id=' + encodeURIComponent(this.options.clientId)
          + '&redirect_uri=' + encodeURIComponent(this.options.redirectUri)
          + '&code_verifier=' + encodeURIComponent(global.window.localStorage.getItem(`${this.options.tenantId}_${this.options.authorizationServerId}_pkce_code_verifier`));

        return global.window.fetch(this.options.tokenUri, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
          },
          body: verificationData
        })
        .then(CloudentityWebAuth._handleApiResponse)
        .then(data => {
          cleanUpPkceLocalStorageItems();
          global.window.localStorage.setItem('access_token', data.access_token);
          if (data.id_token) {
            global.window.localStorage.setItem('id_token', data.id_token);
          }
          return data;
        })
        .catch(err => {
          cleanUpPkceLocalStorageItems();
          return Promise.reject(err);
        });
      }
    } else if (global.window.localStorage.getItem('access_token')) {
      let token = global.window.localStorage.getItem('access_token');
      let issuedAtTime = CloudentityWebAuth._getValueFromToken('iat', token);
      let expiresAtTime = CloudentityWebAuth._getValueFromToken('exp', token);
      let timeToExpiration = CloudentityWebAuth._timeToExpiration(issuedAtTime, expiresAtTime);
      if (timeToExpiration > 0) {
        return Promise.resolve();
      } else {
        CloudentityWebAuth._clearAuthTokens();
        return Promise.reject({error: ERRORS.EXPIRED});
      }
    } else {
      return Promise.reject({error: ERRORS.UNAUTHORIZED});
    }
  }

  /**
   * Revokes access token (logout).
   *
   * @returns {Promise}
   */
   revokeAuth () {
     let token = global.window.localStorage.getItem('access_token');
     return global.window.fetch(this.options.logoutUri, {
       method: 'POST',
       headers: {
         'Content-Type': 'application/x-www-form-urlencoded',
         'Accept': 'application/json',
         'Authorization': 'Bearer ' + token
       }
     })
     .then(CloudentityWebAuth._handleApiResponse)
     .then(data => {
       CloudentityWebAuth._clearAuthTokens();
       return data;
     })
     .catch(err => {
       CloudentityWebAuth._clearAuthTokens();
       return Promise.reject(err);
     });
   }

   silentAuthentication () {
     const startSilentAuthentication = async (tenantId, authorizationServerId, scopes, methodHint, iframeId) => {
       const iframeExists = document.querySelector(`#${iframeId}`);
       iframeExists && document.body.removeChild(iframeToRemove);

       const iframe = document.createElement('iframe');
       const src = await CloudentityWebAuth._calcAuthorizationUrl(this.options, true, methodHint);
       iframe.setAttribute('src', src);
       iframe.setAttribute('id', iframeId);
       iframe.style.display = 'none';
       const listener = e => {
         if (e.data === (SILENT_AUTH_SUCCESS_MESSAGE || SILENT_AUTH_ERROR_MESSAGE)) {
           const iframeToRemove = document.querySelector(`#${iframeId}`);
           iframeToRemove && document.body.removeChild(iframeToRemove);
           window.removeEventListener('message', listener);
         }
       };

       window.addEventListener('message', listener);

       document.body.appendChild(iframe);
     };

     const silentAuthenticationThrottled = throttle(startSilentAuthentication, 10000);

     const counter = global.window.setInterval(async () => {
       const token = global.window.localStorage.getItem('access_token');
       const issuedAtTime = CloudentityWebAuth._getValueFromToken('iat', token);
       const expiresAtTime = CloudentityWebAuth._getValueFromToken('exp', token);
       const methodHint = CloudentityWebAuth._getValueFromToken('mth', token);

       const lifetimeInSec = (expiresAtTime - issuedAtTime);
       const current = new Date().getTime() / 1000;
       const validForInSec = expiresAtTime - current;
       const ratio = (lifetimeInSec - validForInSec) / lifetimeInSec;

       if (ratio > (this.options.timeoutRatioFactor || 0.75) || !token) {
         silentAuthenticationThrottled(this.options.tenantId, this.options.authorizationServerId, this.options.scopes, methodHint, 'silent-auth-iframe');
       }
     }, this.options.tokenExpirationRatioCheckInterval || 5000);

     return () => global.window.clearInterval(counter);
   }

  static _parseOptions (options) {
    const error = validateOptions(options);

    if (error) {
      throw new Error(error);
    }

    options.authorizationUri = options.domain
      ? `https://${options.domain}/${options.tenantId ? options.tenantId + '/' : ''}${options.authorizationServerId ? options.authorizationServerId + '/' : ''}oauth2/authorize`
      : options.authorizationUri;
    options.tokenUri = options.domain
      ? `https://${options.domain}/${options.tenantId ? options.tenantId + '/' : ''}${options.authorizationServerId ? options.authorizationServerId + '/' : ''}oauth2/token`
      : options.tokenUri;
    options.userInfoUri = options.domain
      ? `https://${options.domain}/${options.tenantId ? options.tenantId + '/' : ''}${options.authorizationServerId ? options.authorizationServerId + '/' : ''}userinfo`
      : options.userInfoUri;
    options.logoutUri = options.domain
      ? `https://${options.domain}/${options.tenantId ? options.tenantId + '/' : ''}${options.authorizationServerId ? options.authorizationServerId + '/' : ''}oauth2/revoke`
      : options.logoutUri;

    return options;
  }

  static _handleApiResponse (response) {
    return response.json()
      .then(json => {
        if (response.ok) {
          return json;
        } else {
          if (response.status === 401) {
            return Promise.reject({error: ERRORS.UNAUTHORIZED});
          }
          return Promise.reject({error: ERRORS.ERROR, message: json.error_description || 'Unknown error'});
        }
      });
  }

  static async _calcAuthorizationUrl (options, silentAuth, methodHint) {
    const state = generateRandomString();
    global.window.localStorage.setItem(`${options.tenantId}_${options.authorizationServerId}_pkce_state`, state);

    // Create and store a new PKCE code_verifier (the plaintext random secret)
    const codeVerifier = generateRandomString();
    global.window.localStorage.setItem(`${options.tenantId}_${options.authorizationServerId}_pkce_code_verifier`, codeVerifier);

    // Hash and base64-urlencode the secret to use as the challenge
    const codeChallenge = await pkceChallengeFromVerifier(codeVerifier);

    return options.authorizationUri
      + '?response_type=code'
      + '&client_id=' + encodeURIComponent(options.clientId)
      + '&state=' + encodeURIComponent(state)
      + '&scope=' + encodeURIComponent(options.scopes.join(' '))
      + '&redirect_uri=' + encodeURIComponent(silentAuth && options.silentAuthRedirectUri ? options.silentAuthRedirectUri : options.redirectUri)
      + '&code_challenge=' + encodeURIComponent(codeChallenge)
      + '&code_challenge_method=S256'
      + `${silentAuth ? `&prompt=none&method_hint=${methodHint || ''}` : ''}`;
  }

  static _clearAuthTokens () {
    global.window.localStorage.removeItem('access_token');
    global.window.localStorage.removeItem('id_token');
  };

  static _parseQueryString (string) {
    if (string === '') {
      return {};
    }
    let segments = string.split('&').map(s => s.split('='));
    let queryString = {};
    segments.forEach(s => queryString[s[0]] = s[1]);
    return queryString;
  }

  static _getValueFromToken (field, token) {
    let tokenToObject = token ? JSON.parse(global.window.atob(token.split('.')[1])) : {};
    return tokenToObject[field];
  }

  static _timeToExpiration (iat, exp) {
    const lifetimeInSec = (exp - iat);
    const current = new Date().getTime() / 1000;
    return exp - current;
  }
}

export default CloudentityWebAuth;
