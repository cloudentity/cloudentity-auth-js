// PKCE flow implemented based on https://github.com/aaronpk/pkce-vanilla-js by Aaron Parecki
import {notEmptyStringArray, notEmptyString, validateObject} from "./utils/validators";
import superagent from 'superagent';

const ERRORS = {
  UNAUTHORIZED: 'Unauthorized',
  EXPIRED: 'Session expired',
  ERROR: 'Error'
};

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
    {test: notEmptyStringArray, message: '\'scopes\' [non-empty array of strings] option is required'}
  ]
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
  authorize (options) {
     const pkceChallengeFromVerifier = async (v) => {
       const hashed = await CloudentityWebAuth._encodeSha256(v);
       return CloudentityWebAuth._base64urlencode(hashed);
     };
     // Create and store a random "state" value
     const state = CloudentityWebAuth._generateRandomString();
     global.window.localStorage.setItem(`${this.options.tenantId}_${this.options.authorizationServerId}_pkce_state`, state);

     // Create and store a new PKCE code_verifier (the plaintext random secret)
     const code_verifier = CloudentityWebAuth._generateRandomString();
     global.window.localStorage.setItem(`${this.options.tenantId}_${this.options.authorizationServerId}_pkce_code_verifier`, code_verifier);

     const silentAuthEnabled = options && options.silentAuth === true;

     // Hash and base64-urlencode the secret to use as the challenge
     // const code_challenge = () => pkceChallengeFromVerifier(code_verifier).then(v => v);
     return pkceChallengeFromVerifier(code_verifier)
      .then(challenge => {
        global.window.location.href = this.options.authorizationUri
          + '?response_type=code'
          + '&client_id=' + encodeURIComponent(this.options.clientId)
          + '&state=' + encodeURIComponent(state)
          + '&scope=' + encodeURIComponent(this.options.scopes.join(' '))
          + '&redirect_uri=' + encodeURIComponent(silentAuthEnabled && this.options.silentAuthRedirectUri ? this.options.silentAuthRedirectUri : this.options.redirectUri)
          + '&code_challenge=' + encodeURIComponent(challenge)
          + '&code_challenge_method=S256'
          + `${silentAuthEnabled ? '&prompt=none' : ''}`;
      });
   }

  /**
   * Gets user profile information
   * @param accessToken OAuth2 access token string
   *
   * @returns {Promise}
   */
  userInfo (accessToken) {
    return superagent.get(this.options.userInfoUri).set('Accept', 'application/json').set('Authorization', 'Bearer ' + accessToken).then(
      res => res.body,
      rej => Promise.reject(rej.status === 401 ? {error: ERRORS.UNAUTHORIZED} : {error: ERRORS.ERROR, message: rej.response.body})
    );
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
        return superagent.post(this.options.tokenUri)
          .type('form')
          .send('grant_type=authorization_code')
          .send(`code=${queryString.code}`)
          .send(`client_id=${this.options.clientId}`)
          .send(`redirect_uri=${this.options.redirectUri}`)
          .send(`code_verifier=${global.window.localStorage.getItem(`${this.options.tenantId}_${this.options.authorizationServerId}_pkce_code_verifier`)}`)
          .then(
            res => {
              cleanUpPkceLocalStorageItems();
              global.window.localStorage.setItem('access_token', res.body.access_token);
              if (res.body.id_token) {
                global.window.localStorage.setItem('id_token', res.body.id_token);
              }
              return res.body;
            },
            rej => {
              cleanUpPkceLocalStorageItems();
              return Promise.reject(rej.status === 401 ? {error: ERRORS.UNAUTHORIZED} : {error: ERRORS.ERROR, message: rej.response ? rej.response.body : 'Unknown error'});
            }
          );
      }
    } else if (global.window.localStorage.getItem('access_token')) {
      let token = global.window.localStorage.getItem('access_token');
      let issuedAtTime = CloudentityWebAuth._getValueFromToken('iat', token);
      let expiresAtTime = CloudentityWebAuth._getValueFromToken('exp', token);
      let timeToExpiration = CloudentityWebAuth._timeToExpiration(issuedAtTime, expiresAtTime);
      if (timeToExpiration > 0) {
        return Promise.resolve();
      } else {
        global.window.localStorage.removeItem('access_token');
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
     const clearAuthTokens = () => {
       global.window.localStorage.removeItem('access_token');
       global.window.localStorage.removeItem('id_token');
     };
     return superagent.post(this.options.logoutUri)
      .send({token: token})
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .set('Accept', 'application/json')
      .set('Authorization', 'Bearer ' + token)
      .then(
        res => {
          clearAuthTokens();
          return res.body;
        },
        rej => {
          clearAuthTokens();
          return Promise.reject(rej.status === 401 ? {error: ERRORS.UNAUTHORIZED} : {error: ERRORS.ERROR, message: rej.response.body});
        }
      );
   }

   /**
    * Utility function to help determine when to initiate silent authentication.
    *
    * @returns {Number}
    */
   calculateTimeToExpirationRatio () {
     const token = global.window.localStorage.getItem('access_token');
     const issuedAtTime = CloudentityWebAuth._getValueFromToken('iat', token);
     const expiresAtTime = CloudentityWebAuth._getValueFromToken('exp', token);
     const lifetimeInSec = (expiresAtTime - issuedAtTime);
     const currentTime = new Date().getTime() / 1000;
     const validForInSec = expiresAtTime - currentTime;
     const ratio = (lifetimeInSec - validForInSec) / lifetimeInSec;
     return ratio;
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

  static _generateRandomString () {
    const array = new Uint32Array(28);
    global.window.crypto.getRandomValues(array);
    return Array.from(array, dec => ('0' + dec.toString(16)).substr(-2)).join('');
  }

  static _encodeSha256 (plain) {
    const encoder = new TextEncoder();
    const data = encoder.encode(plain);
    return global.window.crypto.subtle.digest('SHA-256', data);
  }

  static _base64urlencode (str) {
    // Convert the ArrayBuffer to string using Uint8 array to conver to what btoa accepts.
    // btoa accepts chars only within ascii 0-255 and base64 encodes them.
    // Then convert the base64 encoded to base64url encoded
    //   (replace + with -, replace / with _, trim trailing =)
    return btoa(String.fromCharCode.apply(null, new Uint8Array(str)))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

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
