// PKCE flow implemented based on https://github.com/aaronpk/pkce-vanilla-js by Aaron Parecki
import ClientOAuth2 from 'client-oauth2';
import {notEmptyStringArray, notEmptyString, validateObject} from "./utils/validators";
import superagent from 'superagent';

const ERRORS = {
  UNAUTHORIZED: 'Unauthorized',
  ERROR: 'Error'
};

const optionsSpec = {
  clientId: [
    {test: notEmptyString, message: '\'cliendId\' [non-empty string] option is required'}
  ],
  tenantId: [
    {test: notEmptyString, message: '\'tenantId\' [non-empty string] option is required'}
  ],
  authorizationServerId: [
    {test: notEmptyString, message: '\'authorizationServerId\' [non-empty string] option is required'}
  ],
  domain: [],
  authorizationUri: [],
  tokenUri: [],
  redirectUri: [
    {test: notEmptyString, message: '\'redirectUri\' [non-empty string] option is required'}
  ],
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

    this.oauth = new ClientOAuth2({
      clientId,
      redirectUri,
      authorizationUri,
      scopes
    })
  }

  /**
   * Initiates OAuth2 implicit flow (redirecting to Cloudentity authorization page)
   */
  authorize () {
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

     // Hash and base64-urlencode the secret to use as the challenge
     // const code_challenge = () => pkceChallengeFromVerifier(code_verifier).then(v => v);
     return pkceChallengeFromVerifier(code_verifier)
      .then(challenge => {
        global.window.location.href = this.options.authorizationUri
          + "?response_type=code"
          + "&client_id=" + encodeURIComponent(this.options.clientId)
          + "&state=" + encodeURIComponent(state)
          + "&scope=" + encodeURIComponent(this.options.scopes.join(' '))
          + "&redirect_uri=" + encodeURIComponent(this.options.redirectUri)
          + "&code_challenge=" + encodeURIComponent(challenge)
          + "&code_challenge_method=S256";
      })
   }

  /**
   * Gets user profile information
   * @param accessToken OAuth2 access token string
   *
   * @returns {Promise}
   */
  getAuth () {
    const queryString = CloudentityWebAuth._parseQueryString(global.window.location.search.substring(1));

    if (queryString.code) {
      if (global.window.localStorage.getItem(`${this.options.tenantId}_${this.options.authorizationServerId}_pkce_state`) != queryString.state) {
        Promise.reject({error: ERRORS.UNAUTHORIZED})
      } else {
        return superagent.post(this.options.tokenUri)
          .type('form')
          .send('grant_type=authorization_code')
          .send(`code=${queryString.code}`)
          .send(`client_id=${this.options.clientId}`)
          .send(`redirect_uri=${this.options.redirectUri}`)
          .send(`code_verifier=${global.window.localStorage.getItem(`${this.options.tenantId}_${this.options.authorizationServerId}_pkce_code_verifier`)}`)
          .then(
            res => res.body,
            rej => Promise.reject(rej.status === 401 ? {error: ERRORS.UNAUTHORIZED} : {error: ERRORS.ERROR, message: rej.response.body})
          );
      }
    }

    return this.oauth.token.getToken(global.window.location.href).then(
      auth => auth.tokenType && auth.accessToken && !auth.expired() ? Promise.resolve(auth.data) : Promise.reject({error: ERRORS.UNAUTHORIZED})
    );
  }

  static _parseOptions (options) {
    const error = validateOptions(options);

    if (error) {
      throw new Error(error);
    }

    options.authorizationUri = options.domain ? `https://${options.domain}/${options.tenantId}/${options.authorizationServerId}/oauth2/authorize` : options.authorizationUri;
    options.tokenUri = options.domain ? `https://${options.domain}/${options.tenantId}/${options.authorizationServerId}/oauth2/token` : options.tokenUri;

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

  static _cleanUpPkceLocalStorageItems () {
    global.window.localStorage.removeItem(`${this.options.tenantId}_${this.options.authorizationServerId}_pkce_state`);
    global.window.localStorage.removeItem(`${this.options.tenantId}_${this.options.authorizationServerId}_pkce_code_verifier`);
  }
}

export default CloudentityWebAuth;
