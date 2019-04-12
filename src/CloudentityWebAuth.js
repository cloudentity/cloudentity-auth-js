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
  domain: [],
  authorizationUri: [],
  userInfoUri: [],
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
  authorize ({nonce}) {
    global.window.location.href = `${this.oauth.token.getUri()}${nonce ? `&nonce=${nonce}` : ''}`;
  }

  /**
   * Gets authorization data from URL hash after OAuth redirection as a promise.
   *
   * Rejects if there's no authorization data or retrieved token has expired.
   *
   * @returns {Promise<ClientOAuth2.Token>}
   */
  getAuth () {
    return this.oauth.token.getToken(global.window.location.href).then(
      auth => auth.tokenType && auth.accessToken && !auth.expired() ? Promise.resolve(auth.data) : Promise.reject({error: ERRORS.UNAUTHORIZED})
    );
  }

  /**
   * Gets user profile information
   * @param accessToken OAuth2 access token string
   *
   * @returns {Promise}
   */
  userInfo (accessToken) {
    return superagent.get(this.options.userInfoUri).set('Authorization', 'Bearer ' + accessToken).then(
      res => res.body,
      rej => Promise.reject(rej.status === 401 ? {error: ERRORS.UNAUTHORIZED} : {error: ERRORS.ERROR, message: rej.response.body})
    );
  }

  static _parseOptions (options) {
    const error = validateOptions(options);

    if (error) {
      throw new Error(error);
    }

    options.authorizationUri = options.domain ? `https://${options.domain}/oauth/authorize` : options.authorizationUri;
    options.userInfoUri = options.domain ? `https://${options.domain}/oauth/userinfo` : options.userInfoUri;

    return options;
  }
}

export default CloudentityWebAuth;
