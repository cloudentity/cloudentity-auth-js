import {generateRandomString, pkceChallengeFromVerifier} from './utils/pkce.utils';
import {notEmptyString, notEmptyStringArray, optionalBoolean, optionalString, stringOrEmptyArray, validateObject} from './utils/validators';

const ERRORS = {
  UNAUTHORIZED: 'Unauthorized',
  EXPIRED: 'Session expired',
  ERROR: 'Error'
};

const DEFAULT_SILENT_AUTH_TIMEOUT_IN_SECONDS = 45;
const DEFAULT_CHECK_INTERVAL_IN_SECONDS = 60;
const SILENT_AUTH_SUCCESS_MESSAGE = 'silentAuthSuccess';
const SILENT_AUTH_ERROR_MESSAGE = 'silentAuthFailure';

const optionsSpec = {
  clientId: [
    {test: notEmptyString, message: '\'cliendId\' [non-empty string] option is required'}
  ],
  tenantId: [
    {test: optionalString, message: '\'tenantId\' [non-empty string] option is required'}
  ],
  authorizationServerId: [
    {test: optionalString, message: '\'authorizationServerId\' [non-empty string] required if option value given'}
  ],
  domain: [
    {test: optionalString, message: '\'domain\' [non-empty string] required if option value given'}
  ],
  baseUrl: [
    {test: optionalString, message: '\'baseUrl\' [non-empty string] required if option value given'}
  ],
  authorizationUri: [
    {test: optionalString, message: '\'authorizationUri\' [non-empty string] required if option value given'}
  ],
  tokenUri: [
    {test: optionalString, message: '\'tokenUri\' [non-empty string] required if option value given'}
  ],
  userInfoUri: [
    {test: optionalString, message: '\'userInfoUri\' [non-empty string] required if option value given'}
  ],
  logoutUri: [
    {test: optionalString, message: '\'logoutUri\' [non-empty string] required if option value given'}
  ],
  redirectUri: [
    {test: notEmptyString, message: '\'redirectUri\' [non-empty string] option is required'}
  ],
  silentAuthRedirectUri: [
    {test: optionalString, message: '\'silentAuthRedirectUri\' [non-empty string] required if option value given'}
  ],
  scopes: [
    {test: stringOrEmptyArray, message: '\'scopes\' [array of strings or empty array] option is required'}
  ],
  letClientSetAccessToken: [
    {test: optionalBoolean, message: '\'letClientSetAccessToken\' [boolean] required if option value given'}
  ],
  accessTokenName: [
    {test: optionalString, message: '\'accessTokenName\' [non-empty string] required if option value given'}
  ],
  idTokenName: [
    {test: optionalString, message: '\'idTokenName\' [non-empty string] required if option value given'}
  ],
  implicit: [
    {test: optionalBoolean, message: '\'implicit\' [boolean] required if option value given'}
  ],
  responseType: [
    {test: notEmptyStringArray, message: '\'responseType\' [array of non-empty strings] option is required'}
  ]
};

const validateOptions = validateObject(optionsSpec);

const setLocalStorageItem = (id, val) => global.window.localStorage.setItem(id, val);

const getLocalStorageItem = id => global.window.localStorage.getItem(id);

const removeLocalStorageItem = id => global.window.localStorage.removeItem(id);

/**
 * Cloudentity OAuth2 flow client for Javascript SPAs
 */
class CloudentityAuth {
  /**
   * Creates CloudentityAuth client to handle OAuth2 flow
   *
   * @param {Object} options
   */
  constructor (options) {
    this.options = CloudentityAuth._parseOptions(options);

    const {clientId, redirectUri, authorizationUri, scopes} = this.options;
  }

  /**
   * Initiates OAuth2 PKCE flow (redirecting to Cloudentity authorization page)
   * Implicit flow is supported, but not recommended in most circumstances due to potential security issues.
   */
  authorize (dynamicOptions) {
    const dynamicScopes = dynamicOptions && dynamicOptions.scopes && notEmptyStringArray(dynamicOptions.scopes);
    const dynamicResponseType = dynamicOptions && dynamicOptions.responseType && notEmptyStringArray(dynamicOptions.responseType);

    const finalOptions = {
      ...this.options,
      ...(dynamicScopes ? {scopes: dynamicOptions.scopes} : {}),
      ...(dynamicResponseType ? {responseType: dynamicOptions.responseType} : {}),
    }


    const prompt = dynamicOptions && dynamicOptions.prompt;
    if (prompt) {
      finalOptions.prompt = prompt;
    }

    if (this.options.implicit === true) {
      global.window.location.href = CloudentityAuth._calcAuthorizationUrlImplicit(finalOptions);
    } else {
      CloudentityAuth._calcAuthorizationUrl(finalOptions)
        .then(authorizationUri => {
          global.window.location.href = authorizationUri;
        });
    }
  }

  /**
   * Gets user profile information
   * @param accessToken OAuth2 access token string
   *
   * @returns {Promise}
   */
  userInfo () {
    const token = CloudentityAuth._getAccessToken(this.options);
    if (!token) {
      return Promise.reject({error: ERRORS.UNAUTHORIZED});
    }
    return global.window.fetch(this.options.userInfoUri, {
      headers: {
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + token
      }
    })
      .then(CloudentityAuth._handleApiResponse)
      .then(data => data)
      .catch(err => Promise.reject(err));
  }

  /**
   * Gets authorization data from URL hash after OAuth redirection as a promise.
   *
   * @returns {Promise}
   */
  getAuth (options) {
    const queryString = CloudentityAuth._parseQueryString(global.window.location.search.substring(1));
    const hashString = CloudentityAuth._parseQueryString(global.window.location.hash.substring(1));
    const isSilentAuthFlow = options && typeof options === 'object' && options.silent === true;
    const postSilentAuthSuccessMessage = success => global.window.parent.postMessage(success ? SILENT_AUTH_SUCCESS_MESSAGE : SILENT_AUTH_ERROR_MESSAGE, global.window.location.origin);
    const params = {...queryString, ...hashString}

    if (this.options.implicit === true && hashString.access_token) {
      CloudentityAuth._setAccessToken(this.options, hashString.access_token);
      if (hashString.id_token) {
        CloudentityAuth._setIdToken(this.options, hashString.id_token);
      }
      global.window.history.replaceState('', global.window.document.title, global.window.location.pathname + global.window.location.search);
      return Promise.resolve(hashString);
    }

    const accessToken = CloudentityAuth._getAccessToken(this.options);

    if (params.code) {
      if (getLocalStorageItem(`${this.options.tenantId}_${this.options.authorizationServerId}_pkce_state`) != params.state) {
        this.cleanUpPkceLocalStorageItems();
        return Promise.reject({error: ERRORS.UNAUTHORIZED});
      } else {
        const verificationData = 'grant_type=authorization_code'
          + '&code=' + encodeURIComponent(params.code)
          + '&client_id=' + encodeURIComponent(this.options.clientId)
          + '&redirect_uri=' + encodeURIComponent(isSilentAuthFlow && this.options.silentAuthRedirectUri ? this.options.silentAuthRedirectUri : this.options.redirectUri)
          + '&code_verifier=' + encodeURIComponent(getLocalStorageItem(`${this.options.tenantId}_${this.options.authorizationServerId}_pkce_code_verifier`));

        return global.window.fetch(this.options.tokenUri, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
          },
          body: verificationData
        })
          .then(CloudentityAuth._handleApiResponse)
          .then(data => {

            if (!this.options.letClientSetAccessToken) {
              CloudentityAuth._setAccessToken(this.options, data.access_token);
            }

            if (data.id_token) {
              if (CloudentityAuth._getValueFromToken("nonce", data.id_token) !== getLocalStorageItem(`${this.options.tenantId}_${this.options.authorizationServerId}_token_id_nonce`)) {
                this.cleanUpPkceLocalStorageItems();
                return Promise.reject({error: ERRORS.UNAUTHORIZED});
              }

              CloudentityAuth._setIdToken(this.options, data.id_token);
            }

            this.cleanUpPkceLocalStorageItems();
            if (isSilentAuthFlow) {
              postSilentAuthSuccessMessage(true);
            }
            return data;
          })
          .catch(err => {
            this.cleanUpPkceLocalStorageItems();
            if (isSilentAuthFlow) {
              postSilentAuthSuccessMessage(false);
            }
            return Promise.reject(err);
          });
      }
    } else if (params.error) {
      const capitalizeFirstLetter = (string = '') => {
        return string.charAt(0).toUpperCase() + string.slice(1);
      };

      this.cleanUpPkceLocalStorageItems();

      if (isSilentAuthFlow) {
        postSilentAuthSuccessMessage(false);
      }

      return Promise.reject({
        error: ERRORS.ERROR,
        error_key: capitalizeFirstLetter((params.error || '').replace(/(\+|_)/g, ' ')),
        error_cause: params.error_cause,
        error_description: (params.error_description || '').replace(/\+/g, ' '),
        error_hint: params.error_hint
      });
    } else if (accessToken) {
      if (CloudentityAuth._isJWT(accessToken)) {
        let issuedAtTime = CloudentityAuth._getValueFromToken('iat', accessToken);
        let expiresAtTime = CloudentityAuth._getValueFromToken('exp', accessToken);
        let timeToExpiration = CloudentityAuth._timeToExpiration(issuedAtTime, expiresAtTime);
        if (timeToExpiration > 0) {
          if (isSilentAuthFlow) {
            postSilentAuthSuccessMessage(true);
          }
          return Promise.resolve();
        } else {
          CloudentityAuth._clearAuthTokens(this.options);
          if (isSilentAuthFlow) {
            postSilentAuthSuccessMessage(false);
          }
          return Promise.reject({error: ERRORS.EXPIRED});
        }
      } else {
        if (isSilentAuthFlow) {
          postSilentAuthSuccessMessage(true);
        }
        return Promise.resolve();
      }
    } else {
      if (isSilentAuthFlow) {
        postSilentAuthSuccessMessage(false);
      }
      return Promise.reject({error: ERRORS.UNAUTHORIZED});
    }
  }

  /**
   * Gets access token from local storage. Access token returned if token is present and not expired.
   *
   * @returns {String} or {null}
   */
  getAccessToken () {
    const accessToken = CloudentityAuth._getAccessToken(this.options);
    if (!accessToken) {
      return null;
    }

    return accessToken;
  };

  /**
   * Gets ID token from local storage. ID token returned if token is present and not expired.
   *
   * @returns {String} or {null}
   */
   getIDToken () {
    const IDToken = CloudentityAuth._getIDToken(this.options);
    if (!IDToken) {
      return null;
    }

    return IDToken;
  };

  /**
   * Clears access and ID tokens (simple logout).
   */
  logout () {
    return CloudentityAuth._clearAuthTokens(this.options);
  }

  /**
   * Revokes access token, then clears access and ID tokens, regardless of API response (enhanced logout).
   *
   * @returns {Promise}
   */
  revokeAuth () {
    const token = CloudentityAuth._getAccessToken(this.options);
    return global.window.fetch(this.options.logoutUri, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + token
      },
      body: `token=${token}`
    })
      .then(() => CloudentityAuth._clearAuthTokens(this.options))
      .catch(err => {
        CloudentityAuth._clearAuthTokens(this.options);
        return Promise.reject(err);
      });
  }

  /**
   * Initiates 'silent' authentication.
   * If user has opted to stay logged in on their device, this method issues a new access token if the current token is about to expire.
   */
  silentAuthentication (timeoutRatioFactor) {
    const checkInterval = setInterval(() => {
      const token = CloudentityAuth._getAccessToken(this.options);
      if (!CloudentityAuth._isJWT(token)) {
        return;
      }
      const issuedAtTime = CloudentityAuth._getValueFromToken('iat', token);
      const expiresAtTime = CloudentityAuth._getValueFromToken('exp', token);
      const methodHint = CloudentityAuth._getValueFromToken('mth', token);

      const lifetimeInSec = (expiresAtTime - issuedAtTime);
      const current = new Date().getTime() / 1000;
      const validForInSec = expiresAtTime - current;
      const ratio = (lifetimeInSec - validForInSec) / lifetimeInSec;
      const validateTimeoutRatioFactor = typeof timeoutRatioFactor === 'number' && timeoutRatioFactor > 0 && timeoutRatioFactor < 1;

      if (ratio > ((validateTimeoutRatioFactor && timeoutRatioFactor) || 0.75) || !token) {
        startSilentAuthentication(this.options.tenantId, this.options.authorizationServerId, this.options.scopes, methodHint, 'silent-auth-iframe');
      }
    }, DEFAULT_CHECK_INTERVAL_IN_SECONDS * 1000);

    const startSilentAuthentication = (tenantId, authorizationServerId, scopes, methodHint, iframeId) => {
      const existingIframe = document.querySelector(`#${iframeId}`);
      existingIframe && document.body.removeChild(existingIframe);

      const iframe = document.createElement('iframe');

      CloudentityAuth._calcAuthorizationUrl(this.options, true, methodHint)
        .then(authorizationUri => {
          iframe.setAttribute('id', iframeId);
          iframe.setAttribute('width', '0');
          iframe.setAttribute('height', '0');
          iframe.style.display = 'none';

          const timeoutSetTimeoutId = setTimeout(() => {
            clearInterval(checkInterval)
            const iframeToRemove = document.querySelector(`#${iframeId}`);
            iframeToRemove && document.body.removeChild(iframeToRemove);
            window.removeEventListener('message', listener);
          }, DEFAULT_SILENT_AUTH_TIMEOUT_IN_SECONDS * 1000);

          const listener = function (e) {
            if (e.origin !== window.location.origin || iframe.contentWindow !== e.source) {
              return;
            }
            if (e.data === (SILENT_AUTH_SUCCESS_MESSAGE || SILENT_AUTH_ERROR_MESSAGE)) {
              const iframeToRemove = document.querySelector(`#${iframeId}`);
              iframeToRemove && document.body.removeChild(iframeToRemove);
              clearTimeout(timeoutSetTimeoutId);
              window.removeEventListener('message', listener);
            }
          };

          window.addEventListener('message', listener);
          document.body.appendChild(iframe);
          iframe.setAttribute('src', authorizationUri);
        });
    };
  }

  static _parseOptions (options) {
    const error = validateOptions(options);

    if (error) {
      throw new Error(error);
    }

    const useDefaultUriFormat = options.domain || options.baseUrl;
    const baseUrl = options.domain ? `https://${options.domain}` : options.baseUrl;

    options.authorizationUri = useDefaultUriFormat
      ? `${baseUrl}/${options.tenantId ? options.tenantId + '/' : ''}${options.authorizationServerId ? options.authorizationServerId + '/' : ''}oauth2/authorize`
      : options.authorizationUri;
    options.tokenUri = useDefaultUriFormat
      ? `${baseUrl}/${options.tenantId ? options.tenantId + '/' : ''}${options.authorizationServerId ? options.authorizationServerId + '/' : ''}oauth2/token`
      : options.tokenUri;
    options.userInfoUri = useDefaultUriFormat
      ? `${baseUrl}/${options.tenantId ? options.tenantId + '/' : ''}${options.authorizationServerId ? options.authorizationServerId + '/' : ''}userinfo`
      : options.userInfoUri;
    options.logoutUri = useDefaultUriFormat
      ? `${baseUrl}/${options.tenantId ? options.tenantId + '/' : ''}${options.authorizationServerId ? options.authorizationServerId + '/' : ''}oauth2/revoke`
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

  static _calcAuthorizationUrl (options, silentAuth, methodHint) {
    const state = generateRandomString();
    setLocalStorageItem(`${options.tenantId}_${options.authorizationServerId}_pkce_state`, state);

    // Create and store a new PKCE code_verifier (the plaintext random secret)
    const codeVerifier = generateRandomString();
    setLocalStorageItem(`${options.tenantId}_${options.authorizationServerId}_pkce_code_verifier`, codeVerifier);

    const nonce = generateRandomString();
    setLocalStorageItem(`${options.tenantId}_${options.authorizationServerId}_token_id_nonce`, nonce);

    // Hash and base64-urlencode the secret to use as the challenge
    return pkceChallengeFromVerifier(codeVerifier).then(challengeRes => {
      return options.authorizationUri
        + '?response_type=' + encodeURIComponent(options.responseType.join(' '))
        + '&client_id=' + encodeURIComponent(options.clientId)
        + '&state=' + encodeURIComponent(state)
        + '&nonce=' + encodeURIComponent(nonce)
        + '&scope=' + encodeURIComponent(options.scopes.join(' '))
        + '&redirect_uri=' + encodeURIComponent(silentAuth && options.silentAuthRedirectUri ? options.silentAuthRedirectUri : options.redirectUri)
        + '&code_challenge=' + encodeURIComponent(challengeRes)
        + '&code_challenge_method=S256'
        + `${options.prompt ? `&prompt=${options.prompt}` : ""}`
        + `${silentAuth ? `&prompt=none&method_hint=${methodHint || ''}` : ''}`;
    });
  }

  static _calcAuthorizationUrlImplicit (options) {
    return options.authorizationUri
      + '?response_type=' + encodeURIComponent(options.responseType.join(' '))
      + '&client_id=' + encodeURIComponent(options.clientId)
      + '&scope=' + encodeURIComponent(options.scopes.join(' '))
      + '&redirect_uri=' + encodeURIComponent(options.redirectUri);
  }

  static _getAccessToken (options) {
    return getLocalStorageItem(options.accessTokenName || `${options.tenantId}_${options.authorizationServerId}_access_token`);
  }

  static _setAccessToken (options, value) {
    setLocalStorageItem(options.accessTokenName || `${options.tenantId}_${options.authorizationServerId}_access_token`, value);
  }

  static _getIDToken (options) {
    return getLocalStorageItem(options.idTokenName || `${options.tenantId}_${options.authorizationServerId}_id_token`);
  }

  static _setIdToken (options, value) {
    setLocalStorageItem(options.idTokenName || `${options.tenantId}_${options.authorizationServerId}_id_token`, value);
  }

  static _clearAuthTokens (options) {
    removeLocalStorageItem(options.accessTokenName || `${options.tenantId}_${options.authorizationServerId}_access_token`);
    removeLocalStorageItem(options.idTokenName || `${options.tenantId}_${options.authorizationServerId}_id_token`);
  };

  cleanUpPkceLocalStorageItems () {
    removeLocalStorageItem(`${this.options.tenantId}_${this.options.authorizationServerId}_pkce_state`);
    removeLocalStorageItem(`${this.options.tenantId}_${this.options.authorizationServerId}_pkce_code_verifier`);
    removeLocalStorageItem(`${this.options.tenantId}_${this.options.authorizationServerId}_token_id_nonce`);
  };

  static _parseQueryString (string) {
    if (string === '') {
      return {};
    }
    const segments = string.split('&').map(s => s.split('='));
    let queryString = {};
    segments.forEach(s => queryString[s[0]] = s[1]);
    return queryString;
  }

  static _getValueFromToken (field, token) {
    if (token) {
      let payload = token.split('.')[1];
      let base64 = payload.replace(/-/g, '+').replace(/_/g, '/');
      let jsonPayload = decodeURIComponent(global.window.atob(base64).split('').map(function(c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
      }).join(''));
      let jsonPayloadParsed = JSON.parse(jsonPayload)

      return jsonPayloadParsed[field];
    }

    return undefined;
  }

  static _timeToExpiration (iat, exp) {
    const lifetimeInSec = (exp - iat);
    const current = new Date().getTime() / 1000;
    return exp - current;
  }

  static _isJWT (token) {
    return token && (token.match(/\./g) || []).length === 2
  }
}

export default CloudentityAuth;
