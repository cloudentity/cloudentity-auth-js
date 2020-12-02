const crypto = window.crypto || window.msCrypto; // IE11 uses 'msCrypto'

function encodeString (string) {
  if (window.TextEncoder) {
    const encoder = new TextEncoder();
    return encoder.encode(string);
  } else {
    // IE11 or Edge Legacy browsers
    const utf8 = unescape(encodeURIComponent(string));
    let encodedString = new Uint8Array(utf8.length);
    for (var i = 0; i < utf8.length; i++) {
      encodedString[i] = utf8.charCodeAt(i);
    }
    return encodedString;
  }
}

// https://github.com/aaronpk/pkce-vanilla-js

// Generate a secure random string using the browser crypto functions
export const generateRandomString = () => {
  const array = new Uint32Array(28);
  crypto.getRandomValues(array);
  return Array.from(array, dec => ('0' + dec.toString(16)).substr(-2)).join('');
};

// Calculate the SHA256 hash of the input text.
// Returns a promise that resolves to an ArrayBuffer
function sha256 (plain) {
  const data = encodeString(plain);
  if (window.CryptoOperation) {
    // in IE11, window.msCrypto.subtle.digest returns CryptoOperation instead of Promise
    return new Promise((resolve, reject) => {
      try {
        crypto.subtle.digest('SHA-256', data).oncomplete = function (e) {
          return resolve(e && e.target && e.target.result);
        }
      } catch (err) {
        return reject(err);
      }
    });
  } else {
    return crypto.subtle.digest('SHA-256', data);
  }
}

// Base64-urlencodes the input string
function base64urlencode (str) {
  // Convert the ArrayBuffer to string using Uint8 array to conver to what btoa accepts.
  // btoa accepts chars only within ascii 0-255 and base64 encodes them.
  // Then convert the base64 encoded to base64url encoded
  //   (replace + with -, replace / with _, trim trailing =)
  return btoa(String.fromCharCode.apply(null, new Uint8Array(str)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Return the base64-urlencoded sha256 hash for the PKCE challenge
export const pkceChallengeFromVerifier = (v) => {
  return sha256(v).then(hashed => base64urlencode(hashed));
};
