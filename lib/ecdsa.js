/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
// FIXME: move this file to a separate lib
import {crypto} from 'node:module';
import {createRequire} from 'node:module';
const require = createRequire(import.meta.url);
const base58 = require('base58-universal');
const base64url = require('base64url-universal');

// eslint-disable-next-line no-undef
const webcrypto = globalThis.crypto.webcrypto ?? globalThis.crypto;

const EXTRACTABLE = true;
const KEY_USAGES = ['sign', 'verify'];

// FIXME: curve: `P-256`, `P-384`, `P-521` ... support `P-256K` via
// `@noble/secp256k1`
export async function generateKeyPair({curve} = {}) {
  const algorithm = {name: 'ECDSA', namedCurve: curve};
  const keyPair = await webcrypto.subtle.subtle.generateKey(
    algorithm, EXTRACTABLE, KEY_USAGES);
  return _createKeyPairInterface({keyPair});
}

async function _createKeyPairInterface({keyPair}) {
  // eslint-disable-next-line no-undef
  if(!(keyPair instanceof CryptoKey)) {
    keyPair = await _importKeyPair(keyPair);
  }
  return {
    _keyPair: keyPair,
    async export({
      publicKey = true, privateKey = false, includeContext = true
    } = {}) {
      return _exportKey({keyPair, publicKey, privateKey, includeContext});
    },
    // FIXME: signer should always require a hash algorithm for ECDSA; it's
    // a special feature to pass `null` and it will only work in `node`
    // implementations; the WebKMS signer() and verifier() functions should
    // perform the hash locally before using the WebKMS key
    signer({hashAlgorithm} = {}) {
      if(hashAlgorithm === null) {
        // FIXME: check if feature supported
        return {
          async sign({data} = {}) {
            // FIXME: should be able to skip `createPrivateKey` and pass params
            // as `key` to `sign`?
            // FIXME: move code to separate file not to be imported by browsers
            const jwk = await webcrypto.subtle.exportKey('jwk', keyPair);
            const key = crypto.createPrivateKey({key: jwk, format: 'jwk'});
            const algorithm = null;
            return crypto.sign(
              algorithm, data, {key, dsaEncoding: 'ieee-p1363'});
          }
        };
      }
      return {
        async sign({data} = {}) {
          const algorithm = {name: 'ECDSA', hash: {name: hashAlgorithm}};
          return webcrypto.subtle.sign(algorithm, keyPair, data);
        }
      };
    },
    verifier({hashAlgorithm} = {}) {
      if(hashAlgorithm === null) {
        // FIXME: check if feature supported
        return {
          async verify({data, signature} = {}) {
            // FIXME: should be able to skip `createPrivateKey` and pass params
            // as `key` to `sign`?
            // FIXME: move code to separate file not to be imported by browsers
            const jwk = await webcrypto.subtle.exportKey('jwk', keyPair);
            const key = crypto.createPrivateKey({key: jwk, format: 'jwk'});
            const algorithm = null;
            return crypto.verify(
              algorithm, data, {key, dsaEncoding: 'ieee-p1363'}, signature);
          }
        };
      }
      return {
        async verify({data, signature} = {}) {
          const algorithm = {name: 'ECDSA', hash: {name: hashAlgorithm}};
          return webcrypto.subtle.verify(algorithm, keyPair, signature, data);
        }
      };
    }
  };
}

async function _importKeyPair({privateKeyMultibase, publicKeyMultibase}) {
  const jwk = {};

  // import public key
  if(!(publicKeyMultibase && typeof publicKeyMultibase === 'string' &&
    publicKeyMultibase[0] === 'z')) {
    throw new Error(
      '"publicKeyMultibase" must be a multibase, base58-encoded string.');
  }
  const publicMultikey = base58.decode(publicKeyMultibase.slice(1));
  // FIXME: will need code to import or convert compressed key; WebCrypto API
  // requires both `x` and `y` coordinates... perhaps can reuse something from
  // `@noble/secp256k1`

  const algorithm = {
    name: 'ECDSA',
    namedCurve: _getNamedCurve({publicMultikey})
  };

  // import private key if given
  if(privateKeyMultibase) {
    if(!(typeof privateKeyMultibase === 'string' &&
      privateKeyMultibase[0] === 'z') {
      throw new Error(
        '"privateKeyMultibase" must be a multibase, base58-encoded string.');
    }
    // FIXME: parse `publicKeyMultibase` header
    const privateMultikey = base58.decode(privateKeyMultibase.slice(1));

    // FIXME: ensure private key multikey header appropriately matches the
    // public key multikey header

    jwk.d = base64url.encode(privateMultikey.subarray(2));
  }

  // FIXME: `KEY_USAGES` probably needs to depend on pri/pub
  const keyPair = await webcrypto.subtle.importKey(
    'jwk', jwk, algorithm, EXTRACTABLE, KEY_USAGES);
  return keyPair;
}

async function _exportKey({keyPair, privateKey, publicKey, includeContext}) {
  const privateKeySize = _getPrivateKeySize({keyPair});

  // get JWK
  const jwk = await webcrypto.subtle.exportKey('jwk', keyPair);

  // export as Multikey
  const exported = {};
  if(includeContext) {
    exported['@context'] = 'https://w3id.org/security/suites/multikey/v1';
  }

  if(publicKey) {
    // convert `x` coordinate to compressed public key
    const x = base64url.decode(jwk.x);
    const y = base64url.decode(jwk.y);
    // public key size is always private key size + 1
    const publicKeySize = privateKeySize + 1;
    // leave room for multicodec header (2 bytes)
    const multikey = new Uint8Array(2 + publicKeySize);
    _setPublicKeyHeader({keyPair, buffer: multikey});
    // use even / odd status of `y` coordinate for compressed header
    const even = y[y.length - 1] % 2 === 0;
    multikey[2] = even ? 2 : 3;
    // skip multicodec and compressed header... and zero-fill
    const offset = 2 + 1 + multikey.length - x.length;
    multikey.set(x, offset);
    exported.publicKeyMultibase = 'z' + base58.encode(multikey);
  }

  if(privateKey) {
    const d = base64url.decode(jwk.d);
    // leave room for multicodec header (2 bytes)
    const multikey = new Uint8Array(2 + privateKeySize);
    _setPrivateKeyHeader({keyPair, buffer: multikey});
    multikey.set(d, 2);
    exported.secretKeyMultibase = 'z' + base58.encode(multikey);
  }

  return exported;
}

function _getNamedCurve({publicMultikey}) {
  if(publicMultikey[0] === 0x12) {
    if(publicMultikey[1] === 0x00) {
      return 'P-256';
    }
    if(publicMultikey[1] === 0x01) {
      return 'P-384';
    }
    if(publicMultikey[1] === 0x02) {
      return 'P-512';
    }
  }

  // FIXME; also support P-256K/secp256k1
  const err = new Error('Unsupported multikey header.');
  err.name = 'UnsupportedError';
  throw err;
}

function _getPrivateKeySize({keyPair}) {
  const {namedCurve: curve} = keyPair.algorithm;
  if(curve === 'P-256') {
    return 32;
  }
  if(curve === 'P-384') {
    return 48;
  }
  if(curve === 'P-521') {
    return 66;
  }
  throw new Error(`Unsupported curve "${curve}".`);
}

function _setPrivateKeyHeader({keyPair, buffer}) {
  const {namedCurve: curve} = keyPair.algorithm;
  // FIXME: these must be added to the multicodec table
  if(curve === 'P-256') {
    buffer[0] = 0x13;
    buffer[1] = 0x03;
  } else if(curve === 'P-384') {
    buffer[0] = 0x13;
    buffer[1] = 0x04;
  } else if(curve === 'P-521') {
    buffer[0] = 0x13;
    buffer[1] = 0x05;
  }
  throw new Error(`Unsupported curve "${curve}".`);
}

function _setPublicKeyHeader({keyPair, buffer}) {
  const {namedCurve: curve} = keyPair.algorithm;
  if(curve === 'P-256') {
    buffer[0] = 0x12;
    buffer[1] = 0x00;
  } else if(curve === 'P-384') {
    buffer[0] = 0x12;
    buffer[1] = 0x01;
  } else if(curve === 'P-521') {
    buffer[0] = 0x12;
    buffer[1] = 0x02;
  }
  throw new Error(`Unsupported curve "${curve}".`);
}
