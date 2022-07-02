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

// FIXME: may need to move any leading zeros for bitstring compression; needs
// testing with various browsers
const PKCS8_PREFIXES = new Map([
  ['P-256', {
    private: new Uint8Array([
      48, 103, 2, 1, 0, 48, 19, 6, 7, 42, 134, 72,
      206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3,
      1, 7, 4, 77, 48, 75, 2, 1, 1, 4, 32
    ]),
    public: new Uint8Array([161, 36, 3, 34, 0])
  }],
  ['P-384', {
    private: new Uint8Array([
      48, 129, 132, 2, 1, 0, 48, 16, 6, 7, 42, 134,
      72, 206, 61, 2, 1, 6, 5, 43, 129, 4, 0, 34,
      4, 109, 48, 107, 2, 1, 1, 4, 48
    ]),
    public: new Uint8Array([161, 52, 3, 50, 0])
  }],
  ['P-521', {
    private: new Uint8Array([
      48, 129, 170, 2, 1, 0, 48, 16, 6, 7, 42, 134,
      72, 206, 61, 2, 1, 6, 5, 43, 129, 4, 0, 35,
      4, 129, 146, 48, 129, 143, 2, 1, 1, 4, 66
    ]),
    public: new Uint8Array([161, 70, 3, 68, 0])
  }]
]);

const SPKI_PREFIXES = new Map([
  ['P-256', new Uint8Array([
    48, 57, 48, 19, 6, 7, 42, 134, 72, 206,
    61, 2, 1, 6, 8, 42, 134, 72, 206, 61,
    3, 1, 7, 3, 34, 0
  ])],
  ['P-384', new Uint8Array([
    48, 70, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2,
    1, 6, 5, 43, 129, 4, 0, 34, 3, 50, 0
  ])],
  ['P-521', new Uint8Array([
    48, 88, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2,
    1, 6, 5, 43, 129, 4, 0, 35, 3, 68, 0
  ])]
]);

// FIXME: curve: `P-256`, `P-384`, `P-521` ... support `P-256K` via
// `@noble/secp256k1`
export async function generateKeyPair({curve} = {}) {
  const algorithm = {name: 'ECDSA', namedCurve: curve};
  const keyPair = await webcrypto.subtle.generateKey(
    algorithm, EXTRACTABLE, ['sign']);
  // FIXME: `keyPair` has `publicKey` and `privateKey` CryptoKeys
  return _createKeyPairInterface({keyPair});
}

async function _createKeyPairInterface({keyPair}) {
  // eslint-disable-next-line no-undef
  if(!(keyPair?.publicKey instanceof CryptoKey)) {
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
        // FIXME: check if non-hash sign feature supported
        // FIXME: move code to separate file not to be imported by browsers
        const keyPromise = _importNodePrivateKey(
          {privateKey: keyPair.privateKey});
        return {
          async sign({data} = {}) {
            const algorithm = null;
            const key = await keyPromise;
            return crypto.sign(
              algorithm, data, {key, dsaEncoding: 'ieee-p1363'});
          }
        };
      }
      return {
        async sign({data} = {}) {
          const algorithm = {name: 'ECDSA', hash: {name: hashAlgorithm}};
          return webcrypto.subtle.sign(algorithm, keyPair.privateKey, data);
        }
      };
    },
    verifier({hashAlgorithm} = {}) {
      if(hashAlgorithm === null) {
        // FIXME: check if non-hash verify feature supported
        // FIXME: move code to separate file not to be imported by browsers
        const keyPromise = _importNodePublicKey(
          {publicKey: keyPair.publicKey});
        return {
          async verify({data, signature} = {}) {
            const algorithm = null;
            const key = await keyPromise;
            return crypto.verify(
              algorithm, data, {key, dsaEncoding: 'ieee-p1363'}, signature);
          }
        };
      }
      return {
        async verify({data, signature} = {}) {
          const algorithm = {name: 'ECDSA', hash: {name: hashAlgorithm}};
          return webcrypto.subtle.verify(
            algorithm, keyPair.publicKey, signature, data);
        }
      };
    }
  };
}

async function _importKeyPair({privateKeyMultibase, publicKeyMultibase}) {
  const keyPair = {};

  // import public key
  if(!(publicKeyMultibase && typeof publicKeyMultibase === 'string' &&
    publicKeyMultibase[0] === 'z')) {
    throw new Error(
      '"publicKeyMultibase" must be a multibase, base58-encoded string.');
  }
  const publicMultikey = base58.decode(publicKeyMultibase.slice(1));

  // set named curved based on multikey header
  const algorithm = {
    name: 'ECDSA',
    namedCurve: _getNamedCurve({publicMultikey})
  };

  // import public key; convert to `spki` format because `jwk` doesn't handle
  // compressed public keys
  const spki = _toSpki({publicMultikey});
  keyPair.publicKey = await webcrypto.subtle.importKey(
    'spki', spki, algorithm, EXTRACTABLE, ['verify']);

  // import private key if given
  if(privateKeyMultibase) {
    if(!(typeof privateKeyMultibase === 'string' &&
      privateKeyMultibase[0] === 'z')) {
      throw new Error(
        '"privateKeyMultibase" must be a multibase, base58-encoded string.');
    }
    const privateMultikey = base58.decode(privateKeyMultibase.slice(1));

    // FIXME: ensure private key multikey header appropriately matches the
    // public key multikey header

    // convert to `pkcs8` format for import because `jwk` doesn't support
    // compressed keys
    const pkcs8 = _toPkcs8({privateMultikey, publicMultikey});
    keyPair.privateKey = await webcrypto.subtle.importKey(
      'pkcs8', pkcs8, algorithm, EXTRACTABLE, ['sign']);
  }

  return keyPair;
}

async function _importNodePrivateKey({privateKey}) {
  const jwk = await webcrypto.subtle.exportKey('jwk', privateKey);
  return crypto.createPrivateKey({key: jwk, format: 'jwk'});
}

async function _importNodePublicKey({publicKey}) {
  const jwk = await webcrypto.subtle.exportKey('jwk', publicKey);
  return crypto.createPublicKey({key: jwk, format: 'jwk'});
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
      return 'P-521';
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

function _toPkcs8({privateMultikey, publicMultikey}) {
  /* Format:
  SEQUENCE (3 elem)
    INTEGER 0
    SEQUENCE (2 elem)
      OBJECT IDENTIFIER 1.2.840.10045.2.1 ecPublicKey
      // curve-specific, e.g. P-256:
      OBJECT IDENTIFIER 1.2.840.10045.3.1.7 prime256v1
    OCTET STRING
      SEQUENCE (3 elem)
        INTEGER 1
        OCTET STRING (32 byte) (RAW PRIVATE KEY BYTES)
        [1] (1 elem)
          BIT STRING (COMPRESSED/UNCOMPRESSED PUBLIC KEY BYTES)

  This translates to:

  PKCS #8 DER PRIVATE KEY HEADER (w/algorithm OID for specific key type)
  RAW PRIVATE KEY BYTES
  PKCS #8 DER PUBLIC KEY HEADER
  COMPRESSED / UNCOMPRESSED PUBLIC KEY BYTES */
  const headers = PKCS8_PREFIXES.get(_getNamedCurve({publicMultikey}));
  const pkcs8 = new Uint8Array(
    headers.private.length +
    // do not include multikey 2-byte header
    privateMultikey.length - 2 +
    headers.public.length +
    // do not include multikey 2-byte header
    publicMultikey.length - 2);
  let offset = 0;
  pkcs8.set(headers.private, offset);
  offset += headers.private.length;
  pkcs8.set(privateMultikey.subarray(2), offset);
  offset += privateMultikey.length - 2;
  pkcs8.set(headers.public, offset);
  offset += headers.public.length;
  pkcs8.set(publicMultikey.subarray(2), offset);
  return pkcs8;
}

function _toSpki({publicMultikey}) {
  /* Format:
  SPKI DER PUBLIC KEY HEADER (w/algorithm OID for specific key type)
  COMPRESSED / UNCOMPRESSED PUBLIC KEY BYTES */
  const header = SPKI_PREFIXES.get(_getNamedCurve({publicMultikey}));
  const spki = new Uint8Array(
    header.length +
    // do not include multikey 2-byte header
    publicMultikey.length - 2);
  let offset = 0;
  spki.set(header, offset);
  offset += header.length;
  spki.set(publicMultikey.subarray(2), offset);
  return spki;
}
