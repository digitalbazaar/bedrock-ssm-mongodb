/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
// FIXME: move whole directory and files to a ecdsa-specific lib
import {createSigner, createVerifier} from './factory.js';
import {exportKeyPair, importKeyPair} from './serialize.js';
import {CryptoKey, webcrypto} from './helpers.js';

const EXTRACTABLE = true;

// FIXME: curve: `P-256`, `P-384`, `P-521` ... support `P-256K` via
// `@noble/secp256k1`
export async function generate({id, curve} = {}) {
  const algorithm = {name: 'ECDSA', namedCurve: curve};
  const keyPair = await webcrypto.subtle.generateKey(
    algorithm, EXTRACTABLE, ['sign']);
  keyPair.id = id;
  return _createKeyPairInterface({keyPair});
}

// import key pair from JSON Multikey
export async function from(key) {
  _assertMultikey(key);
  return _createKeyPairInterface({keyPair: key});
}

async function _createKeyPairInterface({keyPair}) {
  if(!(keyPair?.publicKey instanceof CryptoKey)) {
    keyPair = await importKeyPair(keyPair);
  }
  return {
    _keyPair: keyPair,
    async export({
      publicKey = true, privateKey = false, includeContext = true
    } = {}) {
      return exportKeyPair({keyPair, publicKey, privateKey, includeContext});
    },
    signer({hashAlgorithm} = {}) {
      const {privateKey} = keyPair;
      return createSigner({privateKey, hashAlgorithm});
    },
    verifier({hashAlgorithm} = {}) {
      const {publicKey} = keyPair;
      return createVerifier({publicKey, hashAlgorithm});
    }
  };
}

function _assertMultikey(key) {
  if(!(key && typeof key === 'object')) {
    throw new TypeError('"key" must be an object.');
  }
  if(!(key['@context'] === 'https://w3id.org/security/suites/multikey/v1' &&
    key.type === 'Multikey')) {
    throw new Error('"key" must be a Multikey.');
  }
}
