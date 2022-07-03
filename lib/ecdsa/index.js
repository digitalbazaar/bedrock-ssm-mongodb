/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
// FIXME: move whole directory and files to a ecdsa-specific lib
import {createSigner, createVerifier} from './factory.js';
import {exportKeyPair, importKeyPair} from './serialize.js';
import {webcrypto} from './helpers.js';

const EXTRACTABLE = true;

// FIXME: curve: `P-256`, `P-384`, `P-521` ... support `P-256K` via
// `@noble/secp256k1`
export async function generate({curve} = {}) {
  const algorithm = {name: 'ECDSA', namedCurve: curve};
  const keyPair = await webcrypto.subtle.generateKey(
    algorithm, EXTRACTABLE, ['sign']);
  // FIXME: `keyPair` has `publicKey` and `privateKey` CryptoKeys
  return _createKeyPairInterface({keyPair});
}

// FIXME: add `import` and `export` functions

async function _createKeyPairInterface({keyPair}) {
  // eslint-disable-next-line no-undef
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
