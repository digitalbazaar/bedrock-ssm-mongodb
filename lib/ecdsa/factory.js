/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as crypto from 'node:module';
import {sign as _sign, verify as _verify, webcrypto} from './helpers.js';

export function createSigner({privateKey, hashAlgorithm}) {
  // node.js version supports signing pre-hashed messages by setting
  // `hashAlgorithm` to `null`
  if(hashAlgorithm === null) {
    const keyPromise = _importNodePrivateKey({privateKey});
    return {
      async sign({data} = {}) {
        const algorithm = null;
        const key = await keyPromise;
        return crypto.sign(algorithm, data, {key, dsaEncoding: 'ieee-p1363'});
      }
    };
  }
  return {
    async sign({data} = {}) {
      return _sign({privateKey, hashAlgorithm, data});
    }
  };
}

export function createVerifier({publicKey, hashAlgorithm}) {
  // node.js version supports verifying pre-hashed messages by setting
  // `hashAlgorithm` to `null`
  if(hashAlgorithm === null) {
    const keyPromise = _importNodePublicKey({publicKey});
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
      return _verify({publicKey, hashAlgorithm, data, signature});
    }
  };
}

async function _importNodePrivateKey({privateKey}) {
  const jwk = await webcrypto.subtle.exportKey('jwk', privateKey);
  return crypto.createPrivateKey({key: jwk, format: 'jwk'});
}

async function _importNodePublicKey({publicKey}) {
  const jwk = await webcrypto.subtle.exportKey('jwk', publicKey);
  return crypto.createPublicKey({key: jwk, format: 'jwk'});
}
