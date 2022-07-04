/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import {sign as _sign, verify as _verify} from './helpers.js';

export function createSigner({privateKey, hashAlgorithm}) {
  _assertHashAlgorithm(hashAlgorithm);
  return {
    async sign({data} = {}) {
      return _sign({privateKey, hashAlgorithm, data});
    }
  };
}

export function createVerifier({publicKey, hashAlgorithm}) {
  _assertHashAlgorithm(hashAlgorithm);
  return {
    async verify({data, signature} = {}) {
      return _verify({publicKey, hashAlgorithm, data, signature});
    }
  };
}

function _assertHashAlgorithm(hashAlgorithm) {
  if(!(typeof hashAlgorithm === 'string')) {
    // signing / verifying pre-hashed messages is not supported in browser
    throw new TypeError('"hashAlgorithm" must be a string.');
  }
}
