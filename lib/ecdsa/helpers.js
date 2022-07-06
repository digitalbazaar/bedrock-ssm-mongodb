/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import {CryptoKey, webcrypto} from './crypto.js';
export {CryptoKey, webcrypto};

export function getNamedCurve({publicMultikey}) {
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

export function getPrivateKeySize({keyPair}) {
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

export function setPrivateKeyHeader({keyPair, buffer}) {
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

export function setPublicKeyHeader({keyPair, buffer}) {
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

export async function sign({privateKey, hashAlgorithm, data} = {}) {
  const algorithm = {name: 'ECDSA', hash: {name: hashAlgorithm}};
  return webcrypto.subtle.sign(algorithm, privateKey, data);
}

export async function verify({publicKey, hashAlgorithm, data, signature} = {}) {
  const algorithm = {name: 'ECDSA', hash: {name: hashAlgorithm}};
  return webcrypto.subtle.verify(algorithm, publicKey, signature, data);
}
