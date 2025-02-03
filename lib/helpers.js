/*!
 * Copyright (c) 2021-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as _asymmetricKey from './asymmetric-key.js';
import * as _keyAgreementKey from './key-agreement-key.js';
import * as _symmetricKey from './symmetric-key.js';
import * as base58 from 'base58-universal';

// this cannot be defined in constants.js due to circular dependency
// issues with constants.js and symmetric-key.js
const OPERATIONS = new Map([
  // asymmetric keys
  ['Ed25519VerificationKey2018', _asymmetricKey],
  ['Ed25519VerificationKey2020', _asymmetricKey],
  ['urn:webkms:multikey:Ed25519', _asymmetricKey],
  ['urn:webkms:multikey:P-256', _asymmetricKey],
  ['urn:webkms:multikey:P-384', _asymmetricKey],
  ['urn:webkms:multikey:P-521', _asymmetricKey],
  ['urn:webkms:multikey:BBS-BLS12-381-SHA-256', _asymmetricKey],
  ['urn:webkms:multikey:BBS-BLS12-381-SHAKE-256', _asymmetricKey],
  ['urn:webkms:multikey:Bls12381G2', _asymmetricKey],
  // key agreement keys
  ['X25519KeyAgreementKey2020', _keyAgreementKey],
  // symmetric keys
  ['AesKeyWrappingKey2019', _symmetricKey],
  ['Sha256HmacKey2019', _symmetricKey],
]);

export function getKeyOp({name, type}) {
  const ops = OPERATIONS.get(type);
  if(!ops) {
    throw new Error(`Unknown key type "${type}".`);
  }
  const op = ops[name];
  if(!op) {
    throw new Error(`Unsupported operation "${name}" for key type "${type}".`);
  }

  return op;
}

export function splitKeyId({id}) {
  // format: <keystoreId>/<localId>
  const idx = id.lastIndexOf('/');
  const localId = id.substr(idx + 1);
  return {
    keystoreId: id.substring(0, idx),
    // convert to `Buffer` for storage savings (`z<base58-encoded ID>`)
    // where the ID is multicodec encoded 16 byte random value
    // 0x00 = identity tag, 0x10 = length (16 bytes) header
    localId: Buffer.from(base58.decode(localId.slice(1)).slice(2))
  };
}
