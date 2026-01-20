/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as base64url from 'base64url-universal';
import {
  X25519KeyAgreementKey2020
} from '@digitalbazaar/x25519-key-agreement-key-2020';

/**
 * Generates a new key agreement key pair.
 *
 * @ignore
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {object} options.type - The key type.
 * @param {string} options.controller - The key controller.
 *
 * @returns {Promise<object>} An object containing `{key, keyDescription}`.
 */
export async function generateKey({keyId, type, controller} = {}) {
  // only `X25519KeyAgreementKey2020` supported
  if(type !== 'X25519KeyAgreementKey2020') {
    throw new Error(`Unsupported key type "${type}".`);
  }

  const keyPair = await X25519KeyAgreementKey2020.generate({id: keyId});
  const key = keyPair.export({
    publicKey: true, privateKey: true, includeContext: true
  });

  // create public key description
  const keyDescription = keyPair.export({
    publicKey: true, includeContext: true
  });
  keyDescription.controller = controller;

  return {key, keyDescription};
}

/**
 * Signs some data. Note that the data will be sent to the server, so if
 * this data is intended to be secret it should be hashed first. However,
 * hashing the data first may present interoperability issues so choose
 * wisely.
 *
 * @ignore
 * @param {object} options - The options to use.
 * @param {object} options.key - Exported key pair record, loaded from storage.
 * @param {object} options.operation - The KMS operation.
 *
 * @returns {Promise<{secret: string}>} Resolves with the derived secret.
 */
export async function deriveSecret({key, operation}) {
  const {publicKey} = operation;
  if(publicKey.type !== key.type) {
    throw Error(
      `The given public key type "${publicKey.type}" does not match the ` +
      `key agreement key's ${key.type}.`);
  }

  const keyPair = await X25519KeyAgreementKey2020.from(key);
  const secret = await keyPair.deriveSecret({publicKey});
  return {secret: base64url.encode(secret)};
}
