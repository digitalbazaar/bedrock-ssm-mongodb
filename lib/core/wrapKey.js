/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as base64url from 'base64url-universal';
import {unwrapKey as aesUnwrapKey, wrapKey as aesWrapKey} from './aeskw.js';
import crypto from 'node:crypto';

const SUPPORTED_KEY_TYPES = new Map([
  ['AesKeyWrappingKey2019', 'https://w3id.org/security/suites/aes-2019/v1']
]);

/**
 * Generates a new wraping key.
 *
 * @ignore
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {string} options.type - A KEY_TYPE.
 * @param {string} options.controller - The key controller.
 *
 * @returns {Promise<object>} An object containing `{key, keyDescription}`.
 */
export async function generateKey({keyId, type, controller} = {}) {
  const keyContextUrl = SUPPORTED_KEY_TYPES.get(type);
  if(!keyContextUrl) {
    throw new Error(`Unknown key type "${type}".`);
  }

  const key = {
    '@context': keyContextUrl,
    id: keyId,
    type,
    secret: base64url.encode(crypto.randomBytes(32))
  };

  const keyDescription = {
    '@context': keyContextUrl,
    id: keyId,
    type,
    controller
  };

  return {key, keyDescription};
}

/**
 * Wraps a cryptographic key using a key encryption key (KEK).
 *
 * @ignore
 * @param {object} options - The options to use.
 * @param {string} options.kek - The key encryption key to use.
 * @param {object} options.operation - The KMS operation.
 *
 * @returns {Promise<object>} An object containing `{wrappedKey}`.
 */
export async function wrapKey({kek, operation}) {
  const {unwrappedKey} = operation;
  const wrappedKey = await _aesWrapKey({kek, unwrappedKey});
  return {wrappedKey};
}

/**
 * Unwraps a cryptographic key using a key encryption key (KEK).
 *
 * @ignore
 * @param {object} options - The options to use.
 * @param {string} options.kek - The key encryption key to use.
 * @param {object} options.operation - The KMS operation.
 *
 * @returns {Promise<object>} An object containing `{unwrappedKey}`.
 */
export async function unwrapKey({kek, operation}) {
  const {wrappedKey} = operation;
  const unwrappedKey = await _aesUnwrapKey({kek, wrappedKey});
  return {unwrappedKey};
}

async function _aesWrapKey({kek, unwrappedKey}) {
  const unwrapped = base64url.decode(unwrappedKey);
  const secretKey = base64url.decode(kek.secret);
  const output = await aesWrapKey({secretKey, unwrapped});
  return base64url.encode(output);
}

async function _aesUnwrapKey({kek, wrappedKey}) {
  const wrapped = base64url.decode(wrappedKey);
  const secretKey = base64url.decode(kek.secret);
  const output = await aesUnwrapKey({secretKey, wrapped});
  return base64url.encode(output);
}
