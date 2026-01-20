/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as _constants from '../constants.js';
import * as base64url from 'base64url-universal';
import {unwrapKey as aesUnwrapKey, wrapKey as aesWrapKey} from './aeskw.js';
import crypto from 'node:crypto';

/**
 * Generates a new symmetric key.
 *
 * @ignore
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {string} options.type - A KEY_TYPE.
 * @param {string} options.controller - The key controller.
 *
 * @returns {Promise<object>} An object containing `{id}`.
 */
export async function generateKey({keyId, type, controller} = {}) {
  const keyContextUrl = _constants.SYMMETRIC_KEY_TYPES.get(type);
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

  return {keyId, key, keyDescription};
}

/**
 * Signs some data. Note that the data will be sent to the server, so if
 * this data is intended to be secret it should be hashed first. However,
 * hashing the data first may present interoperability issues so choose
 * wisely.
 *
 * @ignore
 * @param {object} options - The options to use.
 * @param {object} options.key - The key to use.
 * @param {object} options.operation - The KMS operation.
 *
 * @returns {Promise<object>} Contains `{signatureValue}`.
 */
export async function sign({key, operation}) {
  if(key.type !== 'Sha256HmacKey2019') {
    throw new Error(`Unknown key type "${key.type}".`);
  }
  const {verifyData} = operation;
  const signatureValue = await _hs256Sign({key, verifyData});
  return {signatureValue: base64url.encode(signatureValue)};
}

/**
 * Verifies some data. Note that the data will be sent to the server, so if
 * this data is intended to be secret it should be hashed first. However,
 * hashing the data first may present interoperability issues so choose
 * wisely.
 *
 * @ignore
 * @param {object} options - The options to use.
 * @param {object} options.key - The key to use.
 * @param {object} options.operation - The KMS operation.
 *
 * @returns {Promise<object>} An object containing `{verified}`.
 */
export async function verify({key, operation}) {
  if(key.type !== 'Sha256HmacKey2019') {
    throw new Error(`Unknown key type "${key.type}".`);
  }
  const {signatureValue, verifyData} = operation;
  const verified = await _hs256Verify({key, verifyData, signatureValue});
  return {verified};
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
  if(kek.type !== 'AesKeyWrappingKey2019') {
    throw new Error(`Unknown key type "${kek.type}".`);
  }
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
  if(kek.type !== 'AesKeyWrappingKey2019') {
    throw new Error(`Unknown key type "${kek.type}".`);
  }
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

async function _hs256Sign({key, verifyData}) {
  const secret = base64url.decode(key.secret);
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(base64url.decode(verifyData));
  return hmac.digest();
}

async function _hs256Verify({key, verifyData, signatureValue}) {
  signatureValue = base64url.decode(signatureValue);
  const signatureCheck = await _hs256Sign({key, verifyData});
  return crypto.timingSafeEqual(signatureValue, signatureCheck);
}
