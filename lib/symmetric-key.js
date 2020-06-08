/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const _constants = require('./constants');
const base64url = require('base64url-universal');
const crypto = require('crypto');
const database = require('bedrock-mongodb');
const {util: {BedrockError}} = require('bedrock');

/**
 * Generates a new symmetric key.
 *
 * @ignore
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {string} options.type - A KEY_TYPE.
 * @returns {Promise<object>} An object containing `{id}`.
 */
exports.generateKey = async ({keyId, type}) => {
  if(!_constants.KEY_TYPES.symmetric.has(type)) {
    throw new Error(`Unknown key type "${type}".`);
  }

  const key = {
    id: keyId,
    type,
    secret: base64url.encode(crypto.randomBytes(32))
  };

  // insert the key and get the updated record
  const now = Date.now();
  const meta = {created: now};
  const record = {
    id: database.hash(keyId),
    meta,
    key
  };
  try {
    await database.collections.ssm.insertOne(record, database.writeOptions);
    return {'@context': _constants.SECURITY_CONTEXT_V2_URL, id: keyId, type};
  } catch(e) {
    if(!database.isDuplicateError(e)) {
      throw e;
    }
    throw new BedrockError(
      'Duplicate key identifier.',
      'DuplicateError', {
        public: true,
        httpStatusCode: 409
      }, e);
  }
};

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
exports.sign = async ({key, operation}) => {
  if(key.type !== 'Sha256HmacKey2019') {
    throw new Error(`Unknown key type "${key.type}".`);
  }
  const {verifyData} = operation;
  const signatureValue = await _hs256Sign({key, verifyData});
  return {signatureValue: base64url.encode(signatureValue)};
};

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
exports.verify = async ({key, operation}) => {
  if(key.type !== 'Sha256HmacKey2019') {
    throw new Error(`Unknown key type "${key.type}".`);
  }
  const {signatureValue, verifyData} = operation;
  const verified = await _hs256Verify({key, verifyData, signatureValue});
  return {verified};
};

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
exports.wrapKey = async ({kek, operation}) => {
  if(kek.type !== 'AesKeyWrappingKey2019') {
    throw new Error(`Unknown key type "${kek.type}".`);
  }
  const {unwrappedKey} = operation;
  const wrappedKey = await _aesWrapKey({kek, unwrappedKey});
  return {wrappedKey};
};

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
exports.unwrapKey = async ({kek, operation}) => {
  if(kek.type !== 'AesKeyWrappingKey2019') {
    throw new Error(`Unknown key type "${kek.type}".`);
  }
  const {wrappedKey} = operation;
  const unwrappedKey = await _aesUnwrapKey({kek, wrappedKey});
  return {unwrappedKey};
};

async function _aesWrapKey({kek, unwrappedKey}) {
  unwrappedKey = base64url.decode(unwrappedKey);
  const secret = base64url.decode(kek.secret);
  const cipher = crypto.createCipheriv(
    _constants.AES_KW_ALGORITHM, secret, _constants.AES_KW_RFC3394_IV);
  const output = Buffer.concat([cipher.update(unwrappedKey), cipher.final()]);
  return base64url.encode(output);
}

async function _aesUnwrapKey({kek, wrappedKey}) {
  wrappedKey = base64url.decode(wrappedKey);
  const secret = base64url.decode(kek.secret);
  const decipher = crypto.createDecipheriv(
    _constants.AES_KW_ALGORITHM, secret, _constants.AES_KW_RFC3394_IV);
  const output = Buffer.concat([decipher.update(wrappedKey), decipher.final()]);
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
