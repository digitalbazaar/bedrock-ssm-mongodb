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
 * @param {Object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {Object} options.operation - The KMS operation.
 *
 * @returns {Promise<Object>} An object containing `{id}`.
 */
exports.generateKey = async ({keyId, type}) => {
  let key;
  if(type === 'AesKeyWrappingKey2019') {
    // TODO: support other lengths?
    key = {
      id: keyId,
      type,
      secret: base64url.encode(crypto.randomBytes(32))
    };
  } else if(type === 'Sha256HmacKey2019') {
    // TODO: support other hashes?
    key = {
      id: keyId,
      type,
      secret: base64url.encode(crypto.randomBytes(32))
    };
  } else {
    throw new Error(`Unknown key type "${type}".`);
  }

  // insert the key and get the updated record
  const now = Date.now();
  const meta = {created: now};
  const record = {
    id: database.hash(keyId),
    meta,
    key
  };
  try {
    await database.collections.ssm.insert(record, database.writeOptions);
    return {id: keyId};
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
 * @param {Object} options - The options to use.
 * @param {Object} options.key - The key to use.
 * @param {Object} options.operation - The KMS operation.
 *
 * @returns {Promise<Object>} Contains `{signatureValue}`.
 */
exports.sign = async ({key, operation}) => {
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
 * @param {Object} options - The options to use.
 * @param {Object} options.key - The key to use.
 * @param {Object} options.operation - The KMS operation.
 *
 * @returns {Promise<Object>} An object containing `{verified}`.
 */
exports.verify = async ({key, operation}) => {
  const {signatureValue, verifyData} = operation;
  const verified = await _hs256Verify({key, verifyData, signatureValue});
  return {verified};
};

/**
 * Wraps a cryptographic key using a key encryption key (KEK).
 *
 * @ignore
 * @param {Object} options - The options to use.
 * @param {string} options.kek - The key encryption key to use.
 * @param {Object} options.operation - The KMS operation.
 *
 * @returns {Promise<Object>} An object containing `{wrappedKey}`.
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
 * @param {Object} options - The options to use.
 * @param {string} options.kek - The key encryption key to use.
 * @param {Object} options.operation - The KMS operation.
 *
 * @returns {Promise<Object>} An object containing `{unwrappedKey}`.
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
