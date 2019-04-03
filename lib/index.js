/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const assert = require('assert-plus');
const base64url = require('base64url-universal');
const bedrock = require('bedrock');
const brPackageManager = require('bedrock-package-manager');
const crypto = require('crypto');
const database = require('bedrock-mongodb');
const {LDKeyPair} = require('crypto-ld');
const {promisify} = require('util');
const {util: {BedrockError}} = bedrock;

// load config defaults
require('./config');

const AES_KW_ALGORITHM = 'id-aes256-wrap';
const AES_KW_RFC3394_IV = Buffer.from('A6A6A6A6A6A6A6A6', 'hex');

bedrock.events.on('bedrock.init', () => brPackageManager.register({
  alias: 'ssm-v1',
  packageName: 'bedrock-ssm-mongodb',
  type: 'bedrock-kms-store',
}));

bedrock.events.on('bedrock-mongodb.ready', async () => {
  await promisify(database.openCollections)(['ssm']);

  await promisify(database.createIndexes)([{
    // cover queries by ID
    collection: 'ssm',
    fields: {id: 1},
    options: {unique: true, background: false}
  }]);
});

/**
 * @module bedrock-ssm-mongodb
 */

/**
 * Generates a new symmetric key.
 *
 * @param {Object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {Object} options.operation - The KMS operation.
 *
 * @returns {Promise<Object>} An object containing `{id}`.
 */
exports.generateKey = async ({keyId, operation}) => {
  assert.string(keyId, 'options.keyId');
  assert.object(operation, 'options.operation');

  let key;

  const {invocationTarget: {type}} = operation;
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
 * Generates a new asymmetric key pair.
 *
 * @param {Object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {Object} options.operation - The KMS operation.
 *
 * @returns {Promise<Object>} An object containing public key material.
 */
exports.generateKeyPair = async ({keyId, operation}) => {
  assert.string(keyId, 'options.keyId');
  assert.object(operation, 'options.operation');

  const now = Date.now();
  const meta = {created: now};
  const {invocationTarget: {type}} = operation;
  const key = await LDKeyPair.generate({id: keyId, type});
  // remove unused properties
  delete key.controller;
  delete key.owner;
  delete key.passphrase;
  const record = {
    id: database.hash(keyId),
    meta,
    key
  };

  try {
    await database.collections.ssm.insert(record, database.writeOptions);
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

  return key.publicNode();
};

/**
 * Wraps a cryptographic key using a key encryption key (KEK).
 *
 * @param {Object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {Object} options.operation - The KMS operation.
 *
 * @returns {Promise<Object>} An object containing `{wrappedKey}`.
 */
exports.wrapKey = async ({keyId, operation}) => {
  assert.string(keyId, 'options.keyId');
  assert.object(operation, 'options.operation');

  const {key: kek} = await _getKeyRecord({id: keyId});
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
 * @param {Object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {Object} options.operation - The KMS operation.
 *
 * @returns {Promise<Object>} An object containing `{unwrappedKey}`.
 */
exports.unwrapKey = async ({keyId, operation}) => {
  assert.string(keyId, 'options.keyId');
  assert.object(operation, 'options.operation');

  const {key: kek} = await _getKeyRecord({id: keyId});
  if(kek.type !== 'AesKeyWrappingKey2019') {
    throw new Error(`Unknown key type "${kek.type}".`);
  }

  const {wrappedKey} = operation;
  const unwrappedKey = await _aesUnwrapKey({kek, wrappedKey});
  return {unwrappedKey};
};

/**
 * Signs some data. Note that the data will be sent to the server, so if
 * this data is intended to be secret it should be hashed first. However,
 * hashing the data first may present interoperability issues so choose
 * wisely.
 *
 * @param {Object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {Object} options.operation - The KMS operation.
 *
 * @returns {Promise<Object>} An object containing `{signatureValue}`.
 */
exports.sign = async ({keyId, operation}) => {
  assert.string(keyId, 'options.keyId');
  assert.object(operation, 'options.operation');

  const {key} = await _getKeyRecord({id: keyId});

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
 * @param {Object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {Object} options.operation - The KMS operation.
 *
 * @returns {Promise<Object>} An object containing `{verified}`.
 */
exports.verify = async ({keyId, operation}) => {
  assert.string(keyId, 'options.keyId');
  assert.object(operation, 'options.operation');

  const {key} = await _getKeyRecord({id: keyId});

  const {signatureValue, verifyData} = operation;
  const verified = await _hs256Verify({key, verifyData, signatureValue});
  return {verified};
};

/**
 * Gets a previously stored key record.
 *
 * @ignore
 * @param {Object} options - The options to use.
 * @param {string} options.id - The ID of the key.
 *
 * @returns {Promise<Object>} The key record.
 */
async function _getKeyRecord({id}) {
  assert.string(id, 'options.id');

  const record = await database.collections.ssm.findOne(
    {id: database.hash(id)}, {_id: 0, key: 1, meta: 1});
  if(!record) {
    throw new BedrockError(
      'Key not found.',
      'NotFoundError',
      {key: id, httpStatusCode: 404, public: true});
  }

  return record;
}

async function _aesWrapKey({kek, unwrappedKey}) {
  unwrappedKey = base64url.decode(unwrappedKey);
  const secret = base64url.decode(kek.secret);
  const cipher = crypto.createCipheriv(
    AES_KW_ALGORITHM, secret, AES_KW_RFC3394_IV);
  const output = Buffer.concat([cipher.update(unwrappedKey), cipher.final()]);
  return base64url.encode(output);
}

async function _aesUnwrapKey({kek, wrappedKey}) {
  wrappedKey = base64url.decode(wrappedKey);
  const secret = base64url.decode(kek.secret);
  const decipher = crypto.createDecipheriv(
    AES_KW_ALGORITHM, secret, AES_KW_RFC3394_IV);
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
