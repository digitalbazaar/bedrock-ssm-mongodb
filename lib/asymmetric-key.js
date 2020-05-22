/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const base64url = require('base64url-universal');
const database = require('bedrock-mongodb');
const {util: {BedrockError}} = require('bedrock');
const {LDKeyPair} = require('crypto-ld');

/**
 * Generates a new asymmetric key pair.
 *
 * @ignore
 * @param {Object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {Object} options.type - The key type.
 *
 * @returns {Promise<Object>} An object containing public key material.
 */
exports.generateKeyPair = async ({keyId, type}) => {
  const now = Date.now();
  const meta = {created: now};
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
  const timer = _getTimer();
  const {verifyData} = operation;
  const signer = (await LDKeyPair.from(key)).signer();
  const signatureBytes = await signer.sign(
    {data: base64url.decode(verifyData)});

  const result = {signatureValue: base64url.encode(signatureBytes)};
  console.log('SSM-MONGODB-ASYMMETRIC-SIGN ELAPSED', timer.elapsed());
  return result;
};

function _getTimer() {
  const NS_PER_SEC = 1000000000;
  const NS_PER_MS = 1000000;
  const time = process.hrtime();

  return {
    elapsed() {
      const [seconds, nanoseconds] = process.hrtime(time);
      return (seconds * NS_PER_SEC + nanoseconds) / NS_PER_MS;
    }
  };
}
