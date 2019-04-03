/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

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
