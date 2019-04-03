/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

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
