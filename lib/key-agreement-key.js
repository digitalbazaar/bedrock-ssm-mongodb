/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const database = require('bedrock-mongodb');
const {util: {BedrockError}} = require('bedrock');
const {X25519KeyAgreementKey2020} =
  require('@digitalbazaar/x25519-key-agreement-key-2020');

/**
 * Generates a new key agreement key pair.
 *
 * @ignore
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {object} options.type - The key type.
 *
 * @returns {Promise<object>} An object containing public key material.
 */
exports.generateKeyPair = async ({keyId, type}) => {
  const now = Date.now();
  const meta = {created: now};

  // only `X25519KeyAgreementKey2020` supported
  if(type !== 'X25519KeyAgreementKey2020') {
    throw new Error(`Unsupported key type "${type}".`);
  }

  const keyPair = await X25519KeyAgreementKey2020.generate({id: keyId});

  const record = {
    id: database.hash(keyId),
    meta,
    key: keyPair.export({publicKey: true, privateKey: true})
  };

  try {
    await database.collections.ssm.insertOne(record, database.writeOptions);
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

  return {...keyPair.export({publicKey: true})};
};

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
exports.deriveSecret = async ({key, operation}) => {
  const {publicKey} = operation;
  if(publicKey.type !== key.type) {
    throw Error(
      `The given public key type "${publicKey.type}" does not match the ` +
      `key agreement key's ${key.type}.`);
  }

  const keyPair = await X25519KeyAgreementKey2020.from(key);
  const secret = await keyPair.deriveSecret({publicKey});

  return {secret};
};
