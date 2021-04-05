/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const base64url = require('base64url-universal');
const database = require('bedrock-mongodb');
const {util: {BedrockError}} = require('bedrock');
const {Ed25519VerificationKey2020} = require(
  '@digitalbazaar/ed25519-verification-key-2020');
const {Ed25519VerificationKey2018} = require(
  '@digitalbazaar/ed25519-verification-key-2018');
const {CryptoLD} = require('crypto-ld');

const cryptoLd = new CryptoLD();

cryptoLd.use(Ed25519VerificationKey2020);
cryptoLd.use(Ed25519VerificationKey2018);

/**
 * Generates a new asymmetric key pair.
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
  const key = await cryptoLd.generate({id: keyId, type});
  // remove unused properties
  delete key.controller;
  const record = {
    id: database.hash(keyId),
    meta,
    key
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

  return key.export({publicKey: true});
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
  const {verifyData} = operation;
  const keyPair = await cryptoLd.from(key);
  const {sign} = keyPair.signer();
  const signatureBytes = await sign({data: base64url.decode(verifyData)});

  return {signatureValue: base64url.encode(signatureBytes)};
};
