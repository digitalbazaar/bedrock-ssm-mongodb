/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const base64url = require('base64url-universal');
const {CryptoLD} = require('crypto-ld');
const database = require('bedrock-mongodb');
const {util: {BedrockError}} = require('bedrock');
const {Ed25519VerificationKey2020} = require(
  '@digitalbazaar/ed25519-verification-key-2020');
const {Ed25519VerificationKey2018} = require(
  '@digitalbazaar/ed25519-verification-key-2018');
const {splitKeyId} = require('./helpers');
const urlTemplate = require('url-template');

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
 * @param {string} options.controller - The key controller.
 * @param {string} [options.publicAlias] - The public alias for the key.
 * @param {string} [options.publicAliasTemplate] - The public alias template
 *   for the key.
 *
 * @returns {Promise<object>} An object containing public key material.
 */
exports.generateKeyPair = async ({
  keyId, type, controller, publicAlias, publicAliasTemplate
} = {}) => {
  // if `publicAliasTemplate` was given, ensure it can be parsed
  let template;
  if(publicAliasTemplate) {
    template = urlTemplate.parse(publicAliasTemplate);
  }

  const keyPair = await cryptoLd.generate({id: keyId, type});
  const key = keyPair.export({
    publicKey: true, privateKey: true, includeContext: true
  });

  // add any public alias or template
  if(publicAlias) {
    key.publicAlias = publicAlias;
  } else if(publicAliasTemplate) {
    key.publicAliasTemplate = publicAliasTemplate;
  }

  // remove any `controller` as it is not stored with the key; it is always
  // updated to be the current keystore controller
  delete key.controller;

  const now = Date.now();
  const meta = {created: now, updated: now};
  const {keystoreId, localId} = splitKeyId({id: keyId});
  const record = {
    keystoreId,
    localId,
    meta,
    key
  };

  // prepare key description prior to storage to avoid storing bad public
  // alias template
  const keyDescription = keyPair.export({
    publicKey: true, includeContext: true
  });
  keyDescription.controller = controller;

  // override `id` with `publicAlias` if provided
  if(key.publicAlias) {
    keyDescription.id = key.publicAlias;
  } else if(key.publicAliasTemplate) {
    // compute public alias from template
    keyDescription.id = template.expand(keyDescription);
  }

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

  return {keyId, keyDescription};
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
