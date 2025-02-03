/*!
 * Copyright (c) 2019-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as base64url from 'base64url-universal';
import * as bedrock from '@bedrock/core';
import * as database from '@bedrock/mongodb';
import * as urlTemplate from 'url-template';
import {decryptKeySecrets, encryptKeySecrets} from './aeskw.js';
import {splitKeyId} from './helpers.js';
import {
  X25519KeyAgreementKey2020
} from '@digitalbazaar/x25519-key-agreement-key-2020';

const {util: {BedrockError}} = bedrock;

/**
 * Generates a new key agreement key pair.
 *
 * @ignore
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {object} options.type - The key type.
 * @param {string} options.controller - The key controller.
 * @param {number} [options.maxCapabilityChainLength] - The max acceptable
 *   length of the capability chain used in a capability invocation to invoke a
 *   KMS operation with the key.
 * @param {string} [options.publicAlias] - The public alias for the key.
 * @param {string} [options.publicAliasTemplate] - The public alias template
 *   for the key.
 *
 * @returns {Promise<object>} An object containing public key material.
 */
export async function generateKeyPair({
  keyId, type, controller,
  maxCapabilityChainLength, publicAlias, publicAliasTemplate
} = {}) {
  // only `X25519KeyAgreementKey2020` supported
  if(type !== 'X25519KeyAgreementKey2020') {
    throw new Error(`Unsupported key type "${type}".`);
  }

  // if `publicAliasTemplate` was given, ensure it can be parsed
  let template;
  if(publicAliasTemplate) {
    template = urlTemplate.parse(publicAliasTemplate);
  }

  const keyPair = await X25519KeyAgreementKey2020.generate({id: keyId});
  const key = keyPair.export({
    publicKey: true, privateKey: true, includeContext: true
  });

  // add any extra key restrictions
  if(maxCapabilityChainLength !== undefined) {
    key.maxCapabilityChainLength = maxCapabilityChainLength;
  }

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

  // encrypt key secrets according to configuration
  record.key = await encryptKeySecrets({key: record.key});

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
}

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
export async function deriveSecret({key, operation}) {
  const {publicKey} = operation;
  if(publicKey.type !== key.type) {
    throw Error(
      `The given public key type "${publicKey.type}" does not match the ` +
      `key agreement key's ${key.type}.`);
  }

  // decrypt key secrets according to configuration
  key = await decryptKeySecrets({key});
  const keyPair = await X25519KeyAgreementKey2020.from(key);
  const secret = await keyPair.deriveSecret({publicKey});

  return {secret: base64url.encode(secret)};
}
