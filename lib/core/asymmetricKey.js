/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as base64url from 'base64url-universal';
import * as bedrock from '@bedrock/core';
import * as bls12381Multikey from '@digitalbazaar/bls12-381-multikey';
import * as database from '@bedrock/mongodb';
import * as ecdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import * as ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import {decryptKeySecrets, encryptKeySecrets} from '../keySecrets.js';
import {
  Ed25519VerificationKey2018
} from '@digitalbazaar/ed25519-verification-key-2018';
import {
  Ed25519VerificationKey2020
} from '@digitalbazaar/ed25519-verification-key-2020';
import {parseTemplate} from 'url-template';
import {splitKeyId} from '../helpers.js';

const {util: {BedrockError}} = bedrock;

/**
 * Generates a new asymmetric key pair.
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
  // if `publicAliasTemplate` was given, ensure it can be parsed
  let template;
  if(publicAliasTemplate) {
    template = parseTemplate(publicAliasTemplate);
  }

  let keyDescriptionType;
  let key;
  let keyPair;
  if(type.startsWith('urn:webkms:multikey:')) {
    keyDescriptionType = 'Multikey';
    if(type === 'urn:webkms:multikey:Ed25519') {
      keyPair = await ed25519Multikey.generate({id: keyId});
      key = await keyPair.export(
        {publicKey: true, secretKey: true, includeContext: true});
      key.type = type;
    } else if(type.startsWith('urn:webkms:multikey:P-')) {
      const curve = type.slice('urn:webkms:multikey:'.length);
      keyPair = await ecdsaMultikey.generate({id: keyId, curve});
      key = await keyPair.export(
        {publicKey: true, secretKey: true, includeContext: true});
      key.type = type;
    } else if(type.startsWith('urn:webkms:multikey:BBS-') ||
      type === 'urn:webkms:multikey:Bls12381G2') {
      let algorithm = type.slice('urn:webkms:multikey:'.length);
      if(algorithm === 'Bls12381G2') {
        // default curve-as-algorithm to:
        algorithm = 'BBS-BLS12-381-SHA-256';
      }
      keyPair = await bls12381Multikey.generateBbsKeyPair(
        {id: keyId, algorithm});
      key = await keyPair.export(
        {publicKey: true, secretKey: true, includeContext: true});
      key.type = type;
    } else {
      // FIXME: support other types
      throw new BedrockError(
        `Unsupported key type "${type}".`,
        'NotSupportedError', {
          public: true,
          httpStatusCode: 400
        });
    }
  } else {
    keyDescriptionType = type;
    if(type === 'Ed25519VerificationKey2020') {
      keyPair = await Ed25519VerificationKey2020.generate({id: keyId, type});
    } else if(type === 'Ed25519VerificationKey2018') {
      keyPair = await Ed25519VerificationKey2018.generate({id: keyId, type});
    }
    key = await keyPair.export({
      publicKey: true, privateKey: true, includeContext: true
    });
  }

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

  // prepare key description prior to storage to avoid storing bad public
  // alias template
  const keyDescription = await keyPair.export({
    publicKey: true, includeContext: true
  });
  keyDescription.controller = controller;
  if(keyDescriptionType === 'Multikey') {
    keyDescription['@context'] = 'https://w3id.org/security/multikey/v1';
    keyDescription.type = 'Multikey';
  }

  // override `id` with `publicAlias` if provided
  if(key.publicAlias) {
    keyDescription.id = key.publicAlias;
  } else if(key.publicAliasTemplate) {
    // compute public alias from template
    keyDescription.id = template.expand(keyDescription);
  }

  // store key record
  const now = Date.now();
  const meta = {created: now, updated: now};
  const {keystoreId, localId} = splitKeyId({id: keyId});
  const record = {
    keystoreId,
    localId,
    meta,
    key
  };

  // encrypt key secrets according to configuration
  record.key = await encryptKeySecrets({key: record.key});

  try {
    await database.collections.ssm.insertOne(record);
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
 * @param {object} options.key - The key to use.
 * @param {object} options.operation - The KMS operation.
 *
 * @returns {Promise<object>} Contains `{signatureValue}`.
 */
export async function sign({key, operation}) {
  // decrypt key secrets according to configuration
  key = await decryptKeySecrets({key});

  const {verifyData} = operation;
  let signer;
  const {type} = key;
  if(type.startsWith('urn:webkms:multikey:P-')) {
    const multikey = {
      ...key,
      type: 'Multikey'
    };
    const keyPair = await ecdsaMultikey.from(multikey);
    signer = keyPair.signer();
  } else if(type.startsWith('urn:webkms:multikey:BBS-') ||
    type === 'urn:webkms:multikey:Bls12381G2') {
    const multikey = {
      ...key,
      type: 'Multikey'
    };
    const keyPair = await bls12381Multikey.from(multikey);
    signer = keyPair.signer();
  } else {
    if(type === 'urn:webkms:multikey:Ed25519') {
      key = {...key, type: 'Multikey'};
    }
    const keyPair = await ed25519Multikey.from(key);
    signer = keyPair.signer();
  }
  const {sign} = signer;
  const signatureBytes = await sign({data: base64url.decode(verifyData)});
  return {signatureValue: base64url.encode(signatureBytes)};
}
