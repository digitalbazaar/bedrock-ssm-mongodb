/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as base64url from 'base64url-universal';
import * as bedrock from '@bedrock/core';
import * as database from '@bedrock/mongodb';
import * as ecdsa from '@digitalbazaar/ecdsa-multikey';
import {CryptoLD} from 'crypto-ld';
import {
  Ed25519VerificationKey2018
} from '@digitalbazaar/ed25519-verification-key-2018';
import {
  Ed25519VerificationKey2020
} from '@digitalbazaar/ed25519-verification-key-2020';
import {parseTemplate} from 'url-template';
import {splitKeyId} from './helpers.js';

const {util: {BedrockError}} = bedrock;

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
    // FIXME: use new new multikey libs
    if(type === 'urn:webkms:multikey:Ed25519') {
      keyPair = await cryptoLd.generate(
        {id: keyId, type: 'Ed25519VerificationKey2020'});
      key = await keyPair.export(
        {publicKey: true, privateKey: true, includeContext: true});
      key['@context'] = 'https://w3id.org/security/multikey/v1';
      key.type = type;
    } else if(type.startsWith('urn:webkms:multikey:P-')) {
      const curve = type.slice('urn:webkms:multikey:'.length);
      keyPair = await ecdsa.generate({id: keyId, curve});
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
    keyPair = await cryptoLd.generate({id: keyId, type});
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
  const {verifyData} = operation;
  // FIXME: use new multikey libs
  let signer;
  if(key.type.startsWith('urn:webkms:multikey:P-')) {
    const multikey = {
      ...key,
      type: 'Multikey'
    };
    const keyPair = await ecdsa.from(multikey);
    signer = keyPair.signer();
  } else {
    if(key.type === 'urn:webkms:multikey:Ed25519') {
      key = {
        ...key,
        '@context': 'https://w3id.org/security/suites/ed25519-2020/v1',
        type: 'Ed25519VerificationKey2020'
      };
    }
    const keyPair = await cryptoLd.from(key);
    signer = keyPair.signer();
  }
  const {sign} = signer;
  const signatureBytes = await sign({data: base64url.decode(verifyData)});
  return {signatureValue: base64url.encode(signatureBytes)};
}
