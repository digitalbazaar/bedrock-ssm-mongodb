/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as base64url from 'base64url-universal';
import * as bedrock from '@bedrock/core';
import * as bls12381Multikey from '@digitalbazaar/bls12-381-multikey';
import * as ecdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import * as ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import {
  Ed25519VerificationKey2018
} from '@digitalbazaar/ed25519-verification-key-2018';
import {
  Ed25519VerificationKey2020
} from '@digitalbazaar/ed25519-verification-key-2020';

const {util: {BedrockError}} = bedrock;

/**
 * Generates a new asymmetric key pair.
 *
 * @ignore
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {object} options.type - The key type.
 * @param {string} options.controller - The key controller.
 *
 * @returns {Promise<object>} An object containing public key material.
 */
export async function generateKeyPair({keyId, type, controller} = {}) {
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
      throw new BedrockError(`Unsupported key type "${type}".`, {
        name: 'NotSupportedError',
        details: {public: true, httpStatusCode: 400}
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

  // create public key description
  const keyDescription = await keyPair.export({
    publicKey: true, includeContext: true
  });
  keyDescription.controller = controller;
  if(keyDescriptionType === 'Multikey') {
    keyDescription['@context'] = 'https://w3id.org/security/multikey/v1';
    keyDescription.type = 'Multikey';
  }

  return {key, keyDescription};
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
