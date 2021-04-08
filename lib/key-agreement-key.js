/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const base64url = require('base64url-universal');
const base58 = require('bs58');
const database = require('bedrock-mongodb');
const {util: {BedrockError}} = require('bedrock');
const nacl = require('tweetnacl');

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

  // only `X25519KeyAgreementKey2019` supported
  if(type !== 'X25519KeyAgreementKey2019') {
    throw new Error(`Unknown key type "${type}".`);
  }

  const {secretKey, publicKey} = nacl.box.keyPair();
  const key = {
    id: keyId,
    type,
    privateKeyBase58: base58.encode(Buffer.from(
      secretKey.buffer, secretKey.byteOffset, secretKey.byteLength)),
    publicKeyBase58: base58.encode(Buffer.from(
      publicKey.buffer, publicKey.byteOffset, publicKey.byteLength))
  };

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

  const publicKeyNode = {...key};
  delete publicKeyNode.privateKeyBase58;
  return publicKeyNode;
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
 * @returns {Promise<object>} Contains `{secret}`.
 */
exports.deriveSecret = async ({key, operation}) => {
  const {publicKey} = operation;
  if(publicKey.type !== key.type) {
    throw Error(
      `The given public key type "${publicKey.type}" does not match the ` +
      `key agreement key's ${key.type}.`);
  }
  const privateKey = base58.decode(key.privateKeyBase58);
  const remotePublicKey = base58.decode(publicKey.publicKeyBase58);
  const secret = await _deriveSecret({privateKey, remotePublicKey});
  return {secret: base64url.encode(secret)};
};

async function _deriveSecret({privateKey, remotePublicKey}) {
  // `scalarMult` takes secret key as param 1, public key as param 2
  return nacl.scalarMult(privateKey, remotePublicKey);
}
