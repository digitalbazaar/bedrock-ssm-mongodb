/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as brPackageManager from '@bedrock/package-manager';
import {Core, createKmsModule} from '@bedrock/kms-module-core';
import {createKeyStorage} from './storage.js';
import {logger} from './logger.js';
import {RecordCipher} from '@bedrock/record-cipher';

// load config defaults
import './config.js';

let CORE;
let KEY_STORAGE;
let KEY_RECORD_CIPHER;
let KMS_MODULE_API;

bedrock.events.on('bedrock.init', async () => {
  // create security module core and key record cipher/storage singletons
  CORE = new Core();
  KEY_RECORD_CIPHER = await _createKeyRecordCipher();
  KEY_STORAGE = await createKeyStorage({
    collectionName: 'ssm', recordCipher: KEY_RECORD_CIPHER
  });

  ({api: KMS_MODULE_API} = await createKmsModule({
    core: CORE, keyStorage: KEY_STORAGE
  }));

  return brPackageManager.register({
    alias: 'ssm-v1',
    packageName: '@bedrock/ssm-mongodb',
    type: 'webkms-module'
  });
});

/**
 * @module bedrock-ssm-mongodb
 */

/**
 * Returns the KMS module API for this module.
 *
 * @returns {Promise<object>} The KMS module API.
 */
export async function getKmsModuleApi() {
  return KMS_MODULE_API;
}

// backwards compatibility; expose KMS_MODULE_API on this JS module directly:

/**
 * Generates a new key.
 *
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {string} options.controller - The key controller.
 * @param {object} options.operation - The KMS operation.
 *
 * @returns {Promise<object>} Key information `{keyId, keyDescription}`.
 */
export async function generateKey({keyId, controller, operation} = {}) {
  return KMS_MODULE_API.generateKey({keyId, controller, operation});
}

/**
 * Gets the number of keys in a given keystore.
 *
 * @param {object} options - The options to use.
 * @param {string} options.keystoreId - The ID of the keystore.
 *
 * @returns {Promise<object>} Key count information.
 */
export async function getKeyCount({keystoreId} = {}) {
  return KMS_MODULE_API.getKeyCount({keystoreId});
}

/**
 * Gets the key description (no private key material) for the given key.
 *
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {string} options.controller - The key controller.
 *
 * @returns {Promise<object>} Key information.
 */
export async function getKeyDescription({keyId, controller} = {}) {
  return KMS_MODULE_API.getKeyDescription({keyId, controller});
}

/**
 * Wraps a cryptographic key using a key encryption key (KEK).
 *
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {object} options.operation - The KMS operation.
 * @param {object} [options.zcapInvocation] - The zcap invocation used to
 *   run the KMS operation; if the KMS operation was invoked via zcap.
 *
 * @returns {Promise<object>} An object containing `{wrappedKey}`.
 */
export async function wrapKey({keyId, operation, zcapInvocation} = {}) {
  return KMS_MODULE_API.wrapKey({keyId, operation, zcapInvocation});
}

/**
 * Unwraps a cryptographic key using a key encryption key (KEK).
 *
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {object} options.operation - The KMS operation.
 * @param {object} [options.zcapInvocation] - The zcap invocation used to
 *   run the KMS operation; if the KMS operation was invoked via zcap.
 *
 * @returns {Promise<object>} An object containing `{unwrappedKey}`.
 */
export async function unwrapKey({keyId, operation, zcapInvocation} = {}) {
  return KMS_MODULE_API.unwrapKey({keyId, operation, zcapInvocation});
}

/**
 * Signs some data. Note that the data will be sent to the server, so if
 * this data is intended to be secret it should be hashed first. However,
 * hashing the data first may present interoperability issues so choose
 * wisely.
 *
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {object} options.operation - The KMS operation.
 * @param {object} [options.zcapInvocation] - The zcap invocation used to
 *   run the KMS operation; if the KMS operation was invoked via zcap.
 *
 * @returns {Promise<object>} An object containing `{signatureValue}`.
 */
export async function sign({keyId, operation, zcapInvocation} = {}) {
  return KMS_MODULE_API.sign({keyId, operation, zcapInvocation});
}

/**
 * Verifies some data. Note that the data will be sent to the server, so if
 * this data is intended to be secret it should be hashed first. However,
 * hashing the data first may present interoperability issues so choose
 * wisely.
 *
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {object} options.operation - The KMS operation.
 * @param {object} [options.zcapInvocation] - The zcap invocation used to
 *   run the KMS operation; if the KMS operation was invoked via zcap.
 *
 * @returns {Promise<object>} An object containing `{verified}`.
 */
export async function verify({keyId, operation, zcapInvocation} = {}) {
  return KMS_MODULE_API.verify({keyId, operation, zcapInvocation});
}

/**
* Derives a shared secret via the given peer public key, typically for use
* as one parameter for computing a shared key. It should not be used as
* a shared key itself, but rather input into a key derivation function (KDF)
* to produce a shared key.
 *
 * @param {object} options - The options to use.
 * @param {string} options.keyId - The key ID to use.
 * @param {object} options.operation - The KMS operation.
 * @param {object} [options.zcapInvocation] - The zcap invocation used to
 *   run the KMS operation; if the KMS operation was invoked via zcap.
 *
 * @returns {Promise<object>} An object containing `{secret}`.
 */
export async function deriveSecret({keyId, operation, zcapInvocation} = {}) {
  return KMS_MODULE_API.deriveSecret({keyId, operation, zcapInvocation});
}

// exported for testing purposes only
export async function _createKeyRecordCipher() {
  const {kek} = bedrock.config['ssm-mongodb'].keyRecordEncryption;
  const options = {
    currentKekId: kek === null ? null : kek.id,
    keks: [],
    encoding: 'json'
  };
  if(kek !== null) {
    options.keks.push(kek);
  }
  KEY_RECORD_CIPHER = await RecordCipher.create(options);
  const status = KEY_RECORD_CIPHER.isSecretsEncryptionEnabled() ?
    'enabled' : 'disabled';
  logger.info(`Key record encryption is ${status}.`);
  if(KEY_STORAGE) {
    // replace instance in key storage to enable testing different configs
    KEY_STORAGE.recordCipher = KEY_RECORD_CIPHER;
  }
  return KEY_RECORD_CIPHER;
}
