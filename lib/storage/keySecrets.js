/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {logger} from '../logger.js';
import {RecordCipher} from './RecordCipher.js';

const NON_SECRET_PROPERTIES = new Set([
  '@context', 'id', 'type', 'controller',
  'publicKeyMultibase', 'maxCapabilityChainLength',
  'publicAlias', 'publicAliasTemplate'
]);

// load all key encryption keys (KEKs) from config
let RECORD_CIPHER;
bedrock.events.on('bedrock.init', async () => {
  await _loadKeks();
});

// pass `key` from a key `record`
export async function decryptKeySecrets({key} = {}) {
  // decrypt secrets
  const {encrypted: encryptedSecrets, ...rest} = key;
  const {secrets} = await RECORD_CIPHER.decryptRecordSecrets({
    record: {encryptedSecrets}
  });
  // return new key object w/decrypted secrets
  return {...rest, ...secrets};
}

// pass `key` from a key `record`
export async function encryptKeySecrets({key} = {}) {
  if(key.encrypted !== undefined) {
    // should not happen; bad call
    throw new Error(
      'Could not encrypt key secrets; key secrets already encrypted.');
  }

  // get current wrap key ID
  if(!RECORD_CIPHER.isSecretsEncryptionEnabled()) {
    // no KEK config; return early
    return key;
  }

  // separate record key's non-secret / secret properties
  const nonSecrets = new Map();
  const secrets = new Map();
  for(const prop in key) {
    const value = key[prop];
    if(NON_SECRET_PROPERTIES.has(prop)) {
      nonSecrets.set(prop, value);
      continue;
    }
    secrets.set(prop, value);
  }

  // encrypt key secrets
  const {encryptedSecrets} = await RECORD_CIPHER.encryptRecordSecrets({
    record: {secrets}
  });

  // return new key object w/encrypted secrets
  return {
    ...Object.fromEntries(nonSecrets.entries()),
    encrypted: encryptedSecrets
  };
}

// exported for testing purposes only
export async function _loadKeks() {
  RECORD_CIPHER = await RecordCipher.fromConfig({
    config: bedrock.config['ssm-mongodb'].keyRecordEncryption,
    encoding: 'json'
  });
  const status = RECORD_CIPHER.isSecretsEncryptionEnabled() ?
    'enabled' : 'disabled';
  logger.info(`Key record encryption is ${status}.`);
}
