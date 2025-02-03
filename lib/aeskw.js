/*!
 * Copyright (c) 2019-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as _constants from './constants.js';
import * as bedrock from '@bedrock/core';
import crypto from 'node:crypto';

const {util: {BedrockError}} = bedrock;

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();

const NON_SECRET_PROPERTIES = new Set([
  'id', 'type', 'publicKeyMultibase', 'maxCapabilityChainLength'
]);

// FIXME: load all wrap keys from config
const WRAP_KEYS = new Map();

export async function wrapKey({secretKey, unwrapped} = {}) {
  const cipher = crypto.createCipheriv(
    _constants.AES_KW_ALGORITHM, secretKey, _constants.AES_KW_RFC3394_IV);
  return Buffer.concat([cipher.update(unwrapped), cipher.final()]);
}

export async function unwrapKey({secretKey, wrapped} = {}) {
  const decipher = crypto.createDecipheriv(
    _constants.AES_KW_ALGORITHM, secretKey, _constants.AES_KW_RFC3394_IV);
  return Buffer.concat([decipher.update(wrapped), decipher.final()]);
}

export async function wrapRecordSecrets({wrapKeyId, record} = {}) {
  const {key} = record;

  if(key.wrappedSecrets !== undefined) {
    // should not happen; bad call
    throw new Error(
      'Could not wrap record secrets; record secrets already wrapped.');
  }

  try {
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

    // wrap secrets
    const unwrapped = _mapToBuffer(secrets);
    const secretKey = _getWrapKey(wrapKeyId);
    const wrapped = await wrapKey({secretKey, unwrapped});

    // new key object w/wrapped secrets
    const newKey = {
      ...Object.fromEntries(nonSecrets.entries()),
      wrappedSecrets: {
        wrapKeyId,
        wrapped
      }
    };

    // return new record
    return {...record, key: newKey};
  } catch(cause) {
    throw new BedrockError('Could not wrap record secrets.', {
      name: 'OperationError',
      cause,
      details: {
        public: true,
        httpStatusCode: 500
      }
    });
  }
}

export async function unwrapRecordSecrets({record} = {}) {
  const {key} = record;

  if(key.wrappedSecrets === undefined) {
    // nothing to unwrap, return record as-is early
    return record;
  }

  try {
    // unwrap secrets
    const {wrapKeyId, wrapped} = key.wrappedSecrets;
    const secretKey = _getWrapKey(wrapKeyId);
    const unwrapped = await unwrapKey({secretKey, wrapped});
    const secrets = JSON.parse(TEXT_DECODER.decode(unwrapped));

    // new key object w/unwrapped secrets
    const newKey = {
      ...key,
      ...secrets
    };

    // return new record
    return {...record, key: newKey};
  } catch(cause) {
    throw new BedrockError('Could not unwrap record secrets.', {
      name: 'OperationError',
      cause,
      details: {
        public: true,
        httpStatusCode: 500
      }
    });
  }
}

function _getWrapKey(wrapKeyId) {
  const secretKey = WRAP_KEYS.get(wrapKeyId);
  if(secretKey) {
    return secretKey;
  }
  throw new BedrockError(`Wrap key "${wrapKeyId}" not found.`, {
    name: 'NotFoundError',
    details: {
      public: true,
      httpStatusCode: 400
    }
  });
}

function _mapToBuffer(m) {
  return TEXT_ENCODER.encode(JSON.stringify(Object.fromEntries(m.entries())));
}
