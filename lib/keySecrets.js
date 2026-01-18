/*!
 * Copyright (c) 2019-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as _constants from './constants.js';
import * as base64url from 'base64url-universal';
import * as bedrock from '@bedrock/core';
import {generalDecrypt, GeneralEncrypt} from 'jose';
import {logger} from './logger.js';

const {util: {BedrockError}} = bedrock;

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();

const NON_SECRET_PROPERTIES = new Set([
  '@context', 'id', 'type', 'controller',
  'publicKeyMultibase', 'maxCapabilityChainLength',
  'publicAlias', 'publicAliasTemplate'
]);

// load all key encryption keys (KEKs) from config
const KEKS = new Map();
bedrock.events.on('bedrock.init', () => {
  _loadKeks();
});

// pass `key` from a key `record`
export async function decryptKeySecrets({key} = {}) {
  if(key.encrypted === undefined) {
    // nothing to unwrap, return early
    return key;
  }

  try {
    // decrypt secrets
    const {kekId, jwe} = key.encrypted;
    const secretKey = _getKek(kekId);
    const {plaintext} = await generalDecrypt(jwe, secretKey);
    const secrets = JSON.parse(TEXT_DECODER.decode(plaintext));

    // new key object w/decrypted secrets
    key = {...key, ...secrets};
    delete key.encrypted;
    return key;
  } catch(cause) {
    throw new BedrockError('Could not decrypt key secrets.', {
      name: 'OperationError',
      cause,
      details: {
        public: true,
        httpStatusCode: 500
      }
    });
  }
}

// pass `key` from a key `record`
export async function encryptKeySecrets({key} = {}) {
  if(key.encrypted !== undefined) {
    // should not happen; bad call
    throw new Error(
      'Could not encrypt key secrets; key secrets already encrypted.');
  }

  try {
    // get current wrap key ID
    const kekId = bedrock.config['ssm-mongodb'].keyRecordEncryption?.kek?.id;
    if(!kekId) {
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
    const plaintext = _mapToBuffer(secrets);
    const secretKey = _getKek(kekId);
    const jwe = await new GeneralEncrypt(plaintext)
      .setProtectedHeader({enc: 'A256GCM'})
      .addRecipient(secretKey)
      .setUnprotectedHeader({alg: 'A256KW', kid: kekId})
      .encrypt();

    // return new key object w/encrypted secrets
    return {
      ...Object.fromEntries(nonSecrets.entries()),
      encrypted: {kekId, jwe}
    };
  } catch(cause) {
    throw new BedrockError('Could not encrypt key secrets.', {
      name: 'OperationError',
      cause,
      details: {
        public: true,
        httpStatusCode: 500
      }
    });
  }
}

function _getKek(kekId) {
  const secretKey = KEKS.get(kekId);
  if(secretKey) {
    return secretKey;
  }
  throw new BedrockError(`Key encryption key "${kekId}" not found.`, {
    name: 'NotFoundError',
    details: {
      public: true,
      httpStatusCode: 400
    }
  });
}

function _loadKek(secretKeyMultibase) {
  if(!secretKeyMultibase?.startsWith('u')) {
    throw new BedrockError(
      'Unsupported multibase header; ' +
      '"u" for base64url-encoding must be used.', {
        name: 'NotSupportedError',
        details: {
          public: true,
          httpStatusCode: 400
        }
      });
  }

  // check multikey header
  let keyType;
  let secretKey;
  const multikey = base64url.decode(secretKeyMultibase.slice(1));
  for(const [type, {header, size}] of _constants.SUPPORTED_KEK_TYPES) {
    if(multikey[0] === header[0] && multikey[1] === header[1]) {
      keyType = type;
      if(multikey.length !== (2 + size)) {
        // intentionally do not report what was detected because a
        // misconfigured secret could have its first two bytes revealed
        throw new BedrockError(
          'Incorrect multikey size or invalid multikey header.', {
            name: 'DataError',
            details: {
              public: true,
              httpStatusCode: 400
            }
          });
      }
      secretKey = multikey.subarray(2);
      break;
    }
  }
  if(keyType === undefined) {
    throw new BedrockError(
      'Unsupported multikey type; only AES-256 is supported.', {
        name: 'NotSupportedError',
        details: {
          public: true,
          httpStatusCode: 400
        }
      });
  }

  return secretKey;
}

// exported for testing purposes only
export function _loadKeks() {
  KEKS.clear();
  const cfg = bedrock.config['ssm-mongodb'];
  const key = cfg.keyRecordEncryption?.kek;
  if(!key) {
    logger.info('Key record encryption is disabled.');
  } else {
    if(!(key.id && typeof key.id === 'string')) {
      throw new BedrockError(
        'Invalid key encryption key configuration; ' +
        'key "id" must be a string.', {
          name: 'DataError',
          details: {
            public: true,
            httpStatusCode: 400
          }
        });
    }
    KEKS.set(key.id, _loadKek(key.secretKeyMultibase));
    logger.info('Key record encryption is enabled.');
  }
}

function _mapToBuffer(m) {
  return TEXT_ENCODER.encode(JSON.stringify(Object.fromEntries(m.entries())));
}
