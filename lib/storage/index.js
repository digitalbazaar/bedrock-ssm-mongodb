/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as base58 from 'base58-universal';
import * as bedrock from '@bedrock/core';
import * as database from '@bedrock/mongodb';
import {decryptKeySecrets, encryptKeySecrets} from './keySecrets.js';
import assert from 'assert-plus';
// FIXME: replace with lru-memoized
import {LRUCache as LRU} from 'lru-cache';

const {util: {BedrockError}} = bedrock;

let KEY_RECORD_CACHE;

bedrock.events.on('bedrock.init', async () => {
  const cfg = bedrock.config['ssm-mongodb'];
  let cacheConfig = cfg.keyRecordCache;

  // coerce `maxSize` w/o `sizeCalculation` to `max`
  if(cacheConfig.maxSize !== undefined &&
    cacheConfig.sizeCalculation === undefined) {
    cacheConfig = {...cacheConfig, max: cacheConfig.maxSize};
    delete cacheConfig.maxSize;
  }

  // coerce `maxAge` to `ttl` in `cacheConfig`
  if(cacheConfig.maxAge !== undefined) {
    cacheConfig = {...cacheConfig, ttl: cacheConfig.maxAge};
    delete cacheConfig.maxAge;
  }

  KEY_RECORD_CACHE = new LRU(cacheConfig);
});

bedrock.events.on('bedrock-mongodb.ready', async () => {
  await database.openCollections(['ssm']);

  await database.createIndexes([{
    // cover queries by ID (<keystoreId>/<localId>)
    collection: 'ssm',
    fields: {keystoreId: 1, localId: 1},
    options: {unique: true}
  }]);
});

export async function insertKey({id, key}) {
  // store key record
  const now = Date.now();
  const meta = {created: now, updated: now};
  const {keystoreId, localId} = _splitKeyId({id});
  const record = {keystoreId, localId, meta, key};

  // encrypt key secrets according to configuration
  record.key = await encryptKeySecrets({key: record.key});

  try {
    await database.collections.ssm.insertOne(record);
  } catch(e) {
    if(!database.isDuplicateError(e)) {
      throw e;
    }
    throw new BedrockError('Duplicate key identifier.', {
      name: 'DuplicateError',
      details: {public: true, httpStatusCode: 409},
      cause: e
    });
  }

  return record;
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
  const count = await database.collections.ssm.countDocuments({keystoreId});
  return {count};
}

/**
 * Gets a previously stored key record.
 *
 * @ignore
 * @param {object} options - The options to use.
 * @param {string} options.id - The ID of the key.
 *
 * @returns {Promise<object>} The key record.
 */
export async function getKeyRecord({id}) {
  assert.string(id, 'options.id');

  const record = await _getCachedRecord({id});

  // decrypt key secrets according to configuration
  const key = await decryptKeySecrets({key: record.key});
  return {...record, key};
}

async function _getCachedRecord({id}) {
  let promise = KEY_RECORD_CACHE.get(id);
  if(promise) {
    return promise;
  }

  promise = _getUncachedKeyRecord({id});
  KEY_RECORD_CACHE.set(id, promise);

  let record;
  try {
    record = await promise;
  } catch(e) {
    KEY_RECORD_CACHE.delete(id);
    throw e;
  }

  return record;
}

async function _getUncachedKeyRecord({id}) {
  assert.string(id, 'options.id');

  const {keystoreId, localId} = _splitKeyId({id});
  const record = await database.collections.ssm.findOne(
    {keystoreId, localId}, {projection: {_id: 0, key: 1, meta: 1}});
  if(!record) {
    throw new BedrockError('Key not found.', {
      name: 'NotFoundError',
      details: {key: id, httpStatusCode: 404, public: true}
    });
  }
  return record;
}

export function _splitKeyId({id}) {
  // format: <keystoreId>/<localId>
  const idx = id.lastIndexOf('/');
  const localId = id.substr(idx + 1);
  return {
    keystoreId: id.substring(0, idx),
    // convert to `Buffer` for storage savings (`z<base58-encoded ID>`)
    // where the ID is multicodec encoded 16 byte random value
    // 0x00 = identity tag, 0x10 = length (16 bytes) header
    localId: Buffer.from(base58.decode(localId.slice(1)).slice(2))
  };
}
