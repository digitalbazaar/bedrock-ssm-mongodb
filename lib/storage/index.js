/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {KeyStorage} from './KeyStorage.js';
// FIXME: replace with lru-memoized
import {LRUCache as LRU} from 'lru-cache';

// FIXME: remove singleton
let STORAGE;

export async function createKeyStorage({
  collectionName, recordCipher, cache
} = {}) {
  const storage = await KeyStorage.create({
    collectionName, recordCipher, cache
  });

  bedrock.events.on('bedrock.start', () => {
    if(!storage.initialized) {
      throw new Error(
        '"createKeyStorage" must be called no later than the ' +
        '"bedrock.init" event.');
    }
  });

  return storage;
}

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

  const cache = new LRU(cacheConfig);

  STORAGE = await createKeyStorage({
    collectionName: 'ssm',
    // recordCipher,
    cache
  });
});

export async function insertKey({key}) {
  // FIXME: use returned `storage` instance instead where this is called
  return STORAGE.insert({key});
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
  // FIXME: use returned `storage` instance instead where this is called
  return STORAGE.getCount({keystoreId});
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
  // FIXME: use returned `storage` instance instead where this is called
  return STORAGE.get({id});
}
