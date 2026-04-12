/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {
  createKeyRecordCache, KeyStorage
} from '@bedrock/kms-module-key-storage';

let KEY_RECORD_CACHE;

bedrock.events.on('bedrock.init', async () => {
  const cfg = bedrock.config['ssm-mongodb'];
  KEY_RECORD_CACHE = createKeyRecordCache(cfg.keyRecordCache);
});

export async function createKeyStorage({collectionName, recordCipher} = {}) {
  return KeyStorage.create({
    collectionName, recordCipher, cache: KEY_RECORD_CACHE
  });
}
