/*!
 * Copyright (c) 2019-2025 Digital Bazaar, Inc. All rights reserved.
 */
import {config} from '@bedrock/core';

const cfg = config['ssm-mongodb'] = {};
cfg.keyRecordCache = {
  maxSize: 100,
  maxAge: 5000
};

cfg.keyRecordWrapping = {
  // current key for wrapping record secrets
  wrapKey: null,
  /*
  wrapKey: {
    id: '<a key identifier>',
    secretKeyMultibase: '<multibase encoding of an AES secret key>'
  }*/
};
