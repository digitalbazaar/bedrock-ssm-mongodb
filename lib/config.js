/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {config} = require('bedrock');

const cfg = config['ssm-mongodb'] = {};
cfg.keyRecordCache = {
  maxSize: 100,
  maxAge: 5000
};
