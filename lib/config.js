/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import {config} from 'bedrock';

const cfg = config['ssm-mongodb'] = {};
cfg.keyRecordCache = {
  maxSize: 100,
  maxAge: 5000
};
