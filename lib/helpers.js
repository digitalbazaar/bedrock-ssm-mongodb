/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const base58 = require('base58-universal');

exports.splitKeyId = function splitKeyId({id}) {
  // format: <keystoreId>/<localId>
  const idx = id.lastIndexOf('/');
  const localId = id.substr(idx + 1);
  return {
    keystoreId: id.substring(0, idx),
    // convert to `Buffer` for storage savings (`z<base58-encoded ID>`)
    localId: Buffer.from(base58.decode(localId.slice(1)))
  };
};
