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
    // where the ID is multicodec encoded 16 byte random value
    // 0x00 = identity tag, 0x10 = length (16 bytes) header
    localId: Buffer.from(base58.decode(localId.slice(1)).slice(2))
  };
};
