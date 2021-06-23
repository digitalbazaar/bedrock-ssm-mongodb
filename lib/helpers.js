/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

exports.splitKeyId = function splitKeyId({id}) {
  // format: <keystoreId>/<localId>
  const idx = id.lastIndexOf('/');
  return {
    keystoreId: id.substring(0, idx),
    localId: id.substr(idx + 1)
  };
};
