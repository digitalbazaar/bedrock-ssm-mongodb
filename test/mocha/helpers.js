/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

exports.getKeystoreId = function({id}) {
  const idx = id.lastIndexOf('/');
  return id.substring(0, idx);
};
