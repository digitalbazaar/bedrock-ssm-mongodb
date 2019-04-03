/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

exports.keyTypes = {
  asymmetric: new Set([
    'Ed25519VerificationKey2018',
  ]),
  symmetric: new Set([
    'AesKeyWrappingKey2019',
    'Sha256HmacKey2019',
  ])
};
