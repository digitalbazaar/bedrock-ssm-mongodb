/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

exports.AES_KW_ALGORITHM = 'id-aes256-wrap';
exports.AES_KW_RFC3394_IV = Buffer.from('A6A6A6A6A6A6A6A6', 'hex');

exports.KEY_TYPES = {
  asymmetric: new Set([
    'Ed25519VerificationKey2018',
    'Ed25519VerificationKey2020'
  ]),
  keyAgreement: new Set([
    'X25519KeyAgreementKey2020'
  ]),
  symmetric: new Map([
    ['AesKeyWrappingKey2019',
      'https://w3id.org/security/aes-key-wrapping-2019/v1'],
    ['Sha256HmacKey2019',
      'https://w3id.org/security/sha256-hmac-2019/v1']
  ])
};
