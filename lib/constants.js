/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {constants: {CONTEXT_URL: AES_2019_CONTEXT_URL}} =
  require('aes-key-wrapping-2019-context');
const {constants: {CONTEXT_URL: HMAC_2019_CONTEXT_URL}} =
  require('sha256-hmac-key-2019-context');

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
    ['AesKeyWrappingKey2019', AES_2019_CONTEXT_URL],
    ['Sha256HmacKey2019', HMAC_2019_CONTEXT_URL]
  ])
};
