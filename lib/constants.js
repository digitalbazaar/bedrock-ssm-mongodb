/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
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
    'X25519KeyAgreementKey2019'
  ]),
  symmetric: new Set([
    'AesKeyWrappingKey2019',
    'Sha256HmacKey2019',
  ])
};

exports.SECURITY_CONTEXT_V2_URL = 'https://w3id.org/security/v2';
