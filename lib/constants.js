/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as akwContext from 'aes-key-wrapping-2019-context';
import * as hmacContext from 'sha256-hmac-key-2019-context';

const {constants: {CONTEXT_URL: AES_2019_CONTEXT_URL}} = akwContext;
const {constants: {CONTEXT_URL: HMAC_2019_CONTEXT_URL}} = hmacContext;

export const AES_KW_ALGORITHM = 'id-aes256-wrap';
export const AES_KW_RFC3394_IV = Buffer.from('A6A6A6A6A6A6A6A6', 'hex');

export const KEY_TYPES = {
  asymmetric: new Set([
    'Ed25519VerificationKey2018',
    'Ed25519VerificationKey2020',
    'urn:webkms:multikey:Ed25519'
  ]),
  keyAgreement: new Set([
    'X25519KeyAgreementKey2020'
  ]),
  symmetric: new Map([
    ['AesKeyWrappingKey2019', AES_2019_CONTEXT_URL],
    ['Sha256HmacKey2019', HMAC_2019_CONTEXT_URL]
  ])
};
