/*!
 * Copyright (c) 2019-2024 Digital Bazaar, Inc. All rights reserved.
 */
export const AES_KW_ALGORITHM = 'id-aes256-wrap';
export const AES_KW_RFC3394_IV = Buffer.from('A6A6A6A6A6A6A6A6', 'hex');

export const SYMMETRIC_KEY_TYPES = new Map([
  ['AesKeyWrappingKey2019', 'https://w3id.org/security/suites/aes-2019/v1'],
  ['Sha256HmacKey2019', 'https://w3id.org/security/suites/hmac-2019/v1']
]);
