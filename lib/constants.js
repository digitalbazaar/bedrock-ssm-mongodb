/*!
 * Copyright (c) 2019-2025 Digital Bazaar, Inc. All rights reserved.
 */
export const AES_KW_ALGORITHM = 'id-aes256-wrap';
export const AES_KW_RFC3394_IV = Buffer.from('A6A6A6A6A6A6A6A6', 'hex');

export const SYMMETRIC_KEY_TYPES = new Map([
  ['AesKeyWrappingKey2019', 'https://w3id.org/security/suites/aes-2019/v1'],
  ['Sha256HmacKey2019', 'https://w3id.org/security/suites/hmac-2019/v1']
]);

/* Multikey registry IDs and encoded header values
aes-128 | 0xa0 | 128-bit AES symmetric key
aes-192 | 0xa1 | 192-bit AES symmetric key
aes-256 | 0xa2 | 256-bit AES symmetric key
*/
export const SUPPORTED_WRAP_KEYS = new Map([
  ['aes-128', {header: new Uint8Array([0xa0, 0x01]), size: 16}],
  ['aes-192', {header: new Uint8Array([0xa1, 0x01]), size: 24}],
  ['aes-256', {header: new Uint8Array([0xa2, 0x01]), size: 32}]
]);
