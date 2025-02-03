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
aes-256 | 0xa2 | 256-bit AES symmetric key
*/
export const SUPPORTED_KEK_TYPES = new Map([
  ['aes-256', {header: new Uint8Array([0xa2, 0x01]), size: 32}]
]);
