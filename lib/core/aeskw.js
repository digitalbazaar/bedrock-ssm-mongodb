/*!
 * Copyright (c) 2019-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as _constants from '../constants.js';
import crypto from 'node:crypto';

export async function unwrapKey({secretKey, wrapped} = {}) {
  const decipher = crypto.createDecipheriv(
    _constants.AES_KW_ALGORITHM, secretKey, _constants.AES_KW_RFC3394_IV);
  return Buffer.concat([decipher.update(wrapped), decipher.final()]);
}

export async function wrapKey({secretKey, unwrapped} = {}) {
  const cipher = crypto.createCipheriv(
    _constants.AES_KW_ALGORITHM, secretKey, _constants.AES_KW_RFC3394_IV);
  return Buffer.concat([cipher.update(unwrapped), cipher.final()]);
}
