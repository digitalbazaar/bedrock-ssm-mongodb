/*!
 * Copyright (c) 2019-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as _constants from './constants.js';
import crypto from 'node:crypto';

export async function wrapKey({secret, unwrapped} = {}) {
  const cipher = crypto.createCipheriv(
    _constants.AES_KW_ALGORITHM, secret, _constants.AES_KW_RFC3394_IV);
  return Buffer.concat([cipher.update(unwrapped), cipher.final()]);
}

export async function unwrapKey({secret, wrapped} = {}) {
  const decipher = crypto.createDecipheriv(
    _constants.AES_KW_ALGORITHM, secret, _constants.AES_KW_RFC3394_IV);
  return Buffer.concat([decipher.update(wrapped), decipher.final()]);
}
