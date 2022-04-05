/*!
 * Copyright (c) 2021-2022 Digital Bazaar, Inc. All rights reserved.
 */
export function localId({id}) {
  const idx = id.lastIndexOf('/');
  return id.substring(0, idx);
}
