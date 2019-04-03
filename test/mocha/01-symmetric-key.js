/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const brSSM = require('bedrock-ssm-mongodb');

describe('generateKey API', () => {
  it('returns a key id for type Sha256HmacKey2019', async () => {
    const keyId = 'https://example.com/ksm/ssm-v1/my-hmac-key';
    const controller = 'https://example.com/i/foo';
    const type = 'Sha256HmacKey2019';
    const invocationTarget = {id: keyId, type, controller};
    const result = await brSSM.generateKey(
      {keyId, operation: {invocationTarget}});
    should.exist(result);
    result.should.be.an('object');
    result.should.have.property('id');
    result.id.should.be.a('string');
  });
  it('returns a key id for type AesKeyWrappingKey2019', async () => {
    const keyId = 'https://example.com/ksm/ssm-v1/my-kek';
    const controller = 'https://example.com/i/foo';
    const type = 'AesKeyWrappingKey2019';
    const invocationTarget = {id: keyId, type, controller};
    const result = await brSSM.generateKey(
      {keyId, operation: {invocationTarget}});
    should.exist(result);
    result.should.be.an('object');
    result.should.have.property('id');
    result.id.should.be.a('string');
  });
});
