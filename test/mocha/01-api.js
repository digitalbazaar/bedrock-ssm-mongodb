/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const brSSM = require('bedrock-ssm-mongodb');

describe('generateKey API', () => {
  it('returns a key id for type HS256', async () => {
    const controller = 'https://example.com/i/foo';
    const type = 'HS256';
    const result = await brSSM.generateKey({controller, type});
    should.exist(result);
    result.should.be.an('object');
    result.should.have.property('id');
    result.id.should.be.a('string');
  });
  it('returns a key id for type AES-KW', async () => {
    const controller = 'https://example.com/i/foo';
    const type = 'AES-KW';
    const result = await brSSM.generateKey({controller, type});
    should.exist(result);
    result.should.be.an('object');
    result.should.have.property('id');
    result.id.should.be.a('string');
  });
});
