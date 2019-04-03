/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const brSSM = require('bedrock-ssm-mongodb');
const {util: {uuid}} = require('bedrock');

describe('asymmetric keys', () => {
  it('successfully generates a Ed25519VerificationKey2018', async () => {
    // uuid will be generated at the bedrock-kms-http layer
    const keyId = `https://example.com/ksm/ssm-v1/${uuid()}`;
    const controller = 'https://example.com/i/foo';
    const type = 'Ed25519VerificationKey2018';
    const invocationTarget = {id: keyId, type, controller};
    const result = await brSSM.generateKey(
      {keyId, operation: {invocationTarget}});
    should.exist(result);
    result.should.be.an('object');
    Object.keys(result).should.have.same.members(
      ['id', 'publicKeyBase58', 'type']);
    result.id.should.equal(keyId);
    result.type.should.equal(type);
  });
});
