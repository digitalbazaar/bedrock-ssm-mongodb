/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const brSSM = require('bedrock-ssm-mongodb');
const {util: {uuid}} = require('bedrock');

describe('AesKeyWrappingKey2019', () => {
  describe('generateKey API', () => {
    it('returns a key id for type AesKeyWrappingKey2019', async () => {
      const keyId = 'https://example.com/kms/my-kek';
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
  }); // end generateKey API

  describe('Sha256HmacKey2019', () => {
    describe('generateKey API', () => {
      it('returns a key id for type Sha256HmacKey2019', async () => {
        const keyId = 'https://example.com/kms/my-hmac-key';
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
    }); // end generateKey API

    describe('sign API', () => {
      const keyId =
        'https://example.com/kms/01d832b0-92fe-40ca-aea7-44f49c0c83c6';
      before(async () => {
        const controller = 'https://example.com/i/foo';
        const type = 'Sha256HmacKey2019';
        const invocationTarget = {id: keyId, type, controller};
        await brSSM.generateKey({keyId, operation: {invocationTarget}});
      });
      it('successfully signs data', async () => {
        const operation = {
          verifyData: '2eb221b8-1777-417a-8f3a-05cdd030de12',
        };
        let err;
        let result;
        try {
          result = await brSSM.sign({keyId, operation});
        } catch(e) {
          err = e;
        }
        assertNoError(err);
        should.exist(result);
        result.should.be.an('object');
        result.should.have.property('signatureValue');
        result.signatureValue.should.be.a('string');
        result.signatureValue.should.have.length.gt(0);
      });
      it('successfully signs data', async () => {
        const operation = {
          verifyData: '2eb221b8-1777-417a-8f3a-05cdd030de12',
        };
        let err;
        let result;
        try {
          result = await brSSM.sign({keyId, operation});
        } catch(e) {
          err = e;
        }
        assertNoError(err);
        should.exist(result);
        result.should.be.an('object');
        result.should.have.property('signatureValue');
        result.signatureValue.should.be.a('string');
        result.signatureValue.should.have.length.gt(0);
      });
      describe('bulk operations', () => {
        const operationCount = 10000;
        const vData = [];
        before(async () => {
          for(let i = 0; i < operationCount; ++i) {
            let v = '';
            for(let n = 0; n < 100; ++n) {
              v += uuid();
            }
            vData.push(v);
          }
        });
        it(`performs ${operationCount} signatures`, async function() {
          this.timeout(0);
          const promises = [];
          for(let i = 0; i < operationCount; ++i) {
            const operation = {verifyData: vData[i]};
            promises.push(brSSM.sign({keyId, operation}));
          }
          let result;
          let err;
          try {
            result = await Promise.all(promises);
          } catch(e) {
            err = e;
          }
          assertNoError(err);
          should.exist(result);
          result.should.be.an('array');
          result.should.have.length(operationCount);
        });
      }); // end bulk operations

    }); // end sign API
  }); // end Sha256HmacKey2019
});
