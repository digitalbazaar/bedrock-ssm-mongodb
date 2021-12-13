/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const brSSM = require('bedrock-ssm-mongodb');
const {util: {uuid}} = require('bedrock');
const {generateId} = require('bnid');
const helpers = require('./helpers.js');

describe('symmetric keys', () => {
  describe('AesKeyWrappingKey2019', async () => {
    let keyId;
    before(async () => {
      keyId = `https://example.com/kms/${await generateId()}`;
    });
    describe('generateKey API', () => {
      it('returns a key id for type AesKeyWrappingKey2019', async () => {
        // keyId will be generated at the bedrock-kms-http layer
        const controller = 'https://example.com/i/foo';
        const type = 'AesKeyWrappingKey2019';
        const invocationTarget = {id: keyId, type, controller};
        const result = await brSSM.generateKey(
          {keyId, operation: {invocationTarget}});
        should.exist(result);

        result.should.be.an('object');
        result.should.have.property('id', keyId);
        result.should.have.property('type', type);
        result.should.have.property('@context');
        result['@context'].should.eql([
          'https://w3id.org/webkms/v1',
          'https://w3id.org/security/suites/aes-2019/v1'
        ]);
      });
      it('throws a DuplicateError when generating the same key twice',
        async () => {
          // keyId will be generated at the bedrock-kms-http layer
          const keyId = `https://example.com/kms/${await generateId()}`;
          const controller = 'https://example.com/i/foo';
          const type = 'AesKeyWrappingKey2019';
          const invocationTarget = {id: keyId, type, controller};
          await brSSM.generateKey(
            {keyId, operation: {invocationTarget}});

          let result;
          let err;
          try {
            result = await brSSM.generateKey(
              {keyId, operation: {invocationTarget}});
            should.exist(result);
          } catch(e) {
            err = e;
          }

          should.exist(err);
          should.not.exist(result);
          err.name.should.equal('DuplicateError');
        });
      it('throws an Error if invalid type is used', async () => {
        // keyId will be generated at the bedrock-kms-http layer
        const controller = 'https://example.com/i/foo';
        const type = 'invalid';
        const invocationTarget = {id: keyId, type, controller};

        let result;
        let err;
        try {
          result = await brSSM.generateKey(
            {keyId, operation: {invocationTarget}});
        } catch(e) {
          err = e;
        }
        should.exist(err);
        should.not.exist(result);
        err.name.should.equal('Error');
      });
      it('throws an Error if invalid type is used inside ' +
        '_symmetricKey.generateKey() helper function', async () => {
        const controller = 'https://example.com/i/foo';
        const type = 'invalid';
        const invocationTarget = {id: keyId, type, controller};

        let result;
        let err;
        try {
          result = await brSSM._helpers._symmetricKey.generateKey(
            {keyId, operation: {invocationTarget}});
        } catch(e) {
          err = e;
        }
        should.exist(err);
        should.not.exist(result);
        err.name.should.equal('Error');
      });
    });
    describe('getKeyCount API', () => {
      it('returns a count of the number of keys for keystoreId',
        async () => {
          const keystoreId = helpers.getKeystoreId({id: keyId});
          const result = await brSSM.getKeyCount({keystoreId});
          result.should.be.an('object');
          result.should.have.property('count');
          result.count.should.equal(2);
        });
    });
    describe('verify API', () => {
      it('throws an Error if invalid type is used inside ' +
      '_symmetricKey.verify() helper function', async () => {
        const key = {
          type: 'invalid'
        };
        const operation = {
          verifyData: '2eb221b8-1777-417a-8f3a-05cdd030de12',
        };

        let result;
        let err;
        try {
          result = await brSSM._helpers._symmetricKey.verify({key, operation});
        } catch(e) {
          err = e;
        }

        should.exist(err);
        should.not.exist(result);
        err.name.should.equal('Error');
      });
    });
    describe('wrapKey API', () => {
      it('returns a wrapped cryptographic key',
        async () => {
          const unwrappedKey = '8vEgpnq8F6QVRmaSYPHTKKZyCXMOgRLiBdZPcfYnIfI';
          const result = await brSSM.wrapKey(
            {keyId, operation: {unwrappedKey}});

          result.should.be.an('object');
          result.should.have.property('wrappedKey');
        });
    });
    describe('unwrapKey API', () => {
      it('returns an unwrapped cryptographic key',
        async () => {
          const unwrappedKey = '8vEgpnq8F6QVRmaSYPHTKKZyCXMOgRLiBdZPcfYnIfI';
          const result = await brSSM.wrapKey(
            {keyId, operation: {unwrappedKey}});

          const wrappedKey = result.wrappedKey;
          const result2 = await brSSM.unwrapKey(
            {keyId, operation: {wrappedKey}});

          result2.should.be.an('object');
          result2.should.have.property('unwrappedKey');
          result2.unwrappedKey.should
            .equal('8vEgpnq8F6QVRmaSYPHTKKZyCXMOgRLiBdZPcfYnIfI');
        });
    });
    describe('deriveSecret API', () => {
      it('throws an Error when trying to derive a secret', async () => {
        const keyId = `https://example.com/kms/${await generateId()}`;
        const controller = 'https://example.com/i/foo';
        const type = 'AesKeyWrappingKey2019';
        const invocationTarget = {id: keyId, type, controller};
        await brSSM.generateKey(
          {keyId, operation: {invocationTarget}});

        let result;
        let err;
        try {
          result = await brSSM.deriveSecret(
            {keyId, operation: {invocationTarget}});
        } catch(e) {
          err = e;
        }

        should.exist(err);
        should.not.exist(result);
        err.name.should.equal('Error');
      });
    });
  });

  describe('Sha256HmacKey2019', () => {
    let keyId;
    before(async () => {
      keyId = `https://example.com/kms/${await generateId()}`;
    });
    describe('generateKey API', () => {
      it('returns a key id for type Sha256HmacKey2019', async () => {
        // keyId will be generated at the bedrock-kms-http layer
        const controller = 'https://example.com/i/foo';
        const type = 'Sha256HmacKey2019';
        const invocationTarget = {id: keyId, type, controller};
        const result = await brSSM.generateKey(
          {keyId, operation: {invocationTarget}});
        should.exist(result);
        result.should.be.an('object');
        result.should.have.property('id', keyId);
        result.should.have.property('type', type);
        result.should.have.property('@context');
        result['@context'].should.eql([
          'https://w3id.org/webkms/v1',
          'https://w3id.org/security/suites/hmac-2019/v1'
        ]);
      });
    }); // end generateKey API

    describe('sign API', () => {
      let keyId;
      before(async () => {
        // keyId will be generated at the bedrock-kms-http layer
        keyId = `https://example.com/kms/${await generateId()}`;
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
            // uuids are 37 chars long, * 30 is ~1KiB
            let v = '';
            for(let n = 0; n < 30; ++n) {
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

      it('throws an Error if invalid type is used inside ' +
      '_symmetricKey.sign() helper function', async () => {
        const key = {
          type: 'invalid'
        };
        const operation = {
          verifyData: '2eb221b8-1777-417a-8f3a-05cdd030de12',
        };

        let result;
        let err;
        try {
          result = await brSSM._helpers._symmetricKey.sign({key, operation});
        } catch(e) {
          err = e;
        }

        should.exist(err);
        should.not.exist(result);
        err.name.should.equal('Error');
      });

    }); // end sign API

    describe('verify API', () => {
      it('properly verifies data',
        async () => {
          const verifyData = '2eb221b8-1777-417a-8f3a-05cdd030de12';
          const operation = {
            verifyData
          };
          const result = await brSSM.sign({keyId, operation});
          const {signatureValue} = result;

          const result2 = await brSSM.verify(
            {keyId, operation: {signatureValue, verifyData}});

          result2.should.be.an('object');
          result2.should.have.property('verified');
          result2.verified.should.equal(true);
        });
    });

    describe('wrapKey API', () => {
      it('throws an Error if invalid type is used inside ' +
      '_symmetricKey.wrapKey() helper function', async () => {
        const kek = {
          type: 'invalid'
        };
        const unwrappedKey = '8vEgpnq8F6QVRmaSYPHTKKZyCXMOgRLiBdZPcfYnIfI';

        let result;
        let err;
        try {
          result = await brSSM._helpers._symmetricKey.wrapKey(
            {kek, operation: {unwrappedKey}});
        } catch(e) {
          err = e;
        }

        should.exist(err);
        should.not.exist(result);
        err.name.should.equal('Error');
      });
    });

    describe('unwrapKey API', () => {
      it('throws an Error if invalid type is used inside ' +
      '_symmetricKey.unwrapKey() helper function', async () => {
        const kek = {
          type: 'invalid'
        };
        const wrappedKey = '8vEgpnq8F6QVRmaSYPHTKKZyCXMOgRLiBdZPcfYnIfI';

        let result;
        let err;
        try {
          result = await brSSM._helpers._symmetricKey.unwrapKey(
            {kek, operation: {wrappedKey}});
        } catch(e) {
          err = e;
        }

        should.exist(err);
        should.not.exist(result);
        err.name.should.equal('Error');
      });
    });
  }); // end Sha256HmacKey2019
});
