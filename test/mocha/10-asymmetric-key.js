/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const base64url = require('base64url-universal');
const {util: {uuid}} = require('bedrock');
const brSSM = require('bedrock-ssm-mongodb');
const {CryptoLD} = require('crypto-ld');
const {Ed25519VerificationKey2020} = require(
  '@digitalbazaar/ed25519-verification-key-2020');
const {Ed25519VerificationKey2018} = require(
  '@digitalbazaar/ed25519-verification-key-2018');
const {generateId} = require('bnid');

const cryptoLd = new CryptoLD();

cryptoLd.use(Ed25519VerificationKey2020);
cryptoLd.use(Ed25519VerificationKey2018);
describe('asymmetric keys', () => {
  describe('Ed25519VerificationKey2018', () => {
    let keyId;
    before(async () => {
      keyId = `https://example.com/kms/${await generateId()}`;
    });
    describe('generateKey API', () => {
      it('successfully generates a key pair', async () => {
        // keyId will be generated at the bedrock-kms-http layer
        const controller = 'https://example.com/i/foo';
        const type = 'Ed25519VerificationKey2018';
        const invocationTarget = {id: keyId, type, controller};
        const result = await brSSM.generateKey(
          {keyId, operation: {invocationTarget}});
        should.exist(result);
        result.should.be.an('object');
        result.should.have.keys(['@context', 'id', 'publicKeyBase58', 'type']);
        result.id.should.equal(keyId);
        result.type.should.equal(type);
      });
      it('throws a DuplicateError when generating the same key twice',
        async () => {
          // keyId will be generated at the bedrock-kms-http layer
          const keyId = `https://example.com/kms/${await generateId()}`;
          const controller = 'https://example.com/i/foo';
          const type = 'Ed25519VerificationKey2018';
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
    }); // end generateKey API

    describe('sign API', () => {
      it('successfully signs data', async () => {
        // keyId will be generated at the bedrock-kms-http layer
        const keyId = `https://example.com/kms/${await generateId()}`;
        const controller = 'https://example.com/i/foo';
        const type = 'Ed25519VerificationKey2018';
        const invocationTarget = {id: keyId, type, controller};
        const plaintextBuffer = Buffer.from(uuid(), 'utf8');
        const verifyData = base64url.encode(plaintextBuffer);
        const publicKey = await brSSM.generateKey(
          {keyId, operation: {invocationTarget}});

        const signResult = await brSSM.sign(
          {keyId, operation: {invocationTarget, verifyData}});

        should.exist(signResult);
        signResult.should.be.an('object');
        signResult.should.have.keys(['signatureValue']);
        const {signatureValue} = signResult;
        signatureValue.should.be.a('string');

        const keyPair = await cryptoLd.from(publicKey);
        const {verify} = keyPair.verifier();
        const valid = await verify({
          data: plaintextBuffer,
          signature: base64url.decode(signatureValue)
        });

        valid.should.be.a('boolean');
        valid.should.be.true;
      });
    }); // end sign API

    describe('wrapKey API', () => {
      it('throws an Error when trying to wrap a key',
        async () => {
          const unwrappedKey = '8vEgpnq8F6QVRmaSYPHTKKZyCXMOgRLiBdZPcfYnIfI';

          let result;
          let err;
          try {
            result = await brSSM.wrapKey(
              {keyId, operation: {unwrappedKey}});
          } catch(e) {
            err = e;
          }

          should.exist(err);
          should.not.exist(result);
          err.name.should.equal('Error');
        });
    });

    describe('unwrapKey API', () => {
      it('throws an Error when trying to unwrap a key',
        async () => {
          const wrappedKey = '8vEgpnq8F6QVRmaSYPHTKKZyCXMOgRLiBdZPcfYnIfI';

          let result;
          let err;
          try {
            result = await brSSM.unwrapKey(
              {keyId, operation: {wrappedKey}});
          } catch(e) {
            err = e;
          }

          should.exist(err);
          should.not.exist(result);
          err.name.should.equal('Error');
        });
    });

    describe('verify API', () => {
      it('throws an Error when trying to verify',
        async () => {
          const plaintextBuffer = Buffer.from(uuid(), 'utf8');
          const verifyData = base64url.encode(plaintextBuffer);
          const operation = {
            verifyData
          };
          const result = await brSSM.sign({keyId, operation});
          const {signatureValue} = result;

          let result2;
          let err;
          try {
            result2 = await brSSM.verify(
              {keyId, operation: {signatureValue, verifyData}});
          } catch(e) {
            err = e;
          }

          should.exist(err);
          should.not.exist(result2);
          err.name.should.equal('Error');
        });
    });

    describe('deriveSecret API', () => {
      it('throws an Error when trying to derive a secret', async () => {
        const keyId = `https://example.com/kms/${await generateId()}`;
        const controller = 'https://example.com/i/foo';
        const type = 'Ed25519VerificationKey2018';
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
      it('throws an Error if public and key type do not match inside ' +
      '_keyAgreementKey.deriveSecret() helper function', async () => {
        const key = {
          type: 'typeA'
        };
        const publicKey = {
          type: 'typeB'
        };

        let result;
        let err;
        try {
          result = await brSSM._helpers._keyAgreementKey.deriveSecret(
            {key, operation: {publicKey}});
        } catch(e) {
          err = e;
        }

        should.exist(err);
        should.not.exist(result);
        err.name.should.equal('Error');
      });
    });

    describe('generateKeyPair API', () => {
      it('throws an Error if invalid type is used inside ' +
      '_keyAgreementKey.generateKeyPair() helper function', async () => {
        const type = 'invalid';

        let result;
        let err;
        try {
          result = await brSSM._helpers._keyAgreementKey.generateKeyPair(
            {keyId, type});
        } catch(e) {
          err = e;
        }

        should.exist(err);
        should.not.exist(result);
        err.name.should.equal('Error');
      });
    });
  }); // end Ed25519VerificationKey2018
  describe('Ed25519VerificationKey2020', () => {
    describe('generateKey API', () => {
      it('successfully generates a key pair', async () => {
        // keyId will be generated at the bedrock-kms-http layer
        const keyId = `https://example.com/kms/${await generateId()}`;
        const controller = 'https://example.com/i/foo';
        const type = 'Ed25519VerificationKey2020';
        const invocationTarget = {id: keyId, type, controller};
        const result = await brSSM.generateKey(
          {keyId, operation: {invocationTarget}});
        should.exist(result);
        result.should.be.an('object');
        result.should.have.keys([
          '@context', 'id', 'publicKeyMultibase', 'type']);
        result.id.should.equal(keyId);
        result.type.should.equal(type);
      });
    }); // end generateKey API

    describe('sign API', () => {
      it('successfully signs data', async () => {
        // keyId will be generated at the bedrock-kms-http layer
        const keyId = `https://example.com/kms/${await generateId()}`;
        const controller = 'https://example.com/i/foo';
        const type = 'Ed25519VerificationKey2020';
        const invocationTarget = {id: keyId, type, controller};
        const plaintextBuffer = Buffer.from(uuid(), 'utf8');
        const verifyData = base64url.encode(plaintextBuffer);
        const publicKey = await brSSM.generateKey(
          {keyId, operation: {invocationTarget}});

        const signResult = await brSSM.sign(
          {keyId, operation: {invocationTarget, verifyData}});

        should.exist(signResult);
        signResult.should.be.an('object');
        signResult.should.have.keys(['signatureValue']);
        const {signatureValue} = signResult;
        signatureValue.should.be.a('string');

        const keyPair = await cryptoLd.from(publicKey);
        const {verify} = keyPair.verifier();
        const valid = await verify({
          data: plaintextBuffer,
          signature: base64url.decode(signatureValue)
        });

        valid.should.be.a('boolean');
        valid.should.be.true;
      });
    }); // end sign API
  }); // end Ed25519VerificationKey2020

  describe('X25519KeyAgreementKey2020', () => {
    let keyId;
    before(async () => {
      keyId = `https://example.com/kms/${await generateId()}`;
    });
    describe('generateKey API', () => {
      it('successfully generates a key pair', async () => {
        // uuid will be generated at the bedrock-kms-http layer
        const controller = 'https://example.com/i/foo';
        const type = 'X25519KeyAgreementKey2020';
        const invocationTarget = {id: keyId, type, controller};
        const result = await brSSM.generateKey(
          {keyId, operation: {invocationTarget}});
        should.exist(result);

        result.should.be.an('object');
        result.should.have.keys([
          '@context', 'id', 'publicKeyMultibase', 'type']);
        result.id.should.equal(keyId);
        result.type.should.equal(type);
      });
      it('throws a DuplicateError when generating the same key twice',
        async () => {
          // keyId will be generated at the bedrock-kms-http layer
          const keyId = `https://example.com/kms/${await generateId()}`;
          const controller = 'https://example.com/i/foo';
          const type = 'X25519KeyAgreementKey2020';
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
    }); // end generateKey API

    describe('deriveSecret API', () => {
      it('successfully derives secret from public key', async () => {
        const keyId = `https://example.com/kms/${await generateId()}`;
        const controller = 'https://example.com/i/foo';
        const type = 'X25519KeyAgreementKey2020';
        const invocationTarget = {id: keyId, type, controller};
        const publicKey = await brSSM.generateKey(
          {keyId, operation: {invocationTarget}});

        const result = await brSSM.deriveSecret(
          {keyId, operation: {invocationTarget, publicKey}});

        should.exist(result);
        result.should.be.an('object');
        result.should.have.keys(['secret']);
        const {secret} = result;
        secret.should.be.a('string');
      });
    }); // end sign API

    describe('getKeyDescription API', () => {
      it('returns a key description for keyId with publicKeyMultibase',
        async () => {
          const keyId = `https://example.com/kms/${await generateId()}`;
          const controller = 'https://example.com/i/foo';
          const type = 'X25519KeyAgreementKey2020';
          const invocationTarget = {id: keyId, type, controller};
          await brSSM.generateKey(
            {keyId, operation: {invocationTarget}});

          const result = await brSSM.getKeyDescription({keyId});
          result.should.be.an('object');
          result.should.have.property('id', keyId);
          result.should.have.property('type', 'X25519KeyAgreementKey2020');
          result.should.have.property('@context');
          result['@context'].should.equal(
            'https://w3id.org/security/suites/x25519-2020/v1');
          result.should.have.property('publicKeyMultibase');
        });
    });

    describe('wrapKey API', () => {
      it('throws an Error when trying to wrap a key',
        async () => {
          const unwrappedKey = '8vEgpnq8F6QVRmaSYPHTKKZyCXMOgRLiBdZPcfYnIfI';

          let result;
          let err;
          try {
            result = await brSSM.wrapKey(
              {keyId, operation: {unwrappedKey}});
          } catch(e) {
            err = e;
          }

          should.exist(err);
          should.not.exist(result);
          err.name.should.equal('Error');
        });
    });
    describe('unwrapKey API', () => {
      it('throws an Error when trying to unwrap a key',
        async () => {
          const wrappedKey = '8vEgpnq8F6QVRmaSYPHTKKZyCXMOgRLiBdZPcfYnIfI';

          let result;
          let err;
          try {
            result = await brSSM.unwrapKey(
              {keyId, operation: {wrappedKey}});
          } catch(e) {
            err = e;
          }

          should.exist(err);
          should.not.exist(result);
          err.name.should.equal('Error');
        });
    });
    describe('sign API', () => {
      it('throws an Error when trying to sign', async () => {
        const keyId = `https://example.com/kms/${await generateId()}`;
        const controller = 'https://example.com/i/foo';
        const type = 'X25519KeyAgreementKey2020';
        const invocationTarget = {id: keyId, type, controller};
        const result = await brSSM.generateKey(
          {keyId, operation: {invocationTarget}});
        should.exist(result);
        const plaintextBuffer = Buffer.from(uuid(), 'utf8');
        const verifyData = base64url.encode(plaintextBuffer);

        let signResult;
        let err;
        try {
          signResult = await brSSM.sign(
            {keyId, operation: {invocationTarget, verifyData}});
        } catch(e) {
          err = e;
        }

        should.exist(err);
        should.not.exist(signResult);
        err.name.should.equal('Error');
      });
    }); // end sign API

    describe('verify API', () => {
      it('throws an Error when trying to verify',
        async () => {
          const plaintextBuffer = Buffer.from(uuid(), 'utf8');
          const verifyData = base64url.encode(plaintextBuffer);
          const signatureValue = 'test';

          let result;
          let err;
          try {
            result = await brSSM.verify(
              {keyId, operation: {signatureValue, verifyData}});
          } catch(e) {
            err = e;
          }

          should.exist(err);
          should.not.exist(result);
          err.name.should.equal('Error');
        });
    });
  });
});
