/*!
 * Copyright (c) 2019-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as base64url from 'base64url-universal';
import * as bls12381Multikey from '@digitalbazaar/bls12-381-multikey';
import * as brSSM from '@bedrock/ssm-mongodb';
import * as cborg from 'cborg';
import * as ecdsa from '@digitalbazaar/ecdsa-multikey';
import {
  Ed25519VerificationKey2018
} from '@digitalbazaar/ed25519-verification-key-2018';
import {
  Ed25519VerificationKey2020
} from '@digitalbazaar/ed25519-verification-key-2020';
import {generateId} from 'bnid';
import {v4 as uuid} from 'uuid';

describe('asymmetric keys', () => {
  describe('Ed25519VerificationKey2018', () => {
    describe('generateKey API', () => {
      it('should generate a key pair', async () => {
        // in a real system, `keyId` will be generated by bedrock-kms-http
        const keyId = `https://example.com/kms/${await generateId()}`;
        const controller = 'https://example.com/i/foo';
        const type = 'Ed25519VerificationKey2018';
        const invocationTarget = {id: keyId, type};
        const result = await brSSM.generateKey(
          {keyId, controller, operation: {invocationTarget}});

        should.exist(result);
        result.should.be.an('object');
        should.exist(result.keyId);
        result.keyId.should.equal(keyId);
        const {keyDescription} = result;
        keyDescription.should.have.keys(
          ['@context', 'id', 'publicKeyBase58', 'type', 'controller']);
        keyDescription.id.should.equal(keyId);
        keyDescription.type.should.equal(type);
        keyDescription.controller.should.equal(controller);
      });
      it('should generate a key pair w/public alias', async () => {
        // in a real system, `keyId` will be generated by bedrock-kms-http
        const keyId = `https://example.com/kms/${await generateId()}`;
        const controller = 'https://example.com/i/foo';
        const type = 'Ed25519VerificationKey2018';
        const invocationTarget = {id: keyId, type, publicAlias: 'urn:test'};
        const result = await brSSM.generateKey(
          {keyId, controller, operation: {invocationTarget}});

        should.exist(result);
        result.should.be.an('object');
        should.exist(result.keyId);
        result.keyId.should.equal(keyId);
        const {keyDescription} = result;
        should.exist(keyDescription);
        keyDescription.should.be.an('object');
        keyDescription.should.have.keys(
          ['@context', 'id', 'publicKeyBase58', 'type', 'controller']);
        keyDescription.id.should.equal('urn:test');
        keyDescription.type.should.equal(type);
        keyDescription.controller.should.equal(controller);
      });
      it('should generate a key pair w/public alias template', async () => {
        // in a real system, `keyId` will be generated by bedrock-kms-http
        const keyId = `https://example.com/kms/${await generateId()}`;
        const controller = 'https://example.com/i/foo';
        const type = 'Ed25519VerificationKey2018';
        const invocationTarget = {
          id: keyId, type,
          publicAliasTemplate: '{+controller}#{publicKeyBase58}'
        };
        const result = await brSSM.generateKey(
          {keyId, controller, operation: {invocationTarget}});

        should.exist(result);
        result.should.be.an('object');
        should.exist(result.keyId);
        result.keyId.should.equal(keyId);
        const {keyDescription} = result;
        should.exist(keyDescription);
        keyDescription.should.be.an('object');
        keyDescription.should.have.keys(
          ['@context', 'id', 'publicKeyBase58', 'type', 'controller']);
        const expected = `${controller}#${keyDescription.publicKeyBase58}`;
        keyDescription.id.should.equal(expected);
        keyDescription.type.should.equal(type);
        keyDescription.controller.should.equal(controller);
      });
      it('throws a DuplicateError when generating the same key twice',
        async () => {
          // in a real system, `keyId` will be generated by bedrock-kms-http
          const keyId = `https://example.com/kms/${await generateId()}`;
          const controller = 'https://example.com/i/foo';
          const type = 'Ed25519VerificationKey2018';
          const invocationTarget = {id: keyId, type};
          await brSSM.generateKey(
            {keyId, controller, operation: {invocationTarget}});

          let result;
          let err;
          try {
            result = await brSSM.generateKey(
              {keyId, controller, operation: {invocationTarget}});
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
        // in a real system, `keyId` will be generated by bedrock-kms-http
        const keyId = `https://example.com/kms/${await generateId()}`;
        const controller = 'https://example.com/i/foo';
        const type = 'Ed25519VerificationKey2018';
        const invocationTarget = {id: keyId, type};
        const plaintextBuffer = Buffer.from(uuid(), 'utf8');
        const verifyData = base64url.encode(plaintextBuffer);
        const {keyDescription: publicKey} = await brSSM.generateKey(
          {keyId, controller, operation: {invocationTarget}});

        const signResult = await brSSM.sign(
          {keyId, operation: {invocationTarget, verifyData}});

        should.exist(signResult);
        signResult.should.be.an('object');
        signResult.should.have.keys(['signatureValue']);
        const {signatureValue} = signResult;
        signatureValue.should.be.a('string');

        const keyPair = await Ed25519VerificationKey2018.from(publicKey);
        const {verify} = keyPair.verifier();
        const valid = await verify({
          data: plaintextBuffer,
          signature: base64url.decode(signatureValue)
        });

        valid.should.be.a('boolean');
        valid.should.be.true;
      });
      it('fails when "maxCapabilityChainLength" is exceeded', async () => {
        // in a real system, `keyId` will be generated by bedrock-kms-http
        const keyId = `https://example.com/kms/${await generateId()}`;
        const controller = 'https://example.com/i/foo';
        const type = 'Ed25519VerificationKey2018';
        const invocationTarget = {
          id: keyId,
          type,
          maxCapabilityChainLength: 1
        };
        const plaintextBuffer = Buffer.from(uuid(), 'utf8');
        const verifyData = base64url.encode(plaintextBuffer);
        await brSSM.generateKey({
          keyId, controller, operation: {invocationTarget}
        });

        // mock `zcapInvocation` with `dereferencedChain` that is
        // too long (entries not checked, just length)
        const zcapInvocation = {
          dereferencedChain: [{}, {}]
        };

        let result;
        let err;
        try {
          result = await brSSM.sign(
            {keyId, operation: {invocationTarget, verifyData}, zcapInvocation});
        } catch(e) {
          err = e;
        }

        should.exist(err);
        should.not.exist(result);
        err.name.should.equal('Error');
        err.message.should.equal(
          'Maximum zcap invocation capability chain length (1) exceeded.');
      });
    }); // end sign API

    describe('wrapKey API', () => {
      it('throws an Error when trying to wrap a key',
        async () => {
          // in a real system, `keyId` will be generated by bedrock-kms-http
          const keyId = `https://example.com/kms/${await generateId()}`;
          const controller = 'https://example.com/i/foo';
          const type = 'Ed25519VerificationKey2018';
          const invocationTarget = {id: keyId, type};
          await brSSM.generateKey(
            {keyId, controller, operation: {invocationTarget}});

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
          // in a real system, `keyId` will be generated by bedrock-kms-http
          const keyId = `https://example.com/kms/${await generateId()}`;
          const controller = 'https://example.com/i/foo';
          const type = 'Ed25519VerificationKey2018';
          const invocationTarget = {id: keyId, type};
          await brSSM.generateKey(
            {keyId, controller, operation: {invocationTarget}});

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
          // in a real system, `keyId` will be generated by bedrock-kms-http
          const keyId = `https://example.com/kms/${await generateId()}`;
          const controller = 'https://example.com/i/foo';
          const type = 'Ed25519VerificationKey2018';
          const invocationTarget = {id: keyId, type};
          await brSSM.generateKey(
            {keyId, controller, operation: {invocationTarget}});

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
        // in a real system, `keyId` will be generated by bedrock-kms-http
        const keyId = `https://example.com/kms/${await generateId()}`;
        const controller = 'https://example.com/i/foo';
        const type = 'Ed25519VerificationKey2018';
        const invocationTarget = {id: keyId, type};
        await brSSM.generateKey(
          {keyId, controller, operation: {invocationTarget}});

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
        // in a real system, `keyId` will be generated by bedrock-kms-http
        const keyId = `https://example.com/kms/${await generateId()}`;
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

  const signTests = [
    {type: 'Ed25519VerificationKey2020'},
    {type: 'urn:webkms:multikey:Ed25519'},
    {type: 'urn:webkms:multikey:P-256'},
    {type: 'urn:webkms:multikey:P-384'},
    {type: 'urn:webkms:multikey:P-521'},
    {type: 'urn:webkms:multikey:BBS-BLS12-381-SHA-256'},
    {type: 'urn:webkms:multikey:BBS-BLS12-381-SHAKE-256'}
  ];
  for(const {type} of signTests) {
    let expectedType;
    if(type.startsWith('urn:webkms:multikey:')) {
      expectedType = 'Multikey';
    } else {
      expectedType = type;
    }
    describe(type, () => {
      describe('generateKey API', () => {
        it('successfully generates a key pair', async () => {
          // in a real system, `keyId` will be generated by bedrock-kms-http
          const keyId = `https://example.com/kms/${await generateId()}`;
          const controller = 'https://example.com/i/foo';
          const invocationTarget = {id: keyId, type};
          const result = await brSSM.generateKey(
            {keyId, controller, operation: {invocationTarget}});

          should.exist(result);
          result.should.be.an('object');
          should.exist(result.keyId);
          result.keyId.should.equal(keyId);
          const {keyDescription} = result;
          should.exist(keyDescription);
          keyDescription.should.be.an('object');
          keyDescription.should.have.keys([
            '@context', 'id', 'publicKeyMultibase', 'type', 'controller']);
          keyDescription.id.should.equal(keyId);
          keyDescription.type.should.equal(expectedType);
        });
      }); // end generateKey API

      describe('sign API', () => {
        it('successfully signs data', async () => {
          // in a real system, `keyId` will be generated by bedrock-kms-http
          const keyId = `https://example.com/kms/${await generateId()}`;
          const controller = 'https://example.com/i/foo';
          const invocationTarget = {id: keyId, type};
          const {keyDescription: publicKey} = await brSSM.generateKey(
            {keyId, controller, operation: {invocationTarget}});

          const plaintextBuffer = Buffer.from(uuid(), 'utf8');
          let verifyData;
          if(type.startsWith('urn:webkms:multikey:BBS-')) {
            const header = new Uint8Array();
            const messages = [plaintextBuffer];
            verifyData = base64url.encode(cborg.encode([header, messages]));
          } else {
            verifyData = base64url.encode(plaintextBuffer);
          }
          const signResult = await brSSM.sign(
            {keyId, operation: {invocationTarget, verifyData}});

          should.exist(signResult);
          signResult.should.be.an('object');
          signResult.should.have.keys(['signatureValue']);
          const {signatureValue} = signResult;
          signatureValue.should.be.a('string');

          let verifier;
          if(type === 'urn:webkms:multikey:Ed25519') {
            const keyPair = await Ed25519VerificationKey2020.from({
              ...publicKey,
              '@context': 'https://w3id.org/security/suites/ed25519-2020/v1',
              type: 'Ed25519VerificationKey2020'
            });
            verifier = keyPair.verifier();
          } else if(type.startsWith('urn:webkms:multikey:P-')) {
            const keyPair = await ecdsa.from(publicKey);
            verifier = keyPair.verifier();
          } else if(type === 'Ed25519VerificationKey2020') {
            const keyPair = await Ed25519VerificationKey2020.from(publicKey);
            verifier = keyPair.verifier();
          } else if(type === 'Ed25519VerificationKey2018') {
            const keyPair = await Ed25519VerificationKey2018.from(publicKey);
            verifier = keyPair.verifier();
          } else if(type.startsWith('urn:webkms:multikey:BBS-')) {
            const keyPair = await bls12381Multikey.from(publicKey);
            verifier = keyPair.verifier();

            // do multiverify
            const presentationHeader = new Uint8Array();
            const header = new Uint8Array();
            const messages = [plaintextBuffer];
            const proof = await keyPair.deriveProof({
              signature: base64url.decode(signatureValue),
              header, messages, presentationHeader,
              disclosedMessageIndexes: [0]
            });
            const verified = await verifier.multiverify({
              proof, header, presentationHeader, messages
            });
            verified.should.be.a('boolean');
            verified.should.be.true;
            return;
          }

          const {verify} = verifier;
          const verified = await verify({
            data: plaintextBuffer,
            signature: base64url.decode(signatureValue)
          });

          verified.should.be.a('boolean');
          verified.should.be.true;
        });
      }); // end sign API
    }); // end type-specific sign test
  }

  describe('X25519KeyAgreementKey2020', () => {
    describe('generateKey API', () => {
      it('successfully generates a key pair', async () => {
        // in a real system, `keyId` will be generated by bedrock-kms-http
        const keyId = `https://example.com/kms/${await generateId()}`;
        const controller = 'https://example.com/i/foo';
        const type = 'X25519KeyAgreementKey2020';
        const invocationTarget = {id: keyId, type};
        const result = await brSSM.generateKey(
          {keyId, controller, operation: {invocationTarget}});

        should.exist(result);
        result.should.be.an('object');
        should.exist(result.keyId);
        result.keyId.should.equal(keyId);
        const {keyDescription} = result;
        should.exist(keyDescription);
        keyDescription.should.be.an('object');
        keyDescription.should.have.keys([
          '@context', 'id', 'publicKeyMultibase', 'type', 'controller']);
        keyDescription.id.should.equal(keyId);
        keyDescription.type.should.equal(type);
      });
      it('throws a DuplicateError when generating the same key twice',
        async () => {
          // in a real system, `keyId` will be generated by bedrock-kms-http
          const keyId = `https://example.com/kms/${await generateId()}`;
          const controller = 'https://example.com/i/foo';
          const type = 'X25519KeyAgreementKey2020';
          const invocationTarget = {id: keyId, type};
          await brSSM.generateKey(
            {keyId, controller, operation: {invocationTarget}});

          let result;
          let err;
          try {
            result = await brSSM.generateKey(
              {keyId, controller, operation: {invocationTarget}});
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
        // in a real system, `keyId` will be generated by bedrock-kms-http
        const keyId = `https://example.com/kms/${await generateId()}`;
        const controller = 'https://example.com/i/foo';
        const type = 'X25519KeyAgreementKey2020';
        const invocationTarget = {id: keyId, type};
        const {keyDescription: publicKey} = await brSSM.generateKey(
          {keyId, controller, operation: {invocationTarget}});

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
          // in a real system, `keyId` will be generated by bedrock-kms-http
          const keyId = `https://example.com/kms/${await generateId()}`;
          const controller = 'https://example.com/i/foo';
          const type = 'X25519KeyAgreementKey2020';
          const invocationTarget = {id: keyId, type};
          await brSSM.generateKey(
            {keyId, controller, operation: {invocationTarget}});

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
          // in a real system, `keyId` will be generated by bedrock-kms-http
          const keyId = `https://example.com/kms/${await generateId()}`;
          const controller = 'https://example.com/i/foo';
          const type = 'X25519KeyAgreementKey2020';
          const invocationTarget = {id: keyId, type};
          await brSSM.generateKey(
            {keyId, controller, operation: {invocationTarget}});

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
          // in a real system, `keyId` will be generated by bedrock-kms-http
          const keyId = `https://example.com/kms/${await generateId()}`;
          const controller = 'https://example.com/i/foo';
          const type = 'X25519KeyAgreementKey2020';
          const invocationTarget = {id: keyId, type};
          await brSSM.generateKey(
            {keyId, controller, operation: {invocationTarget}});

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
        // in a real system, `keyId` will be generated by bedrock-kms-http
        const keyId = `https://example.com/kms/${await generateId()}`;
        const controller = 'https://example.com/i/foo';
        const type = 'X25519KeyAgreementKey2020';
        const invocationTarget = {id: keyId, type};
        const result = await brSSM.generateKey(
          {keyId, controller, operation: {invocationTarget}});

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
          // in a real system, `keyId` will be generated by bedrock-kms-http
          const keyId = `https://example.com/kms/${await generateId()}`;
          const controller = 'https://example.com/i/foo';
          const type = 'X25519KeyAgreementKey2020';
          const invocationTarget = {id: keyId, type};
          await brSSM.generateKey(
            {keyId, controller, operation: {invocationTarget}});

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
