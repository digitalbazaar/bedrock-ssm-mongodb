/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const base64url = require('base64url-universal');
const brSSM = require('bedrock-ssm-mongodb');
const {util: {uuid}} = require('bedrock');
const {CryptoLD} = require('crypto-ld');
const {Ed25519VerificationKey2020} = require(
  '@digitalbazaar/ed25519-verification-key-2020');
const {Ed25519VerificationKey2018} = require(
  '@digitalbazaar/ed25519-verification-key-2018');

const cryptoLd = new CryptoLD();

cryptoLd.use(Ed25519VerificationKey2020);
cryptoLd.use(Ed25519VerificationKey2018);
describe('asymmetric keys', () => {
  describe('Ed25519VerificationKey2018', () => {
    describe('generateKey API', () => {
      it('successfully generates a key pair', async () => {
        // uuid will be generated at the bedrock-kms-http layer
        const keyId = `https://example.com/kms/${uuid()}`;
        const controller = 'https://example.com/i/foo';
        const type = 'Ed25519VerificationKey2018';
        const invocationTarget = {id: keyId, type, controller};
        const result = await brSSM.generateKey(
          {keyId, operation: {invocationTarget}});
        should.exist(result);
        result.should.be.an('object');
        result.should.have.keys(['id', 'publicKeyBase58', 'type']);
        result.id.should.equal(keyId);
        result.type.should.equal(type);
      });
    }); // end generateKey API

    describe('sign API', () => {
      it('successfully signs data', async () => {
        const keyId = `https://example.com/kms/${uuid()}`;
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
        Object.keys(signResult).should.have.same.members(['signatureValue']);
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
  }); // end Ed25519VerificationKey2018
  describe('Ed25519VerificationKey2020', () => {
    describe('generateKey API', () => {
      it('successfully generates a key pair', async () => {
        // uuid will be generated at the bedrock-kms-http layer
        const keyId = `https://example.com/kms/${uuid()}`;
        const controller = 'https://example.com/i/foo';
        const type = 'Ed25519VerificationKey2020';
        const invocationTarget = {id: keyId, type, controller};
        const result = await brSSM.generateKey(
          {keyId, operation: {invocationTarget}});
        should.exist(result);
        result.should.be.an('object');
        result.should.have.keys(['id', 'publicKeyMultibase', 'type']);
        result.id.should.equal(keyId);
        result.type.should.equal(type);
      });
    }); // end generateKey API

    describe('sign API', () => {
      it('successfully signs data', async () => {
        const keyId = `https://example.com/kms/${uuid()}`;
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
        Object.keys(signResult).should.have.same.members(['signatureValue']);
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
});
