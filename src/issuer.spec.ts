
import { readFileSync } from 'fs';
import { expect } from 'chai';
import 'mocha';
import crypto from "crypto";
const didKeyDriver = require('@digitalbazaar/did-method-key').driver();
const vc = require('@digitalbazaar/vc');
const ed25519 = require('@digitalbazaar/ed25519-signature-2020');
const ed25519Verification = require('@digitalbazaar/ed25519-verification-key-2020');

import { createIssuer, getController } from './issuer';
import { getProofProperty } from './signatures';

const identifer = 'did:web:digitalcredentials.github.io#96K4BSIWAkhcclKssb8yTWMQSz4QzPWBy-JsAFlwoIs';
const controller = 'did:web:digitalcredentials.github.io';
const challenge = '123';
const presentationId = '456'
const simpleCredential = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1",
    "https://w3id.org/security/jws/v1"
  ],
  "id": "http://example.gov/credentials/3732",
  "type": [
    "VerifiableCredential",
    "UniversityDegreeCredential"
  ],
  "issuer": "did:web:digitalcredentials.github.io",
  "issuanceDate": "2020-03-10T04:24:12.164Z",
  "credentialSubject": {
    "id": "did:example:abcdef",
    "degree": {
      "type": "BachelorDegree",
      "name": "Bachelor of Science and Arts"
    }
  }
};

const dccCredential =
{
  '@context': [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1",
    "https://w3id.org/security/jws/v1",
    "https://w3id.org/dcc/v1"
  ],
  'id': 'https://digitalcredentials.github.io/samples/certificate/1fe91f0f-4c64-48c8-bfc8-7132f75776fe/',
  'type': ['VerifiableCredential', 'LearningCredential'],
  'issuer': {
    'type': 'Issuer',
    'id': 'did:web:digitalcredentials.github.io',
    'name': 'Sample Issuer',
    'url': 'https://digitalcredentials.github.io/samples/'
  },
  'issuanceDate': '2021-01-19T18:22:34.772810+00:00',
  'credentialSubject': {
    'type': 'Person',
    'id': 'did:example:456',
    'name': 'Percy',

    'hasCredential': {
      'type': ['EducationalOccupationalCredential', 'ProgramCompletionCredential'],
      'name': 'DCC Sample Program Completion Credential',
      'description': '<p>Learn stuff about requesting a DCC credential.</p>',

      'awardedOnCompletionOf': {
        'type': 'EducationalOccupationalProgram',
        'identifier': 'program-v1:Sample',
        'name': 'Successful completion of sample request program',
        'description': '<p>Learn stuff about DCC credential issuance</p>',
        'numberOfCredits': { 'value': '1' },
        'startDate': '',
        'endDate': ''
      }
    }
  }
}

const verifiablePresentation = 
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1",
    "https://w3id.org/security/jws/v1"
  ],
  "type": [
    "VerifiablePresentation"
  ],
  "id": "456",
  "holder": "did:web:digitalcredentials.github.io",
  "proof": {
    "type": "JsonWebSignature2020",
    "created": "2020-11-12T22:00:33.393Z",
    "challenge": "123",
    "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..nuQE1vdLcf0YJSI_ojCdOpkQ53Amf4admAfA1eds9ONz9iskp5NBHqoz_YpzyRPxRvj4zblDDAhR524Dn4BtBA",
    "proofPurpose": "authentication",
    "verificationMethod": "did:web:digitalcredentials.github.io#96K4BSIWAkhcclKssb8yTWMQSz4QzPWBy-JsAFlwoIs"
  }
};

const verifiablePresentationDidKey = 
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/security/jws/v1"
  ],
  "type": [
    "VerifiablePresentation"
  ],
  "id": "123",
  "holder": "did:key:z6Mks47FaLKufWC8Uu4djvsUm2pZ9ADVzBscy4S6k63PsaH7",
  "proof": {
    "type": "Ed25519Signature2018",
    "created": "2021-04-27T00:53:01.793Z",
    "challenge": "c71f0a0d-0ff5-480d-bf95-a11bf62f2e04",
    "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..-gUUtRlt4ltJQ5ZWpTPEE4mw3RkauIND9rpJInRS7yyq7UP0UrzPew7ZLktbw3ExtbTO-kjXn4n9X0ZvnVCvBA",
    "proofPurpose": "authentication",
    "verificationMethod": "#z6Mks47FaLKufWC8Uu4djvsUm2pZ9ADVzBscy4S6k63PsaH7"
  }
};


const unlockedDidDocument = JSON.parse(readFileSync("data/unlocked-did:web:digitalcredentials.github.io.json").toString("ascii"));
const issuer = createIssuer(unlockedDidDocument)

describe('Issuer test',
  () => {
    it('should parse controller', () => {
      const result = getController(identifer);
      expect(result).to.equal(controller);
    });

    it('should create JsonKeyKey', () => {
      const result = issuer.createJwk(identifer);
      expect(result.id).to.equal(identifer);
      expect(result.type).to.equal('JsonWebKey2020');
      expect(result.controller).to.equal(controller);
    });

    it('should sign', async () => {
      const options = {
        'verificationMethod': identifer
      };
      const result = await issuer.sign(simpleCredential, options);
      expect(result.issuer).to.equal(controller);
    }).slow(5000).timeout(10000);

    it('should sign with DCC context', async () => {
      const options = {
        'verificationMethod': identifer
      };
      const result = await issuer.sign(dccCredential, options);
      expect(result.issuer.id).to.equal(controller);
    }).slow(5000).timeout(10000);

    it('should verify', async () => {
      const options = {
        'verificationMethod': identifer
      };

      const temp = await issuer.sign(simpleCredential, options);
      const verificationResult = await issuer.verify(temp, options);
      expect(verificationResult.verified).to.equal(true);
    }).slow(5000).timeout(10000);

    it('should verify with DCC context', async () => {
      const options = {
        'verificationMethod': identifer
      };

      const temp = await issuer.sign(dccCredential, options);
      const verificationResult = await issuer.verify(temp, options);
      expect(verificationResult.verified).to.equal(true);
    }).slow(5000).timeout(10000);


    it('should sign presentation', async () => {
      const options = {
        'verificationMethod': identifer,
        'challenge': challenge
      };
      const result: any = await issuer.createAndSignPresentation(null, presentationId, controller, options);
      const vmResult = getProofProperty(result.proof, 'verificationMethod');
      expect(vmResult).to.equal(identifer);
    }).slow(5000).timeout(10000);


    it('should verify presentation', async () => {
      const options = {
        'verificationMethod': identifer,
        'challenge': challenge
      };
      const verificationResult = await issuer.verifyPresentation(verifiablePresentation, options);
      expect(verificationResult.verified).to.equal(true);
    }).slow(5000).timeout(10000);

    it("should get demo credential", async () => {
      const options = {
        'verificationMethod': identifer,
        'challenge': challenge
      };
      const credential = await issuer.requestDemoCredential(verifiablePresentation);
      expect(credential.credentialSubject.id).to.equal("did:web:digitalcredentials.github.io");
    }).slow(5000).timeout(10000);

    it("should get demo credential without verification", async () => {
      const request = {
        holder: "did:example:me"
      };

      const credential = await issuer.requestDemoCredential(request, true);
      expect(credential.credentialSubject.id).to.equal("did:example:me");
    }).slow(5000).timeout(10000);

    it('should verify presentation signed with did:key', async () => {

      const { didKeyDocument, keyPairs, methodFor } = await didKeyDriver.generate();
      const kp = keyPairs.entries().next().value;
      const k = kp[0];
      const v = kp[1];
      console.log(k);
      

      const challenge = 'test123';
      const signingSuite = new ed25519.Ed25519Signature2020({key: v});
      console.log(JSON.stringify(signingSuite, null, 2));

      //ed25519Key.id = ed25519Key.controller + ed25519Key.id;

      const testPres = {
        '@context': [
          'https://www.w3.org/2018/credentials/v1',
         'https://w3id.org/security/jws/v1',
         //'https://www.w3.org/ns/did/v1'
        // 'https://w3id.org/security/v1'
        ],
        type: ['VerifiablePresentation'],
        id: '123',
        holder: keyPairs.controller,
      };

      const signedPresentation = await vc.signPresentation({
        presentation: testPres,
        documentLoader: issuer.customLoader,
        suite: signingSuite,
        challenge: challenge,
      });
      //https://www.w3.org/ns/did/v1
      //https://w3id.org/did/v1
      //signedPresentation['@context'].push('https://www.w3.org/ns/did/v1');

      console.log(JSON.stringify(signedPresentation));

      const proofVm = signedPresentation.proof.verificationMethod;

      /*
      const didDocument = await didKeyDriver.get(
        proofVm
      );

      console.log(JSON.stringify(didDocument));
      const vm = didDocument.didDocument.verificationMethod[0];
      
      const verifySuite = new ed25519.Ed25519Signature2020({
        key: vm,
      });

      console.log(JSON.stringify(verifySuite));

      const verified = await vc.verify({
        presentation: signedPresentation,
        documentLoader: issuer.customLoader,
        suite: verifySuite,
        challenge: challenge,
      });
      console.log(JSON.stringify(verified));*/

    }).slow(5000).timeout(10000);

  });
