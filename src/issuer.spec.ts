import { readFileSync } from 'fs';
import { expect } from 'chai';
import 'mocha';

import { createIssuer } from './issuer';
import { getProofProperty } from './signatures';

const identifer = 'did:web:digitalcredentials.github.io#z6MkrXSQTybtqyMasfSxeRBJxDvDUGqb7mt9fFVXkVn6xTG7';
const controller = 'did:web:digitalcredentials.github.io';
const challenge = '123';
const presentationId = '456'
const simpleCredential = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1"
  ],
  "id": "http://example.gov/credentials/3732",
  "type": [
    "VerifiableCredential"
  ],
  "issuer": "did:web:digitalcredentials.github.io",
  "issuanceDate": "2020-03-10T04:24:12.164Z",
  "credentialSubject": {
    "id": "did:example:abcdef"
  }
};

const dccCredential =
{
  '@context': [
    "https://www.w3.org/2018/credentials/v1",
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

const unlockedDidDocument = JSON.parse(readFileSync("data/unlocked-did:web:digitalcredentials.github.io.json").toString("ascii"));
const issuer = createIssuer([unlockedDidDocument], identifer);

describe('Issuer test',
  () => {
    it('should create key', async () => {
      const result = await issuer.createKey(identifer);
      expect(result.id).to.equal(identifer);
      expect(result.type).to.equal('Ed25519VerificationKey2020');
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

    it('should sign presentation', async () => {
      const options = {
        'verificationMethod': identifer,
        'challenge': challenge
      };
      const result: any = await issuer.createAndSignPresentation(null, presentationId, controller, options);
      const vmResult = getProofProperty(result.proof, 'verificationMethod');
      expect(vmResult).to.equal(identifer);
    }).slow(5000).timeout(10000);
  });
