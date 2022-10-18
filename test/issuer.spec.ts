import { readFileSync } from 'fs';
import { expect } from 'chai';
import 'mocha';

import { createIssuer } from '../src/issuer';
import { getProofProperty } from '../src/signatures';

const controller = 'did:key:z6MkqanD5cmEVf154z5xExoxNKENAzVr3gdPo4wD2R2aCUzj';
const keyId = 'did:key:z6MkqanD5cmEVf154z5xExoxNKENAzVr3gdPo4wD2R2aCUzj#z6MkqanD5cmEVf154z5xExoxNKENAzVr3gdPo4wD2R2aCUzj';
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
  "issuer": controller,
  "issuanceDate": "2020-03-10T04:24:12.164Z",
  "credentialSubject": {
    "id": "did:example:abcdef"
  }
};

const dccCredential = {
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    'https://w3c-ccg.github.io/vc-ed/plugfest-1-2022/jff-vc-edu-plugfest-1-context.json'
  ],
  'type': [
    'VerifiableCredential',
    'OpenBadgeCredential'
  ],
  'issuer': {
    'type': 'Profile',
    'id': controller,
    'name': 'Jobs for the Future (JFF)',
    'url': 'https://www.jff.org/',
    'image': 'https://w3c-ccg.github.io/vc-ed/plugfest-1-2022/images/JFF_LogoLockup.png'
  },
  'issuanceDate': '2022-05-01T00:00:00Z',
  'credentialSubject': {
    'type': 'AchievementSubject',
    'achievement': {
      'type': 'Achievement',
      'name': 'Sample test credential to prep for JFF Plugfest #1 2022',
      'description': 'This wallet can display this Open Badge 3.0',
      'criteria': {
        'type': 'Criteria',
        'narrative': 'The first cohort of the JFF Plugfest 1 in May/June of 2022 collaborated to push interoperability of VCs in education forward.'
      },
      'image': 'https://w3c-ccg.github.io/vc-ed/plugfest-1-2022/images/plugfest-1-badge-image.png'
    }
  }
}

const unlockedDidDocument = JSON.parse(readFileSync("data/unlocked-did:key.json").toString("ascii"));
const issuer = createIssuer([unlockedDidDocument], controller);

describe('Issuer test',
  () => {
    it('should create key', async () => {
      const result = await issuer.createKey(keyId);
      expect(result.id).to.equal(keyId);
      expect(result.type).to.equal('Ed25519VerificationKey2020');
      expect(result.controller).to.equal(controller);
    });

    it('should sign', async () => {
      const options = {
        'verificationMethod': keyId
      };
      const result = await issuer.sign(simpleCredential, options);
      expect(result.issuer).to.equal(controller);
    }).slow(5000).timeout(10000);

    it('should sign with DCC context', async () => {
      const options = {
        'verificationMethod': keyId
      };
      const result = await issuer.sign(dccCredential, options);
      expect(result.issuer.id).to.equal(controller);
    }).slow(5000).timeout(10000);

    it('should sign presentation', async () => {
      const options = {
        'verificationMethod': keyId,
        'challenge': challenge
      };
      const result: any = await issuer.createAndSignPresentation(null, presentationId, controller, options);
      const vmResult = getProofProperty(result.proof, 'verificationMethod');
      expect(vmResult).to.equal(keyId);
    }).slow(5000).timeout(10000);
  });
