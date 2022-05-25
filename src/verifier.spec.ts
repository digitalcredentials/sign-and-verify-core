import { readFileSync } from 'fs';
import { expect } from 'chai';
import { createSandbox } from 'sinon';
import 'mocha';
import * as Verifier from './verifier';

import { createVerifier } from './verifier';

const sandbox = createSandbox();

const keyId = 'did:key:z6MkqanD5cmEVf154z5xExoxNKENAzVr3gdPo4wD2R2aCUzj#z6MkqanD5cmEVf154z5xExoxNKENAzVr3gdPo4wD2R2aCUzj';

const challenge = 'test123';

const simpleCredentialSigned = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "http://example.gov/credentials/3732",
  "type": [
    "VerifiableCredential"
  ],
  "issuer": "did:key:z6MkqanD5cmEVf154z5xExoxNKENAzVr3gdPo4wD2R2aCUzj",
  "issuanceDate": "2020-03-10T04:24:12.164Z",
  "credentialSubject": {
    "id": "did:example:abcdef"
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2022-05-25T16:31:36Z",
    "verificationMethod": "did:key:z6MkqanD5cmEVf154z5xExoxNKENAzVr3gdPo4wD2R2aCUzj#z6MkqanD5cmEVf154z5xExoxNKENAzVr3gdPo4wD2R2aCUzj",
    "proofPurpose": "assertionMethod",
    "proofValue": "z5BVEnYV8MdPSMAWEDuFnJ9ufnEjSuGkEKKqWyoZenUH6eNVaxbPLY2kqMp5amSgcRwymms6qboefqsNsvvvNggdZ"
  }
}


const dccCredentialSigned = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3c-ccg.github.io/vc-ed/plugfest-1-2022/jff-vc-edu-plugfest-1-context.json",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "type": [
    "VerifiableCredential",
    "OpenBadgeCredential"
  ],
  "issuer": {
    "type": "Profile",
    "id": "did:key:z6MkqanD5cmEVf154z5xExoxNKENAzVr3gdPo4wD2R2aCUzj",
    "name": "Jobs for the Future (JFF)",
    "url": "https://www.jff.org/",
    "image": "https://w3c-ccg.github.io/vc-ed/plugfest-1-2022/images/JFF_LogoLockup.png"
  },
  "issuanceDate": "2022-05-01T00:00:00Z",
  "credentialSubject": {
    "type": "AchievementSubject",
    "achievement": {
      "type": "Achievement",
      "name": "Sample test credential to prep for JFF Plugfest #1 2022",
      "description": "This wallet can display this Open Badge 3.0",
      "criteria": {
        "type": "Criteria",
        "narrative": "The first cohort of the JFF Plugfest 1 in May/June of 2022 collaborated to push interoperability of VCs in education forward."
      },
      "image": "https://w3c-ccg.github.io/vc-ed/plugfest-1-2022/images/plugfest-1-badge-image.png"
    }
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2022-05-25T16:32:30Z",
    "verificationMethod": "did:key:z6MkqanD5cmEVf154z5xExoxNKENAzVr3gdPo4wD2R2aCUzj#z6MkqanD5cmEVf154z5xExoxNKENAzVr3gdPo4wD2R2aCUzj",
    "proofPurpose": "assertionMethod",
    "proofValue": "z2WLrRzdKpda4KkdDgKdLmwmAjUH1WCZKVUc14r8BdJv2pJe2BSaCBsQHctP4wFdTCikaxycjQXPjcfhHw7yhBW7C"
  }
}

const verifiablePresentation = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "type": [
    "VerifiablePresentation"
  ],
  "id": "123",
  "holder": "did:key:z6MkoSu3TY7zYt7RF9LAqXbW7VegC3SFAdLp32VWudSfv8Qy",
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2021-05-01T23:38:10Z",
    "verificationMethod": "did:key:z6MkoSu3TY7zYt7RF9LAqXbW7VegC3SFAdLp32VWudSfv8Qy#z6MkoSu3TY7zYt7RF9LAqXbW7VegC3SFAdLp32VWudSfv8Qy",
    "proofPurpose": "authentication",
    "challenge": "test123",
    "proofValue": "z3Ukrcvwg59pPywog48R6xB6Fd5XWmPazqPCjdpaXpdKzaeNAc1Un1EF8VnVLbf4nvRk5SGiVDvgxddS66bi7kdAo"
  }
};

const preloadedDidDocument = JSON.parse(readFileSync("data/public-did:key.json").toString("ascii"));
const verifier = createVerifier([preloadedDidDocument]);

const configureTestSuite = (success: boolean) => {
  const describeModifier = success ? 'Valid' : 'Invalid';
  const itModifier = success ? ' ' : ' not ';

  describe(`${describeModifier} DCC Issuer`, () => {
    before(() => {
      // This line ensures that the issuer is accepted
      // as a valid DCC member for testing purposes
      sandbox.stub(Verifier, 'validateCredential').resolves(success);
      sandbox.stub(Verifier, 'validatePresentation').resolves(success);
    });

    after(() => {
      // This line restores the stubs (e.g., validate)
      // function for subsequent test suites
      sandbox.restore();
    });

    it(`should${itModifier}verify`, async () => {
      const options = {
        'verificationMethod': keyId
      };
      const verificationResult = await verifier.verify({
        verifiableCredential: simpleCredentialSigned,
        issuerMembershipRegistry: {},
        options
      });
      expect(verificationResult.verified && verificationResult.valid).to.equal(success);
    }).slow(5000).timeout(10000);

    it(`should${itModifier}verify with DCC context`, async () => {
      const options = {
        'verificationMethod': keyId
      };
      const verificationResult = await verifier.verify({
        verifiableCredential: dccCredentialSigned,
        issuerMembershipRegistry: {},
        options
      });
      expect(verificationResult.verified && verificationResult.valid).to.equal(success);
    }).slow(5000).timeout(10000);

    it(`should${itModifier}verify presentation`, async () => {
      const options = {
        'challenge': challenge,
      };
      const verificationResult = await verifier.verifyPresentation({
        verifiablePresentation,
        issuerMembershipRegistry: {},
        options
      });
      expect(verificationResult.verified && verificationResult.valid).to.equal(success);
    }).slow(5000).timeout(10000);
  });
};

describe('Verifier Test',
  () => {
    configureTestSuite(true);
    configureTestSuite(false);
  }
);
