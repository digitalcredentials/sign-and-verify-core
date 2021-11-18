import { readFileSync } from 'fs';
import { expect } from 'chai';
import { createSandbox } from 'sinon';
import 'mocha';
import * as Verifier from './verifier';

const sandbox = createSandbox();
const identifer = 'did:web:digitalcredentials.github.io#z6MkrXSQTybtqyMasfSxeRBJxDvDUGqb7mt9fFVXkVn6xTG7';
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
  "issuer": "did:web:digitalcredentials.github.io",
  "issuanceDate": "2020-03-10T04:24:12.164Z",
  "credentialSubject": {
    "id": "did:example:abcdef"
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2021-05-04T18:59:42Z",
    "verificationMethod": "did:web:digitalcredentials.github.io#z6MkrXSQTybtqyMasfSxeRBJxDvDUGqb7mt9fFVXkVn6xTG7",
    "proofPurpose": "assertionMethod",
    "proofValue": "z4jnMia8Q1EDAQDNnurAnQgNmc1PmhrXx87j6zr9rjvrpGqSFxcHqJf55HjQPJm7Qj712KU3DXpNF1N6gYh77k9M3"
  }
}

const dccCredentialSigned = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/dcc/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "https://digitalcredentials.github.io/samples/certificate/1fe91f0f-4c64-48c8-bfc8-7132f75776fe/",
  "type": [
    "VerifiableCredential",
    "LearningCredential"
  ],
  "issuer": {
    "type": "Issuer",
    "id": "did:web:digitalcredentials.github.io",
    "name": "Sample Issuer",
    "url": "https://digitalcredentials.github.io/samples/"
  },
  "issuanceDate": "2021-01-19T18:22:34.772810+00:00",
  "credentialSubject": {
    "type": "Person",
    "id": "did:example:456",
    "name": "Percy",
    "hasCredential": {
      "type": [
        "EducationalOccupationalCredential",
        "ProgramCompletionCredential"
      ],
      "name": "DCC Sample Program Completion Credential",
      "description": "<p>Learn stuff about requesting a DCC credential.</p>",
      "awardedOnCompletionOf": {
        "type": "EducationalOccupationalProgram",
        "identifier": "program-v1:Sample",
        "name": "Successful completion of sample request program",
        "description": "<p>Learn stuff about DCC credential issuance</p>",
        "numberOfCredits": {
          "value": "1"
        },
        "startDate": "",
        "endDate": ""
      }
    }
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2021-05-04T18:59:42Z",
    "verificationMethod": "did:web:digitalcredentials.github.io#z6MkrXSQTybtqyMasfSxeRBJxDvDUGqb7mt9fFVXkVn6xTG7",
    "proofPurpose": "assertionMethod",
    "proofValue": "z5TL5WVEHoh4NAyooyreDpgGYRhGymDzvZMXEynMpNVCtAupMV7N8WJVzmjSUHFe71T6FZqVZxexA8iVtD7PLL8f4"
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

const preloadedDidDocument = JSON.parse(readFileSync("data/public-did:web:digitalcredentials.github.io.json").toString("ascii"));
const verifier = Verifier.createVerifier([preloadedDidDocument]);

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
        'verificationMethod': identifer
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
        'verificationMethod': identifer
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
