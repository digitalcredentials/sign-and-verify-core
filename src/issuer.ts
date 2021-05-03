import { DIDDocument } from "./types"
import { SignatureOptions, getSigningKeyIdentifier, getSigningDate, getProofProperty } from "./signatures";
import { default as demoCredential } from "./demoCredential.json";
import { v4 as uuidv4 } from 'uuid';
import { contexts as ldContexts, documentLoaderFactory } from '@transmute/jsonld-document-loader';
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';
import { Ed25519Signature2020 } from '@digitalbazaar/ed25519-signature-2020';
import DccContextV1 from "./contexts/dcc-v1.json";

const didContext = require('did-context');
const ed25519 = require('ed25519-signature-2020-context');
const vc = require('@digitalbazaar/vc');
const didKey = require('@digitalbazaar/did-method-key');
const proofPurposes = require('jsonld-signatures').purposes;
const DccContextV1Url = "https://w3id.org/dcc/v1";
const VerificationMethod = "verificationMethod";
const Challenge = "challenge";

export function getController(fullDid: string) {
  return fullDid.split('#')[0];
}

export function createIssuer(unlockedDID: DIDDocument) {

  const customLoaderProto = documentLoaderFactory.pluginFactory
    .build({
      contexts: {
        ...ldContexts.W3C_Verifiable_Credentials,
        ...ldContexts.W3ID_Security_Vocabulary,
        ...ldContexts.W3C_Decentralized_Identifiers
      },
    })
    .addContext({ [ed25519.constants.CONTEXT_URL]: ed25519.contexts.get(ed25519.constants.CONTEXT_URL) })
    .addContext({ [didContext.constants.DID_CONTEXT_URL]: didContext.contexts.get(didContext.constants.DID_CONTEXT_URL) })
    .addContext({ [DccContextV1Url]: DccContextV1 });

  const didKeyDriver = didKey.driver();

  const customLoader = customLoaderProto.
    addResolver({
      [unlockedDID.id]: {
        resolve: async (_did: string) => {
          return unlockedDID;
        },
      },
    })
    .addResolver({
      ['did:key:']: {
        resolve: async (_did: string) => {
          return didKeyDriver.get({ did: _did });

        },
      },
    })
    .buildDocumentLoader();

  const unlockedAssertionMethods = new Map<string, Ed25519VerificationKey2020>([
    [unlockedDID.assertionMethod[0].id, new Ed25519VerificationKey2020(unlockedDID.assertionMethod[0])]
  ]);

  async function resolveDid(assertionMethod: string): Promise<any> {
    if (assertionMethod == null) {
      throw new Error(`Can't resolve empty DID string`);
    }
    const controller = getController(assertionMethod);
    const doc = await customLoader(controller);
    console.log(JSON.stringify(doc, null, 2));
    return doc.document;
    /*
    if (!controller.startsWith('did:key')) {
      throw new Error(`DID method (${controller}) not supported`);
    } 

    const res = await didKeyDriver.get({ did: controller });
    if (res == null) {
      throw new Error(`Unable to resolve DID method for ${controller}`);
    }
    return res;*/

  }
  async function createKey(assertionMethod: string): Promise<Ed25519VerificationKey2020> {
    const keyInfo: Ed25519VerificationKey2020 | undefined = unlockedAssertionMethods.get(assertionMethod);
    if (keyInfo == null) {
      const res = await resolveDid(assertionMethod);
      const key = res.verificationMethod[0];
      return new Ed25519VerificationKey2020(key);
    }

    return keyInfo;
  }


  async function createSigningKey(options: SignatureOptions): Promise<Ed25519Signature2020> {
    const signingKey = await createKey(getSigningKeyIdentifier(options));
    const signatureSuite = new Ed25519Signature2020({
      key: signingKey,
      date: getSigningDate(options)
    });
    return signatureSuite;
  }

  async function createVerificationKey(options: SignatureOptions): Promise<Ed25519VerificationKey2020> {
    const signingKey = await createKey(getSigningKeyIdentifier(options));
    return signingKey;
  }

  const assertionController = {
    '@context': 'https://w3id.org/security/v2',
    id: 'https://example.edu/issuers/565049',
    // actual keys are going to be added in the test suite before() block
    assertionMethod: [],
    authentication: []
  };
  module.exports = assertionController;

  async function verify(verifiableCredential: any, options: SignatureOptions): Promise<any> {
    const verificationMethod = getSigningKeyIdentifier(options);
    const didDocument = await resolveDid(verificationMethod);

    const key = didDocument.verificationMethod ? didDocument.verificationMethod[0] : didDocument.assertionMethod[0];
    const verificationKey = new Ed25519VerificationKey2020(key);
    try {
      /*
      let valid = await vc.verifyCredential({
        credential: verifiableCredential,
        controller: didDocument,
        suite: verificationKey,
        customLoader
      });
      return valid;*/

      const valid = await vc.verifyCredential({ credential: verifiableCredential, suite: verificationKey });
      return valid;
    }
    catch (e) {
      console.error(e);
      throw e;
    }
  }

  async function sign(credential: any, options: SignatureOptions): Promise<any> {
    const suite = await createSigningKey(options);
    // this library attaches the signature on the original object, so make a copy 
    const credCopy = JSON.parse(JSON.stringify(credential));
    try {
      let result = await vc.issue({
        credential: credCopy,
        suite: suite,
        documentLoader: customLoader
      });
      return result;
    } catch (e) {
      console.error(e);
      throw e;
    }
  }

  async function signPresentation(presentation: any, options: SignatureOptions): Promise<any> {
    const suite = await createSigningKey(options);

    let result = await vc.signPresentation({
      presentation: presentation,
      documentLoader: customLoader,
      suite: suite,
      challenge: options.challenge!
    });
    return result;
  }

  async function createAndSignPresentation(credential: any, presentationId: string, holder: string, options: SignatureOptions): Promise<any> {
    const suite = await createSigningKey(options);
    const presentation = vc.createPresentation({
      verifiableCredential: credential,
      id: presentationId,
      holder: holder,
    });

    let result = await vc.signPresentation({
      presentation: presentation,
      documentLoader: customLoader,
      suite: suite,
      challenge: options.challenge!
    });
    return result;
  }

  async function verifyPresentation(verifiablePresentation: any, options: SignatureOptions): Promise<any> {
    const suite = await createVerificationKey(options);

    let valid = await vc.verify({
      presentation: { ...verifiablePresentation },
      documentLoader: customLoader,
      suite: suite,
      challenge: options.challenge!,
    });
    return valid;
  }

  async function requestDemoCredential(verifiablePresentation: any, skipVerification = false): Promise<any> {

    if (!skipVerification) {
      // issuer also needs to check if challenge is expected
      const verificationOptions = {
        verificationMethod: getProofProperty(verifiablePresentation.proof, VerificationMethod),
        challenge: getProofProperty(verifiablePresentation.proof, Challenge)
      };
      const verificationResult = await verifyPresentation(verifiablePresentation, verificationOptions);
      if (!verificationResult.verified) {
        throw new Error("Invalid credential request");
      }
    }

    const subjectDid = verifiablePresentation.holder;
    const verificationMethod = unlockedDID.assertionMethod[0].id;
    const options = new SignatureOptions({ verificationMethod: verificationMethod });

    let copy = JSON.parse(JSON.stringify(demoCredential));
    copy.id = uuidv4();
    copy.credentialSubject.id = subjectDid;
    copy.issuanceDate = new Date().toISOString();
    return sign(copy, options);
  }

  return {
    createKey,
    createSuite: createSigningKey,
    verify,
    sign,
    signPresentation,
    createAndSignPresentation,
    verifyPresentation,
    requestDemoCredential,
    customLoader // tODO
  }
}
