import jsonld from "jsonld";
import { JsonWebKey, JsonWebSignature } from "@transmute/json-web-signature-2020";
import vc from "vc-js";
import { PublicKey, DIDDocument } from "./types"
import { SignatureOptions, getSigningKeyIdentifier, getSigningDate, getProofProperty } from "./signatures";
import { default as demoCredential } from "./demoCredential.json";
import { v4 as uuidv4 } from 'uuid';

import { contexts, documentLoaderFactory } from '@transmute/jsonld-document-loader';
import DccContextV1 from "./contexts/dcc-v1.json";
import LdsJws2020ContextV1 from "./contexts/lds-jws2020-v1.json";

const DccContextV1Url = "https://w3id.org/dcc/v1";
const LdsJws2020ContextV1Url = "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json";
const CredentialExamplesV1Url = "https://www.w3.org/2018/credentials/examples/v1";


const VerificationMethod = "verificationMethod";
const Challenge = "challenge";

export function getController(fullDid: string) {
  return fullDid.split('#')[0];
}

export function createIssuer(unlockedDID: DIDDocument) {

  const customLoader = documentLoaderFactory.pluginFactory
    .build({
      contexts: {
        ...contexts.W3C_Verifiable_Credentials,
        ...contexts.W3ID_Security_Vocabulary,
        ...contexts.W3C_Decentralized_Identifiers
      },
    })
    .addContext({[LdsJws2020ContextV1Url]: LdsJws2020ContextV1})
    .addContext({[DccContextV1Url]: DccContextV1})
    .addResolver({
      [unlockedDID.id]: {
        resolve: async (_did: string) => {
          return unlockedDID;
        },
      },
    })
    .buildDocumentLoader();

  const unlockedAssertionMethods = new Map<string, PublicKey>([
    [unlockedDID.publicKey[0].id, unlockedDID.publicKey[0]]
  ]);

  function createJwk(assertionMethod: string) {
    const keyInfo: any = unlockedAssertionMethods.get(assertionMethod);
    return new JsonWebKey(keyInfo);
  }

  function createSuite(options: SignatureOptions) {
    const signingKey = createJwk(getSigningKeyIdentifier(options));
    const signatureSuite = new JsonWebSignature({
      key: signingKey,
      date: getSigningDate(options)
    });
    return signatureSuite;
  }

  async function verify(verifiableCredential: any, options: SignatureOptions) {
    const suite = createSuite(options);
    try {
      let valid = await vc.verifyCredential({
        credential: { ...verifiableCredential },
        documentLoader: customLoader,
        suite
      });
      return valid;
    }
    catch (e) {
      console.error(e);
      throw e;
    }
  }

  async function sign(credential: any, options: SignatureOptions) {
    const suite = createSuite(options);
    try {
      let result = await vc.issue({
        credential: credential,
        documentLoader: customLoader,
        suite
      });
      return result;
    } catch (e) {
      console.error(e);
      throw e;
    }
  }

  async function signPresentation(presentation: any, options: SignatureOptions) {
    const suite = createSuite(options);

    let result = await vc.signPresentation({
      presentation: presentation,
      documentLoader: customLoader,
      suite,
      challenge: options.challenge!
    });
    return result;
  }

  async function createAndSignPresentation(credential: any, presentationId: string, holder: string, options: SignatureOptions) {
    const suite = createSuite(options);
    const presentation = vc.createPresentation({
      verifiableCredential: credential,
      id: presentationId,
      holder: holder
    });
    presentation["@context"].push(CredentialExamplesV1Url);
    presentation["@context"].push(LdsJws2020ContextV1Url);

    let result = await vc.signPresentation({
      presentation: presentation,
      documentLoader: customLoader,
      suite,
      challenge: options.challenge!
    });
    return result;
  }

  async function verifyPresentation(verifiablePresentation: any, options: SignatureOptions) {
    const suite = createSuite(options);

    let valid = await vc.verify({
      presentation: { ...verifiablePresentation },
      documentLoader: customLoader,
      challenge: options.challenge!,
      suite
    });
    return valid;
  }

  async function requestDemoCredential(verifiablePresentation: any, skipVerification = false) {

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
    const verificationMethod = unlockedDID.assertionMethod[0];
    const signatureOptions = {
      verificationMethod: verificationMethod
    };

    let copy = JSON.parse(JSON.stringify(demoCredential));
    copy.id = uuidv4();
    copy.credentialSubject.id = subjectDid;
    copy.issuanceDate = new Date().toISOString();
    return sign(copy, signatureOptions);
  }

  return {
    createJwk,
    createSuite,
    verify,
    sign,
    signPresentation,
    createAndSignPresentation,
    verifyPresentation,
    requestDemoCredential
  }
}
