import { DIDDocument } from "./types";
import { getCustomLoaderProto } from "./common";
import { SignatureOptions, getSigningKeyIdentifier, getSigningDate, getProofProperty } from "./signatures";
import { default as demoCredential } from "./demoCredential.json";
import { v4 as uuidv4 } from 'uuid';
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';
import { Ed25519Signature2020 } from '@digitalbazaar/ed25519-signature-2020';

const vc = require('@digitalbazaar/vc');
const VerificationMethod = "verificationMethod";
const Challenge = "challenge";

export function create(unlockedDID: DIDDocument) {

  const customLoader = getCustomLoaderProto()
    .addResolver({
      [unlockedDID.id]: {
        resolve: async (_did: string) => {
          return unlockedDID;
        },
      },
    })
    .buildDocumentLoader();

  const unlockedAssertionMethods = new Map<string, Ed25519VerificationKey2020>([
    [unlockedDID.assertionMethod[0].id, new Ed25519VerificationKey2020(unlockedDID.assertionMethod[0])]
  ]);

  async function createKey(assertionMethod: string): Promise<Ed25519VerificationKey2020> {
    const keyInfo: Ed25519VerificationKey2020 | undefined = unlockedAssertionMethods.get(assertionMethod);
    if (keyInfo == null) {
      throw new Error(`key for assertionMethod ${assertionMethod} not found`);
    }
    return new Ed25519VerificationKey2020(keyInfo);
  }

  async function createSigningKey(options: SignatureOptions): Promise<Ed25519Signature2020> {
    const signingKey = await createKey(getSigningKeyIdentifier(options));
    const signatureSuite = new Ed25519Signature2020({
      key: signingKey,
      date: getSigningDate(options)
    });
    return signatureSuite;
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


  async function requestDemoCredential(verifiablePresentation: any, skipVerification = false): Promise<any> {

    /*
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
    return sign(copy, options);*/
    return null;
    // TODO
  }

  return {
    createKey,
    createSuite: createSigningKey,
    sign,
    signPresentation,
    createAndSignPresentation,
    requestDemoCredential
  }
}
