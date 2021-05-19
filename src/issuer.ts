import { DIDDocument } from "./types";
import { getCustomLoader, addDidDocuments, getPreloadedAssertionMethods } from "./common";
import { SignatureOptions, getSigningKeyIdentifier, getSigningDate, getProofProperty } from "./signatures";
import { Ed25519VerificationKey2020 } from '@digitalcredentials/ed25519-verification-key-2020';
import { Ed25519Signature2020 } from '@digitalcredentials/ed25519-signature-2020';

const vc = require('@digitalcredentials/vc');

export function createIssuer(unlockedDIDDocuments: DIDDocument[], defaultSigningIdentifier?: string) {

  let customLoaderProto = getCustomLoader();
  customLoaderProto = addDidDocuments(customLoaderProto, unlockedDIDDocuments);
  let customLoader = customLoaderProto.buildDocumentLoader();

  const unlockedAssertionMethods: Map<string, Ed25519VerificationKey2020> = getPreloadedAssertionMethods(unlockedDIDDocuments);

  const signingIdentifier = defaultSigningIdentifier ? defaultSigningIdentifier :
    unlockedAssertionMethods.keys().next().value;

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

  return {
    createKey,
    createSuite: createSigningKey,
    sign,
    signPresentation,
    createAndSignPresentation
  }
}
