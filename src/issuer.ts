import { DIDDocument } from './types';
import { getCustomLoader, addDidDocuments, getPreloadedAssertionMethods } from './common';
import { SignatureOptions, getSigningKeyIdentifier, getSigningDate } from './signatures';
import { Ed25519VerificationKey2020 } from '@digitalcredentials/ed25519-verification-key-2020';
import { Ed25519Signature2020 } from '@digitalcredentials/ed25519-signature-2020';
import vc from '@digitalcredentials/vc';
import { securityLoader } from '@digitalcredentials/security-document-loader';

export function createIssuer(unlockedDIDDocuments: DIDDocument[], defaultSigningIdentifier?: string) {
  const customLoader = securityLoader({ fetchRemoteContexts: true }).build();

  const unlockedAssertionMethods: Map<string, Ed25519VerificationKey2020> = getPreloadedAssertionMethods(unlockedDIDDocuments);

  async function createKey(assertionMethod: string): Promise<Ed25519VerificationKey2020> {
    const keyInfo: Ed25519VerificationKey2020 | undefined = unlockedAssertionMethods.get(assertionMethod);
    if (!keyInfo) {
      throw new Error(`key for assertionMethod ${assertionMethod} not found`);
    }
    return new Ed25519VerificationKey2020(keyInfo);
  }

  async function createSigningKey(options: SignatureOptions): Promise<Ed25519Signature2020> {
    const signingKey = await createKey(getSigningKeyIdentifier(options));
    return new Ed25519Signature2020({
      key: signingKey,
      date: getSigningDate(options)
    });
  }

  async function sign(credential: any, options: SignatureOptions): Promise<any> {
    const suite = await createSigningKey(options);
    // this library attaches the signature on the original object, so make a copy
    const credCopy = JSON.parse(JSON.stringify(credential));
    try {
      return vc.issue({
        credential: credCopy,
        suite: suite,
        documentLoader: customLoader
      });
    } catch (e) {
      console.error(e);
      throw e;
    }
  }

  async function signPresentation(presentation: any, options: SignatureOptions): Promise<any> {
    const suite = await createSigningKey(options);

    return vc.signPresentation({
      presentation: presentation,
      documentLoader: customLoader,
      suite: suite,
      challenge: options.challenge!
    });
  }

  async function createAndSignPresentation(credential: any, presentationId: string, holder: string, options: SignatureOptions): Promise<any> {
    const suite = await createSigningKey(options);
    const presentation = vc.createPresentation({
      verifiableCredential: credential,
      id: presentationId,
      holder: holder,
    });

    return vc.signPresentation({
      presentation: presentation,
      documentLoader: customLoader,
      suite: suite,
      challenge: options.challenge!
    });
  }

  return {
    createKey,
    createSuite: createSigningKey,
    sign,
    signPresentation,
    createAndSignPresentation
  }
}
