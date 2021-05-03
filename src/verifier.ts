import { DIDDocument } from "./types"
import { SignatureOptions, getSigningKeyIdentifier } from "./signatures";
import { getCustomLoaderProto, getController } from "./common"
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';

const vc = require('@digitalbazaar/vc');
const didKey = require('@digitalbazaar/did-method-key');

export function create(preloadedDid: DIDDocument) {

  const didKeyDriver = didKey.driver();
  const customLoader = getCustomLoaderProto()
    .addResolver({
      [preloadedDid.id]: {
        resolve: async (_did: string) => {
          return preloadedDid;
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

  async function resolveDid(controller: string): Promise<any> {
    if (controller == null) {
      throw new Error(`Can't resolve empty DID string`);
    }
    const doc = await customLoader(controller);
    if (doc == null) {
      throw new Error(`did doc for controller ${controller} not found`);
    }
    return doc.document;
  }


  async function createVerificationKey(verificationMethod: string): Promise<Ed25519VerificationKey2020> {
    const controller = getController(verificationMethod);
    const didDocument = await resolveDid(controller);
    const keyInfo = didDocument.verificationMethod ? didDocument.verificationMethod[0] : didDocument.assertionMethod[0];
    return new Ed25519VerificationKey2020(keyInfo);
  }

  async function verify(verifiableCredential: any, options: SignatureOptions): Promise<any> {
    const verificationMethod = getSigningKeyIdentifier(options);
    const key = await createVerificationKey(verificationMethod)

    try {
      /*
      let valid = await vc.verifyCredential({
        credential: verifiableCredential,
        controller: didDocument,
        suite: verificationKey,
        customLoader
      });
      return valid;*/

      const valid = await vc.verifyCredential({ credential: verifiableCredential, suite: key });
      return valid;
    }
    catch (e) {
      console.error(e);
      throw e;
    }
  }

  async function verifyPresentation(verifiablePresentation: any, options: SignatureOptions): Promise<any> {
    const suite = await createVerificationKey(getSigningKeyIdentifier(options));

    let valid = await vc.verify({
      presentation: { ...verifiablePresentation },
      documentLoader: customLoader,
      suite: suite,
      challenge: options.challenge!,
    });
    return valid;
  }

  return {
    createVerificationKey,
    verify,
    verifyPresentation
  }
}
