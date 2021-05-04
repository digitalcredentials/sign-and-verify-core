import { DIDDocument } from "./types"
import { SignatureOptions } from "./signatures";
import { getCustomLoaderProto } from "./common"
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';
import { Ed25519Signature2020 } from '@digitalbazaar/ed25519-signature-2020';

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

  async function verify(verifiableCredential: any, options: SignatureOptions): Promise<any> {
    // During verification, the public key is fetched via documentLoader,
    // so no key is necessary when creating the suite
    const suite = new Ed25519Signature2020();

    try {
      const valid = await vc.verifyCredential({
        credential: verifiableCredential,
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

  async function verifyPresentation(verifiablePresentation: any, options: SignatureOptions): Promise<any> {
    // During verification, the public key is fetched via documentLoader,
    // so no key is necessary when creating the suite
    const suite = new Ed25519Signature2020();

    let valid = await vc.verify({
      presentation: { ...verifiablePresentation },
      documentLoader: customLoader,
      suite: suite,
      challenge: 'test123' // options.challenge!,
    });
    return valid;
  }

  return {
    verify,
    verifyPresentation
  }
}
