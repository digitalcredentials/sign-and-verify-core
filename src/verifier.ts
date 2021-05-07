import { DIDDocument } from "./types"
import { SignatureOptions } from "./signatures";
import { getCustomLoader, addDidDocuments, getPreloadedAssertionMethods } from "./common"
import { Ed25519Signature2020 } from '@digitalbazaar/ed25519-signature-2020';

const vc = require('@digitalbazaar/vc');
const didKey = require('@digitalbazaar/did-method-key');

export function createVerifier(preloadedDidDocuments: DIDDocument[]) {
  const didKeyDriver = didKey.driver();

  let customLoaderProto = getCustomLoader();
  customLoaderProto = addDidDocuments(customLoaderProto, preloadedDidDocuments);
  customLoaderProto.addResolver({
      ['did:key:']: {
        resolve: async (_did: string) => {
          return didKeyDriver.get({ did: _did });
        },
      },
    });

  let transmuteLoader = customLoaderProto.buildDocumentLoader();

  const preloadedAssertionMethods = getPreloadedAssertionMethods(preloadedDidDocuments);

  const customLoader = async (url: string): Promise<any> => {
    const result = preloadedAssertionMethods.get(url);
    if (result) {
      const document = {
        '@context': 'https://w3id.org/security/suites/ed25519-2020/v1',
        ...result
      };
      return {
        documentUrl: url,
        document
      };
    }

    return transmuteLoader(url);
  };

  async function verify(verifiableCredential: any, options?: SignatureOptions): Promise<any> {
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

  async function verifyPresentation(verifiablePresentation: any, options?: SignatureOptions): Promise<any> {
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
