import * as axios from axios;
import { DIDDocument } from "./types"
import { SignatureOptions } from "./signatures";
import { getCustomLoader, addDidDocuments, getPreloadedAssertionMethods } from "./common"
import { Ed25519Signature2020 } from '@digitalcredentials/ed25519-signature-2020';

const vc = require('@digitalcredentials/vc');
const didKey = require('@digitalcredentials/did-method-key');
const ISSUER_REGISTRY_URL = 'https://digitalcredentials.github.io/issuer-registry/registry.json';

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

  async function validate(verifiableCredential: any): Promise<any> {
    const issuerRegistry = JSON.parse((await axios.get(ISSUER_REGISTRY_URL)).data.registry);
    return issuerRegistry.hasOwnProperty(verifiableCredential.issuer);
  }

  async function verify(verifiableCredential: any, options?: SignatureOptions): Promise<any> {
    // During verification, the public key is fetched via documentLoader,
    // so no key is necessary when creating the suite
    const suite = new Ed25519Signature2020();

    try {
      const verified = await vc.verifyCredential({
        credential: verifiableCredential,
        documentLoader: customLoader,
        suite
      });
      const valid = await validate(verifiableCredential);
      return verified && valid;
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
    const toVerify: any = {
      presentation: { ...verifiablePresentation },
      documentLoader: customLoader,
      suite: suite
    };
    if (options && options!.challenge) {
      toVerify['challenge'] = options!.challenge;
    }

    let valid = await vc.verify(toVerify);
    return valid;
  }

  return {
    verify,
    verifyPresentation,
    validate
  }
}
