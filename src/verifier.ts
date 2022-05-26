import { DIDDocument } from "./types"
import { SignatureOptions } from "./signatures";
import { getCustomLoader, addDidDocuments, getPreloadedAssertionMethods } from "./common"
import { Ed25519Signature2020 } from '@digitalcredentials/ed25519-signature-2020';
import { Ed25519VerificationKey2020 } from '@digitalcredentials/ed25519-verification-key-2020';
import { X25519KeyAgreementKey2020 } from '@digitalcredentials/x25519-key-agreement-key-2020';
import { CryptoLD } from 'crypto-ld';
import * as vc from '@digitalcredentials/vc';
import * as didWeb from '@interop/did-web-resolver';
import * as didKey from '@digitalcredentials/did-method-key';
const { checkStatus } = require('@digitalbazaar/vc-status-list');

interface VerifyCredentialParameters {
  verifiableCredential: any;
  issuerMembershipRegistry: any;
  options?: SignatureOptions;
}

interface VerifyPresentationParameters {
  verifiablePresentation: any;
  issuerMembershipRegistry: any;
  options?: SignatureOptions;
}

// NOTE: This method is a simple and common issuer validation
// You may modify this method to suit the validation needs
// of your organization
export const validateCredential = async (verifiableCredential: any, issuerMembershipRegistry: any): Promise<boolean> => {
  if (typeof verifiableCredential.issuer === 'object') {
    return issuerMembershipRegistry.hasOwnProperty(verifiableCredential.issuer.id);
  }
  return issuerMembershipRegistry.hasOwnProperty(verifiableCredential.issuer);
};

export const validatePresentation = async (verifiablePresentation: any, issuerMembershipRegistry: any): Promise<boolean> => {
  if (!verifiablePresentation.verifiableCredential) {
    // presentation may omit credential
    return true;
  }
  if (Array.isArray(verifiablePresentation.verifiableCredential)) {
    return verifiablePresentation.verifiableCredential.every((credential: any) => {
      return validateCredential(credential, issuerMembershipRegistry);
    });
  }
  return validateCredential(verifiablePresentation.verifiableCredential, issuerMembershipRegistry);
};

export const createVerifier = (preloadedDidDocuments: DIDDocument[]) => {
  const cryptoLd = new CryptoLD();
  cryptoLd.use(Ed25519VerificationKey2020);
  cryptoLd.use(X25519KeyAgreementKey2020);

  const didWebDriver = didWeb.driver({ cryptoLd });
  const didKeyDriver = didKey.driver();

  let customLoaderProto = getCustomLoader();
  customLoaderProto = addDidDocuments(customLoaderProto, preloadedDidDocuments);
  customLoaderProto.addResolver({
      ['did:web:']: {
        resolve: async (_did: string) => {
          return didWebDriver.get({ did: _did });
        },
      },
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

  async function verify({
    verifiableCredential,
    issuerMembershipRegistry,
    options
  }: VerifyCredentialParameters): Promise<any> {
    // During verification, the public key is fetched via documentLoader,
    // so no key is necessary when creating the suite
    const suite = new Ed25519Signature2020();

    try {
      const result = await vc.verifyCredential({
        credential: verifiableCredential,
        documentLoader: customLoader,
        checkStatus,
        suite
      });
      const verified = result.verified;
      const valid = await validateCredential(verifiableCredential, issuerMembershipRegistry);
      return { ...result, verified, valid };
    }
    catch (e) {
      console.error(e);
      throw e;
    }
  }

  async function verifyPresentation({
    verifiablePresentation,
    issuerMembershipRegistry,
    options
  }: VerifyPresentationParameters): Promise<any> {
    // During verification, the public key is fetched via documentLoader,
    // so no key is necessary when creating the suite
    const suite = new Ed25519Signature2020();
    const toVerify: any = {
      presentation: { ...verifiablePresentation },
      documentLoader: customLoader,
      checkStatus,
      suite
    };
    if (options && options!.challenge) {
      toVerify['challenge'] = options!.challenge;
    }

    const result = await vc.verify(toVerify);
    const verified = result.verified;
    const valid = await validatePresentation(verifiablePresentation, issuerMembershipRegistry);
    return { ...result, verified, valid };
  }

  return {
    verify,
    verifyPresentation
  }
};
