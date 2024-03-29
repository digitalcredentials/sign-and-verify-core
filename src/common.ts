import { contexts as ldContexts, documentLoaderFactory } from '@transmute/jsonld-document-loader';
import { CONTEXT_URL_V1 as SL_CONTEXT_URL_V1, CONTEXT_V1 as SL_CONTEXT_V1 } from '@digitalbazaar/vc-status-list-context';
import { DIDDocument } from './types';
import { Ed25519VerificationKey2020 } from '@digitalcredentials/ed25519-verification-key-2020';
import obCtx from '@digitalcredentials/open-badges-context';

import didContext from '@digitalcredentials/did-context';
import ed25519 from 'ed25519-signature-2020-context';
import x25519Ctx from '@digitalcredentials/x25519-key-agreement-2020-context';

export function getController(fullDid: string) {
  return fullDid.split('#')[0];
}

export function getCustomLoader() : any {
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
  .addContext({ [SL_CONTEXT_URL_V1]: SL_CONTEXT_V1 })

  // Open Badges v3 Context (with multiple URL aliases)
  .addContext({ [obCtx.CONTEXT_URL_V3]: obCtx.CONTEXT_V3 })
  .addContext({ [obCtx.constants.CONTEXT_URL_V3_JFF_V1]: obCtx.CONTEXT_V3 })
  .addContext({ [obCtx.constants.CONTEXT_URL_V3_IMS]: obCtx.CONTEXT_V3 })

    .addContext({ [x25519Ctx.constants.CONTEXT_URL]: x25519Ctx.contexts.get(x25519Ctx.constants.CONTEXT_URL) });
  return customLoaderProto;
}

export function addDidDocuments(customLoaderProto: any, preloadedDidDocuments: DIDDocument[]) : any {
  preloadedDidDocuments.forEach((didDoc) => {
    customLoaderProto.addResolver({
      [didDoc.id]: {
        resolve: async (_did: string) => {
          return didDoc;
        },
      },
    });
  });
  return customLoaderProto;
}

export function getPreloadedAssertionMethods(preloadedDidDocuments: DIDDocument[]) : Map<string, Ed25519VerificationKey2020> {
  const preloadedAssertionMethods: Map<string, Ed25519VerificationKey2020> = new Map();
  preloadedDidDocuments.forEach((didDoc) => {
    didDoc.assertionMethod.forEach((am: Ed25519VerificationKey2020) => {
      preloadedAssertionMethods.set(am.id, am);
    });
  });
  return preloadedAssertionMethods;
}
