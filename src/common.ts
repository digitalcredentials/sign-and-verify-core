
import { contexts as ldContexts, documentLoaderFactory } from '@transmute/jsonld-document-loader';
import DccContextV1 from "./contexts/dcc-v1.json";

const didContext = require('did-context');
const ed25519 = require('ed25519-signature-2020-context');
const DccContextV1Url = "https://w3id.org/dcc/v1";
const x25519Ctx = require('x25519-key-agreement-2020-context');

export function getController(fullDid: string) {
  return fullDid.split('#')[0];
}

export function getCustomLoaderProto() {
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
    .addContext({ [DccContextV1Url]: DccContextV1 })
    .addContext({ [x25519Ctx.constants.CONTEXT_URL]: x25519Ctx.contexts.get(x25519Ctx.constants.CONTEXT_URL) });

    return customLoaderProto;
}
