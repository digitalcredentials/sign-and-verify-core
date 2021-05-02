/// <reference types="node" />

declare module '@digitalbazaar/security-document-loader' {

  export function securityLoader() : JsonLdDocumentLoader; 

}

/*
export function securityLoader() {
  const loader = new JsonLdDocumentLoader();

  loader.addStatic(ed25519.constants.CONTEXT_URL,
    ed25519.contexts.get(ed25519.constants.CONTEXT_URL));

  loader.addStatic(x25519.constants.CONTEXT_URL,
    x25519.contexts.get(x25519.constants.CONTEXT_URL));

  loader.addStatic(didContext.constants.DID_CONTEXT_URL,
    didContext.contexts.get(didContext.constants.DID_CONTEXT_URL));

  loader.addStatic(CREDENTIALS_CONTEXT_V1_URL,
    credentialsContext.get(CREDENTIALS_CONTEXT_V1_URL));

  loader.setDidResolver(resolver);

  return loader;
}*/
