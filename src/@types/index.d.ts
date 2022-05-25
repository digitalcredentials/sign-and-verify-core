declare module '@digitalcredentials/did-method-key';
declare module '@digitalcredentials/did-web-resolver';
declare module '@digitalcredentials/ed25519-verification-key-2020' {
  export class Ed25519VerificationKey2020 {
    id: string;
    type: string;
    controller: string;
    publicKeyMultibase: string;
    privateKeyMultibase?: string;
    constructor(options?: any);

    verifier(): any;
  }
}
declare module '@digitalcredentials/ed25519-signature-2020' {
  export class Ed25519Signature2020 {
    constructor(options?: any)
  }
}
declare module '@digitalcredentials/x25519-key-agreement-key-2020';
declare module '@digitalcredentials/open-badges-context';
