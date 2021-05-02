/// <reference types="node" />

declare module '@digitalbazaar/ed25519-verification-key-2020' {

  export class Ed25519VerificationKey2020 {
    id: string;
    type: "JsonWebKey2020";
    controller: string;
    publicKeyMultibase: string;
    privateKeyMultibase: string;

    constructor(options = {});
  
  };


}