import { Ed25519VerificationKey2020 }
  from '@digitalbazaar/ed25519-verification-key-2020';

export type DIDDocument = {
  "@context": string,
  "id": string,
  "controller": string | string[],
  "assertionMethod": Ed25519VerificationKey2020[],
  "authentication": Ed25519VerificationKey2020[] | string[],
  "capabilityDelegation": Ed25519VerificationKey2020[] | string[],
  "capabilityInvocation": Ed25519VerificationKey2020[] | string[]
}


