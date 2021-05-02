import { Ed25519VerificationKey2020 }
  from '@digitalbazaar/ed25519-verification-key-2020';


export type DIDDocument = {
  "@context": string,
  "id": string,
  "assertionMethod": Ed25519VerificationKey2020[]
}
