export const DefaultProofPurpose = 'assertionMethod';
const SecurityPrefix = 'https://w3id.org/security';

export class SignatureOptions {
  public verificationMethod?: string;
  public proofPurpose?: string = DefaultProofPurpose;
  public created?: string;
  public domain?: string;
  public challenge?: string;

  public constructor(options: SignatureOptions) {
    Object.assign(this, options);
  }
}

// Added to work around confusing naming schemes. Later, there may be some layer of indirection
// but for now, it's just the verificationMethod for our use cases.
export function getSigningKeyIdentifier(options: SignatureOptions): string {
  return options.verificationMethod!;
};

export function getSigningDate(options: SignatureOptions): string {
  return options.created ? options.created! : new Date().toISOString()
};

export function getProofProperty(vpProof: any, property: string): any {
  let propValue: any = null;
  if (vpProof.hasOwnProperty(property)) {
    propValue = vpProof[property];
  } else if (vpProof.hasOwnProperty(`${SecurityPrefix}#${property}`)) {
    propValue = vpProof[`${SecurityPrefix}#${property}`];
  } else {
    throw new Error(`Invalid proof property ${property}`);
  }

  if (propValue.hasOwnProperty('id')) {
    return propValue.id;
  }
  return propValue;
}