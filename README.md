# sign-and-verify-core

Signing and verification of [Verifiable Credentials](https://www.w3.org/TR/vc-data-model/#credentials) and [Verifiable Presentations](https://www.w3.org/TR/vc-data-model/#presentations) using an unlocked DID Document.

# Usage

Install the npm package:

```
npm i @digitalcredentials/sign-and-verify-core
OR
yarn add @digitalcredentials/sign-and-verify-core
```

and then use that issuer...

## Generating a new key pair

You can use the sample keypair that comes with sign-and-verify ([unlockedDID](data/unlocked-did:key.json)), but eventually you'll want to generate your own key pair, which you can do thusly:

```js
const {Ed25519VerificationKey2020} = require('@digitalbazaar/ed25519-verification-key-2020');
const generate = async function() {
    const edKeyPair = await Ed25519VerificationKey2020.generate({controller: 'did:web:credentials.mcmaster.ca'})
    const keys = await edKeyPair.export({publicKey: true, privateKey: true});
    console.log(JSON.stringify(keys, null, 2))
}
generate()
```

You can run this on the command line in an npm package with the @digitalbazaar/ed25519-verification-key-2020 library installed.

This produces a key pair, which should look something like this:

```
{
  id: 'did:web:credentials.mcmaster.ca#z6MkfcpjR3X7xJja2atED1E6meTTUjjTmKf7E2Kq2JFHK1Xp',
  type: 'Ed25519VerificationKey2020',
  controller: 'did:web:credentials.mcmaster.ca',
  publicKeyMultibase: 'z6MkfcpjR3X7xJja2atED1E6meTTUjjTmKf7E2Kq2JFHK1Xp',
  privateKeyMultibase: 'zruzggrR7q9cHFrzVmk7kHvDwo9vdtCQtXoUebGBDYYz3A6CdnLub4CYYMaKLB6X6LQTCix7m2tEJbYbUWjTN5yX8ZY'
}
```

Put it into the DID document to get something like this:

```json
{
	"@context": [
		"https://www.w3.org/ns/did/v1",
		"https://w3id.org/security/suites/ed25519-2020/v1"
	],
	"id": "did:web:digitalcredentials.mcmaster.ca",
	"assertionMethod": [{
  		"id": "did:web:credentials.mcmaster.ca#z6MkfcpjR3X7xJja2atED1E6meTTUjjTmKf7E2Kq2JFHK1Xp",
  		"type": "Ed25519VerificationKey2020",
  		"controller": "did:web:credentials.mcmaster.ca",
  		"publicKeyMultibase": "z6MkfcpjR3X7xJja2atED1E6meTTUjjTmKf7E2Kq2JFHK1Xp",
  		"privateKeyMultibase": "zruzggrR7q9cHFrzVmk7kHvDwo9vdtCQtXoUebGBDYYz3A6CdnLub4CYYMaKLB6X6LQTCix7m2tEJbYbUWjTN5yX8ZY"
	}]
}
```

Save this somewhere.  The Examples section explains how to use it.

NOTE:  IMPORTANT!  IMPORTANT! This DID Document contains the private key and so should NEVER be posted publicly (and should be kept secure as appropriate for your security requirements.)  This so-called 'unlocked' DID Document is only meant to be used locally with this library (because the library needs the private key to sign with). If you do end up wanting to post the DID publicly (like at the DID:WEB .well-known URI, e.g., http://credentials.mcmaster.ca/.well-known/did.json), first remove the private key, and post the rest:

```json
{
	"@context": [
		"https://www.w3.org/ns/did/v1",
		"https://w3id.org/security/suites/ed25519-2020/v1"
	],
	"id": "did:web:digitalcredentials.mcmaster.ca",
	"assertionMethod": [{
  		"id": "did:web:credentials.mcmaster.ca#z6MkfcpjR3X7xJja2atED1E6meTTUjjTmKf7E2Kq2JFHK1Xp",
  		"type": "Ed25519VerificationKey2020",
  		"controller": "did:web:credentials.mcmaster.ca",
  		"publicKeyMultibase": "z6MkfcpjR3X7xJja2atED1E6meTTUjjTmKf7E2Kq2JFHK1Xp"
	}]
}
```

## Examples

You can see a lot of this in [tests](src/issuer.spec.ts) - we just reproduce/re-organize it here to make it easier to understand if you are new to javascript, or to testing, or really just want to see the important parts without distractions. 

NOTE:  where we say 'presentation', we mean a [Verifiable Presentation](https://www.w3.org/TR/vc-data-model/#presentations)

NOTE:  where we say 'credential', we mean a [Verifiable Credential](https://www.w3.org/TR/vc-data-model/#credentials)

You'll need an unlocked DID document with which to sign (like this one: [unlockedDID](data/unlocked-did:key.json) or generate your own as explained above).

```js
import {createIssuer} from sign-and-verify-core;

// Load your unlocked DID from wherever you like.  For example, from the file system (if say you copied 
// data/unlocked-did:key.json from this repo to your project):

const unlockedDidDocument = JSON.parse(readFileSync("data/unlocked-did:key.json").toString("ascii"));

// create the issuer, passing in the unlocked DID document
const { sign, requestDemoCredential, verify, signPresentation, createAndSignPresentation, verifyPresentation } = createIssuer(unlockedDidDocument)

const sampleUnsignedCredential = {
	"@context": [
    "https://www.w3.org/2018/credentials/v1", 
    "https://www.w3.org/2018/credentials/examples/v1", 
    "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"
  ],
	"id": "http://example.gov/credentials/3732",
	"type": ["VerifiableCredential", "UniversityDegreeCredential"],
	"issuer": "did:web:digitalcredentials.github.io",
	"issuanceDate": "2020-03-10T04:24:12.164Z",
	"credentialSubject": {
		"id": "did:example:abcdef",
		"degree": {
			"type": "BachelorDegree",
			"name": "Bachelor of Science and Arts"
		}
	}
} 

const sampleSignedCredential = {
	"@context": [
    "https://www.w3.org/2018/credentials/v1", 
    "https://www.w3.org/2018/credentials/examples/v1", 
    "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"
  ],
	"id": "http://example.gov/credentials/3732",
	"type": ["VerifiableCredential", "UniversityDegreeCredential"],
	"issuer": "did:web:digitalcredentials.github.io",
	"issuanceDate": "2020-03-10T04:24:12.164Z",
	"credentialSubject": {
		"id": "did:example:me",
		"degree": {
			"type": "BachelorDegree",
			"name": "Bachelor of Science and Arts"
		}
	},
	"proof": {
		"type": "JsonWebSignature2020",
		"created": "2020-11-12T23:56:27.928Z",
		"jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..2DppQ4Euf9PUX6NrFPyJwHKPmeAqNWAC6UH8kiFNbsoiinebPpwdortHe-bLzDOQ_W7MQD5nqOnNN8JIVGarAA",
		"proofPurpose": "assertionMethod",
		"verificationMethod": "did:web:digitalcredentials.github.io#96K4BSIWAkhcclKssb8yTWMQSz4QzPWBy-JsAFlwoIs"
	}
}

const sampleUnsignedPresentation = {
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    'https://www.w3.org/2018/credentials/examples/v1',
    'https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json'
  ],
  type: [ 'VerifiablePresentation' ],
  id: '456',
  holder: 'did:web:digitalcredentials.github.io'
}


const sampleSignedPresentation = {
	"@context": [
    "https://www.w3.org/2018/credentials/v1", 
    "https://www.w3.org/2018/credentials/examples/v1", 
    "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"
  ],
	"type": ["VerifiablePresentation"],
	"id": "456",
	"holder": "did:web:digitalcredentials.github.io",
	"proof": {
		"type": "JsonWebSignature2020",
		"created": "2020-11-12T22:00:33.393Z",
		"challenge": "123",
		"jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..nuQE1vdLcf0YJSI_ojCdOpkQ53Amf4admAfA1eds9ONz9iskp5NBHqoz_YpzyRPxRvj4zblDDAhR524Dn4BtBA",
		"proofPurpose": "authentication",
		"verificationMethod": "did:web:digitalcredentials.github.io#96K4BSIWAkhcclKssb8yTWMQSz4QzPWBy-JsAFlwoIs"
	}
}

// NOTE that the property passed in through credentialOptions is called the verificationMethod, 
// but for this demo, which uses an [unlockedDID](data/unlocked-did:key.json) 
// it also identifies the signing key with which to sign credentials, I think just because the 
// the private key is packaged in together with the public key
const credentialOptions = {
  "verificationMethod": "did:web:digitalcredentials.github.io#96K4BSIWAkhcclKssb8yTWMQSz4QzPWBy-JsAFlwoIs",
}
// same as above for credentials, but also with a 'challenge':
const presentationOptions = {...credentialOptions, "challenge": "123"}

/* CREDENTIAL EXAMPLES */

// sign a credential
const result = sign(sampleUnsignedCredential, credentialOptions)

// verify a credential
const result = verify(sampleSignedCredential, credentialOptions)

// Request a demo credential, providing a signed presentation to prove DID ownership (control)
const result = requestDemoCredential(sampleSignedPresentation)


// Request a demo credential - without providing a full presentation to prove DID ownership.
// Instead, simply provide an object with a holder property where we'd expect one in a presentation,
// so kind of like a presentation stripped down to just the holder property.
const minimalPresentation = { holder: "did:example:me" }
const shouldSkipVerification = true
const result = requestDemoCredential(minimalPresentation, shouldSkipVerification)

/* PRESENTATION EXAMPLES */

// sign a provided but as yet unsigned presentation
const result = signPresentation(sampleUnsignedPresentation, presentationOptions)

// verify a presentation
// Note:  for fun and profit, you could also verify the signed presentation returned 
// from the 'signPresentation' step above
const result = verifyPresentation(sampleSignedPresentation, presentationOptions)

const presentationId = '456'
const holderDID = 'did:example:me';
// construct and sign a presentation that wraps a given signed credential
const result = createAndSignPresentation(sampleSignedCredential, presentationId, holderDID, presentationOptions);

// construct and sign a presentation, without providing an associated credential (hence the null argument)
const result = createAndSignPresentation(null, presentationId, holderDID, presentationOptions);
```

# References

You should be familiar with the [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/). Two key concepts are:

- [Verifiable Credential](https://www.w3.org/TR/vc-data-model/#credentials)
- [Verifiable Presentation](https://www.w3.org/TR/vc-data-model/#presentations)

# Development

To make changes to the package:

## Install

```
npm run install
```

## Build

```
npm run build
```

## Test

```
npm run test
```

## Publish to NPM

```
npm publish --access public
```

Before publishing, do make sure you are logged into npm on the command line, e.g., with 

```
npm adduser
```

Note that `npm publish --access public` will trigger the `prepublishOnly` script to first run the build
