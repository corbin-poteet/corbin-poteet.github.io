import crypto from 'crypto';
import elliptic from 'elliptic';
import { ES256KSigner, hexToBytes } from 'did-jwt';
import { createJWT } from 'did-jwt';
import { decodeJWT } from 'did-jwt';
import { verifyJWT } from 'did-jwt';
import { Resolver } from 'did-resolver'
import { getResolver } from 'web-did-resolver'
import { createVerifiableCredentialJwt } from 'did-jwt-vc'
import { createVerifiablePresentationJwt } from 'did-jwt-vc'

// Request a 32 byte key
const size = parseInt(process.argv.slice(2)[0]) || 32;
const randomString = crypto.randomBytes(size).toString("hex");
// TEMP: Use a fixed key for testing
//const key = randomString;
const key = '8eb63d435de4d634bc5f3df79c361e9233f55c9c2fca097758eefb018c4c61df';
console.log(`Key (hex): ${key}\n`);

// Calculate the `secp256k1` curve and build the public key
const ec = new elliptic.ec('secp256k1');
const prv = ec.keyFromPrivate(key, 'hex');
const pub = prv.getPublic();


// Build the JWK
const kty = 'EC';
const crv = 'secp256k1';
const x = pub.x.toBuffer().toString('base64');
const y = pub.y.toBuffer().toString('base64');

const jwk = { kty, crv, x, y };
const publicKeyJwk = JSON.stringify(jwk, null, 2);

console.log(publicKeyJwk);


// Create the DID:WEB
const prefix = 'did:web:';
const url = 'skounis.github.io';
const suffix = '/.wellknown/did.json';

const id = `${prefix}${url}`;
const didUrl = `https://${url}${suffix}`;

// Create the JWT
const signer = ES256KSigner(hexToBytes(key));
const jwt = await createJWT(
  { aud: id, name: 'Bob Smith' },
  { issuer: id, signer },
  { alg: 'ES256K' }
)
const decodedJwt = decodeJWT(jwt)
console.log('JWT Decoded:\n', decodedJwt)

// TODO: Create the DID Document 
// TODO: Host the DID Document at didUrl

// Verify the JWT
const webResolver = getResolver()
const resolver = new Resolver({
  ...webResolver
})
verifyJWT(jwt, {
  resolver,
  audience: id
}).then(({ payload, doc, did, signer, jwt }) => {
  console.log('Verified:\n', payload)
})


// CREATE VERIFIABLE CREDENTIAL
// https://www.w3.org/TR/vc-data-model/#dfn-verifiable-credentials
// A verifiable credential is a tamper-proof credential that can be cryptographically verified. 
// credentialSubject == service? 
// https://www.w3.org/TR/vc-data-model/#credential-subject
// https://keybase.io/max/sigchain#9f731fa7c75b64e1c9d70300b4383196a8fb432294a4308f8d7a379376a0b1900f
// Replace 'degree' with: ?
// service: {
//   name: 'github',
//   username: 'maxtaco',
// }
// issuanceDate == ctime?
// https://www.w3.org/TR/vc-data-model/#issuance-date

// Payload
const vcPayload = {
  sub: id,
  nbf: 1562950282,
  vc: {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiableCredential'],
    credentialSubject: {
      degree: {
        type: 'BachelorDegree',
        name: 'Baccalauréat en musiques numériques'
      }
    }
  }
}

const issuer = {
  did: id,
  signer: signer
}

const vcJwt = await createVerifiableCredentialJwt(vcPayload, issuer) //the verifiable credential in the form of a JWT
console.log(`Verifiable Credential JWT:\n${vcJwt}`)

// CREATE VERIFIABLE PRESENTATION
// https://www.w3.org/TR/vc-data-model/#dfn-presentations
// A verifiable presentation is a tamper-proof presentation encoded in such a way that authorshop of the data can be trusted after a process of cryptographic verification.
// https://www.ubisecure.com/identity-management/verifiable-credentials-understanding-key-principles/#:~:text=Verifiable%20Presentation%20(VP)%20is%20a,verify%20the%20integrity%20of%20presentation.
// Is a collection of verifiable credentials
const vpPayload = {
  vp: {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiablePresentation'],
    verifiableCredential: [vcJwt],
    foo: "bar"
  }
}

const vpJwt = await createVerifiablePresentationJwt(vpPayload, issuer)
console.log(`Verifiable Presentation JWT:\n${vpJwt}`)