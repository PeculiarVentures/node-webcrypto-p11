# node-webcrypto-p11

[![license](https://img.shields.io/badge/license-MIT-green.svg?style=flat)](https://raw.githubusercontent.com/PeculiarVentures/node-webcrypto-p11/master/LICENSE)
[![CircleCI](https://circleci.com/gh/PeculiarVentures/node-webcrypto-p11/tree/master.svg?style=svg)](https://circleci.com/gh/PeculiarVentures/node-webcrypto-p11/tree/master)
[![Coverage Status](https://coveralls.io/repos/github/PeculiarVentures/node-webcrypto-p11/badge.svg?branch=master)](https://coveralls.io/github/PeculiarVentures/node-webcrypto-p11?branch=master)
[![npm version](https://badge.fury.io/js/node-webcrypto-p11.svg)](https://badge.fury.io/js/node-webcrypto-p11)

[![NPM](https://nodei.co/npm/node-webcrypto-p11.png)](https://nodei.co/npm/node-webcrypto-p11/)

We wanted to be able to write Javascript that used crypto on both the client and the server but we did not want to rely on Javascript implementations of crypto. The only native cryptography availible in browser is [Web Crypto](caniuse.com/#search=cryptography), this resulted in us creating a [native polyfil for WebCrypto based on Openssl](https://github.com/PeculiarVentures/node-webcrypto-ossl).

Our project also required us to utilize Hardware Security Modules and smart cards on the server side so we made a [library called Graphene that made it possible to use PKCS#11 devices from within Nodejs](https://github.com/PeculiarVentures/graphene). 

We then thought that in most cases others did not care about interacting with the token directly and would prefer a higher level API they were already familiar with. We hope that library is `node-webcrypto-p11`, if you have code based on WebCrypto (for example the excelent [js-jose](https://github.com/square/js-jose)) with only a change in a constructor you can work with PKCS#11 devices.

For example to generate a key you this is all it takes:

```js
const { Crypto } = require("node-webcrypto-p11");
const config = {
    library: "/usr/local/lib/softhsm/libsofthsm2.so",
    name: "SoftHSM v2.0",
    slot: 0,
    readWrite: true,
    pin: "12345"
};

const crypto = new Crypto(config);

const keys = await crypto.subtle.generateKey({
  name:"RSASSA-PKCS1-v1_5",
  modulusLength: 1024,
  publicExponent: new Uint8Array([1, 0, 1]), 
  hash: {
      name: "SHA-1"
  }}, 
  true, 
  ["sign", "verify"]
);
```

## WARNING

**At this time this solution should be considered suitable for research and experimentation, further code and security review is needed before utilization in a production application.**

## Algorithms

## Supported algorithms

| Algorithm name    | generateKey | digest  | export/import | sign/verify | encrypt/decrypt | wrapKey/unwrapKey | derive  |
|-------------------|-------------|---------|---------------|-------------|-----------------|-------------------|---------|
| SHA-1             |             |    X    |               |             |                 |                   |         |
| SHA-256           |             |    X    |               |             |                 |                   |         |
| SHA-384           |             |    X    |               |             |                 |                   |         |
| SHA-512           |             |    X    |               |             |                 |                   |         |
| RSASSA-PKCS1-v1_5 |      X      |         |       X       |      X      |                 |                   |         |
| RSA-PSS           |      X      |         |       X       |      X      |                 |                   |         |
| RSA-OAEP          |      X      |         |       X       |             |        X        |         X         |         |
| AES-CBC           |      X      |         |       X       |             |        X        |         X         |         |
| AES-ECB <sub>2</sub>|      X      |         |       X       |             |        X        |         X         |         |
| AES-GCM           |      X      |         |       X       |             |        X        |         X         |         |
| ECDSA <sub>1</sub>|      X      |         |       X       |      X      |                 |                   |         |
| ECDH <sub>2</sub> |      X      |         |       X       |             |                 |                   |    X    |
| HMAC              |      X      |         |       X       |      X      |                 |                   |         |

<sup>1</sup> Mechanism supports extended list of named curves `P-256`, `P-384`, `P-521`, and `K-256`

<sup>2</sup> Mechanism is not defined by the WebCrypto specifications. Use of mechanism in a safe way is hard, it was added for the purpose of enabling interoperability with an existing system. We recommend against its use unless needed for interoperability.

## Installation

### NPM

```
npm install node-webcrypto-p11
```

### Clone Repository

```
git clone https://github.com/PeculiarVentures/node-webcrypto-p11
cd node-webcrypto-p11
```

### Install SoftHSM2

- For OSX see the [instructions here](https://github.com/opendnssec/SoftHSMv2/blob/develop/OSX-NOTES.md)
- For linux [instructions here](https://github.com/opendnssec/SoftHSMv2/blob/develop/README.md)

 
### Install 

```                          
npm install
```

### Test

```
mocha
```

### Configuration

Tests and samples use a file called [config.js](https://github.com/PeculiarVentures/node-webcrypto-p11/blob/master/test/config.js) file for PKCS11 module configuration. The format of which is:

```js
module.exports = {
    library: "path/to/pkcs11/module.so",
    name: "Name of PKCS11 module",
    slot: 0,        // number of slot
    pin: "password"
    readWrite: true,
    vendors: []     // list of vendor files, optional
}
```

## Threats
The threat model is defined in terms of what each possible attacker can achieve. The list is intended to be exhaustive.

### Assumptions
TODO: ADD ASSUMPTIONS

### Threats From A node-webcrypto-p11 Defect
`node-webcrypto-p11` handles ciphertext, cleartext, and sessions. A defect in this library could result in these values being exposed to an attacker. Examples of such defects include:
- Buffer, Integer or other overflow related defects,
- Parsing errors,
- Logic errors,
- Weak user seperation or permissions.

### Threats From A PKCS#11 defect
PKCS#11 implementations are often old, poorly maintained and incomplete. This can obviously lead to defects. Defects in the PKCS#11 implementation can result in:
- Weakly implemented or applied cryptographic primitives,
- Leaked sessions or secrets that expose use of the key,
- Leaked cryptographic key material.

### Threats From Weak Cryptography
Secure use of cryptography requires the implementor to understand the security properties of a given algorithm as well as how to use it in a secure construction.

Additionally this library exposes some algorithms that may have known weakneses or are simply too old to be used safely.

### Threats From Improper Use Of Cryptography
It is easy to apply cryptography but hard to apply it correctly. Algorithms each have their own security properties and appropriate constructions. The consumer of this library is responsible for understanding how to use the exposed algorithms securely.

### Generates `ECDSA` key pair with named curve `P-256` and signs/verifies text message.

```js
const { Crypto } = require("node-webcrypto-p11");

const config = {
    library: "/usr/local/lib/softhsm/libsofthsm2.so",
    name: "SoftHSM v2.0",
    slot: 0,
    readWrite: true,
    pin: "12345"
}

const crypto = new Crypto(config);

const keys = await crypto.subtle.generateKey({name: "ECDSA", namedCurve: "P-256"}, false, ["sign", "verify"]);
const signature = await crypto.subtle.sign({name: "ECDSA", hash: "SHA-256"}, keys.privateKey, Buffer.from("Hello world!"));
console.log(`Signature: ${signature}`);
const ok = await crypto.subtle.verify({name: "ECDSA", hash: "SHA-256"}, keys.publicKey, signature, Buffer.from("Hello world!"));
console.log(`Verification: ${ok}`);
```

## Key Storage
The [CryptoKeyStorage](https://github.com/PeculiarVentures/webcrypto-docs/blob/master/KEY_STORAGE.md#cryptokeystorage) interface enables you to persist and retrieve keys across sessions.

### Generate a cryptographic key and store it

```js
const keys = await crypto.subtle.generateKey({name: "ECDSA", namedCurve: "P-256"}, false, ["sign", "verify"]);
// set private key to storage
const privateKeyID = await crypto.keyStorage.setItem(keys.privateKey);
// set public key to storage
const publicKeyID = await crypto.keyStorage.setItem(keys.publicKey);
// get list of keys
const indexes = await crypto.keyStorage.keys();
console.log(indexes); // ['private-3239...', 'public-3239...']
// get key by id
const privateKey = await crypto.keyStorage.getItem("private-3239...");
// signing data
const signature = await crypto.subtle.sign({name: "ECDSA", hash: "SHA-256"}, key, Buffer.from("Message here"));
console.log("Signature:", Buffer.from(signature).toString("hex"));
```

## Certificate Storage
The [CryptoCertificateStorage](https://github.com/PeculiarVentures/webcrypto-docs/blob/master/CERT_STORAGE.md#cryptocertstorage) interface enables you to persist and retrieve certificates across sessions.

### Add certificate to storage and use it for verification of signed data

```javascript
const X509_RAW = Buffer.from("308203A830820290A003020...", "hex")

const x509 = await crypto.certStorage.importCert("raw", X509_RAW, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, ["verify"]);
console.log(x509.subjectName); // C=name, O=...
const index = await crypto.certStorage.setItem(x509)
console.log(index); // x509-2943...
const ok = await crypto.subtle.verify({name: "RSASSA-PKCS1-v1_5"}, x509.publicKey, SIGNATURE, MESSAGE);
console.log("Signature:", ok);
```

## Bug Reporting
Please report bugs either as pull requests or as issues in the issue tracker. Backwater has a full disclosure vulnerability policy. Please do NOT attempt to report any security vulnerability in this code privately to anybody.


## Related 
 - [webcrypto](https://github.com/PeculiarVentures/webcrypto)
 - [node-webcrypto-ossl](https://github.com/PeculiarVentures/node-webcrypto-ossl)
 - [webcrypto-liner](https://github.com/PeculiarVentures/webcrypto-liner)
 - [WebCrypto Examples](https://github.com/PeculiarVentures/webcrypto-docs#webcrypto)
 - [Graphene](https://github.com/PeculiarVentures/graphene)
 - [pkcs11js](https://github.com/PeculiarVentures/pkcs11js)
 - [OpenCryptoKi](https://sourceforge.net/projects/opencryptoki/)
 - [SoftHSM](https://github.com/opendnssec/SoftHSMv2)
