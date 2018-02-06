# node-webcrypto-p11

[![license](https://img.shields.io/badge/license-MIT-green.svg?style=flat)](https://raw.githubusercontent.com/PeculiarVentures/node-webcrypto-p11/master/LICENSE)
[![Build Status](https://travis-ci.org/PeculiarVentures/node-webcrypto-p11.svg?branch=master)](https://travis-ci.org/PeculiarVentures/node-webcrypto-p11)
[![Coverage Status](https://coveralls.io/repos/github/PeculiarVentures/node-webcrypto-p11/badge.svg?branch=master)](https://coveralls.io/github/PeculiarVentures/node-webcrypto-p11?branch=master)
[![npm version](https://badge.fury.io/js/node-webcrypto-p11.svg)](https://badge.fury.io/js/node-webcrypto-p11)

[![NPM](https://nodei.co/npm/node-webcrypto-p11.png)](https://nodei.co/npm/node-webcrypto-p11/)

We wanted to be able to write Javascript that used crypto on both the client and the server but we did not want to rely on Javascript implementations of crypto. The only native cryptography availible in browser is [Web Crypto](caniuse.com/#search=cryptography), this resulted in us creating a [native polyfil for WebCrypto based on Openssl](https://github.com/PeculiarVentures/node-webcrypto-ossl).

Our project also required us to utilize Hardware Security Modules and smart cards on the server side so we made a [library called Graphene that made it possible to use PKCS#11 devices from within Nodejs](https://github.com/PeculiarVentures/graphene). 

We then thought that in most cases others did not care about interacting with the token directly and would prefer a higher level API they were already familiar with. We hope that library is `node-webcrypto-p11`, if you have code based on WebCrypto (for example the excelent [js-jose](https://github.com/square/js-jose)) with only a change in a constructor you can work with PKCS#11 devices.

For example to generate a key you this is all it takes:

```javascript
var config = {
    library: "/usr/local/lib/softhsm/libsofthsm2.so",
    name: "SoftHSM v2.0",
    slot: 0,
    readWrite: true,
    pin: "12345"
}

var webcrypto = new WebCrypto(config);

webcrypto.subtle.generateKey({
        name:"RSASSA-PKCS1-v1_5",
        modulusLength: 1024,
        publicExponent: new Uint8Array([1, 0, 1]), 
        hash: {
            name: "SHA-1"
        }}, 
        true, 
        ["sign", "verify"]
    )
    .then(function(keys){
        assert.equal(!!keys.privateKey, true, "Has no private key");
        assert.equal(!!keys.publicKey, true, "Has no public key");
        assert.equal(keys.privateKey.extractable, true);
    })
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
| AES-ECB <sub>2</sub> |      X      |         |       X       |             |        X        |         X         |         |
| AES-GCM           |      X      |         |       X       |             |        X        |         X         |         |
| AES-KW            |      X      |         |       X       |             |                 |         X         |         |
| ECDSA             |      X      |         |       X       |      X      |                 |                   |         |
| ECDH              |      X      |         |       X       |             |                 |                   |    X    |
| HMAC              |      X      |         |       X       |      X      |                 |                   |         |
| PBKDF2            |             |         |       X       |             |                 |                   |    X    |

<sub>2 ECB support is not defined by the WebCrypto specifications. Use of EBC in a safe way is hard, it was added for the purpose of enabling interoperability with an existing system. We recommend against its use unless needed for interoperability.</sub>

## Elliptic curve secp256k1

`secp256k1` curve is not defined by the WebCrypto specifications. This module implements `K-256` curve for ECDSA algorithm.

[K-256 curve examples](https://github.com/PeculiarVentures/webcrypto-core/blob/master/spec/EC_K_256.md)

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

```javascript
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
- Leaked sessions or secreats that expose use of the key,
- Leaked cryptographic key material.

### Threats From Weak Cryptography
Secure use of cryptography requires the implementor to understand the security properties of a given algorithm as well as how to use it in a secure construction.

Additionally this library exposes some algorithms that may have known weakneses or are simply too old to be used safely.

### Threats From Improper Use Of Cryptography
It is easy to apply cryptography but hard to apply it correctly. Algorithms each have their own security properties and appropriate constructions. The consumer of this library is responsible for understanding how to use the exposed algorithms securely.



## Using

### Initializing with a specific PKCS#11 implementation.

```javascript
var wcp11 = require("node-webcrypto-p11");
const provider = new wcp11.Provider("path/to/pkcs11.so");

let tokens = 0;
provider
    .on("listening", (info) => {
        console.log("listening");
        console.log(info);
        console.log(`Providers: ${info.providers.length}`);

        tokens = info.providers.length;
    })
    .on("token", (info) => {
        console.log("Removed:", info.removed);
        console.log("Added:", info.added);
    })
    .on("error", (e) => {
        console.error(e);
    })

provider.open();
```

### Generates `ECDSA` key pair with named curve `P-256` and signs/verifies text message.

```javascript
var wcp11 = require("node-webcrypto-p11");

var config = {
    library: "/usr/local/lib/softhsm/libsofthsm2.so",
    name: "SoftHSM v2.0",
    slot: 0,
    readWrite: true,
    pin: "12345"
}

var crypto = new wcp11.WebCrypto(config);

crypto.subtle.generateKey({name: "ECDSA", namedCurve: "P-256"}, false, ["sign", "verify"])
    .then((keys) => {
        return crypto.subtle.sign({name: "ECDSA", hash: "SHA-256"}, keys.privateKey, new Buffer("Hello world!"))
            .then((signature) => {
                console.log(`Signature: ${signature}`);
                return crypto.subtle.verify({name: "ECDSA", hash: "SHA-256"}, keys.publicKey, signature, new Buffer("Hello world!"))
            })
            .then((ok) => {
                console.log(`Verification: ${ok}`);
            });
    })
    .catch((err) => {
        console.error(err);
    });
```

## Provider

The `Provider` interface enables you to get information about a PKCS#11 module and watch token removal/insertion.

### Interface

```typescript

interface IProvider {
    id: string;
    name: string;
    serialNumber: string;
    algorithms: string[];
}

interface IModule {
    name: string;
    providers: IProvider[];
}

type ProviderTokenHandler = (info: { removed: IProvider[], added: IProvider[] }) => void;
type ProviderListeningHandler = (info: IModule) => void;
type ProviderErrorHandler = (e: Error) => void;
type ProviderStopHandler = () => void;

interface Provider extends EventEmitter {

    readonly library: string;

    /**
     * Creates an instance of Provider.
     */
    new(lib: string);

    public on(event: "stop", listener: ProviderStopHandler): this;
    public on(event: "listening", listener: ProviderListeningHandler): this;
    public on(event: "token", listener: ProviderTokenHandler): this;
    public on(event: "error", listener: ProviderErrorHandler): this;

    public once(event: "stop", listener: ProviderStopHandler): this;
    public once(event: "listening", listener: ProviderListeningHandler): this;
    public once(event: "token", listener: ProviderTokenHandler): this;
    public once(event: "error", listener: ProviderErrorHandler): this;

    public open(watch?: boolean): void;
    public stop(): void;

}
```

## Key Storage
The `Key Storage` interface enables you to persist and retrieve keys accross sessions.

### Interface

#### KeyStorage

```typescript
interface IKeyStorage {

    /**
     * Return list of names of stored keys
     */
    keys(): Promise<string[]>;
    /**
     * Returns identity of item from storage.
     * If item is not found, then returns `null`
     */
    indexOf(item: CryptoKey): Promise<string | null>;
    /**
     * Returns key from storage
     */
    getItem(key: string): Promise<CryptoKey>;
    getItem(key: string, algorithm: Algorithm, usages: string[]): Promise<CryptoKey>;
    /**
     * Add key to storage
     */
    setItem(value: CryptoKey): Promise<string>;
    /**
     * Removes item from storage by given key
     */
    removeItem(key: string): Promise<void>;
    /**
     * Removes all keys from storage
     */
    clear(): Promise<void>

}
```

### Generate a cryptographic key and store it

```javascript
crypto.subtle.generateKey({name: "ECDSA", namedCurve: "P-256"}, false, ["sign", "verify"])
    .then((keys) => {
        // set private key to storage
        return crypto.keyStorage.setItem(keys.privateKey)
            .then((privateKeyID) => {
                // set public key to storage
                return crypto.keyStorage.setItem(keys.publicKey);
            })
            .then((publicKeyID) => {
                // get list of keys
                return crypto.keyStorage.keys();
            })
    })
    .then((indexes) => {
        console.log(indexes); // ['private-3239...', 'public-3239...']
        // get key by id
        return crypto.keyStorage.getItem("private-3239...");
    })
    .then((key) => {
        // signing data
        return crypto.subtle.sign({name: "ECDSA", hash: "SHA-256"}, key, new Buffer("Message here"));
            .then((signature) => {
                console.log("Signature:", new Buffer(signature).toString("hex"));
            })
    })
    .catch((err) => {
        console.error(err);
    });
```

## Certificate Storage
The `Certificate Storage` interface enables you to persist and retrieve certificates accross sessions.

### Interfaces
#### CryptoCertificate

```typescript
type HexString = string;

type CryptoCertificateType = string | "x509" | "request";

interface CryptoCertificate {
    type: CryptoCertificateType;
    publicKey: CryptoKey;
}

interface CryptoX509Certificate extends CryptoCertificate {
    notBefore: Date;
    notAfter: Date;
    serialNumber: HexString;
    issuerName: string;
    subjectName: string;
}

interface CryptoX509CertificateRequest extends CryptoCertificate {
    subjectName: string;
}
```

#### CertificateStorage

```typescript
interface ICertificateStorage {
    /**
     * Returns list of indexes of stored items
     */
    keys(): Promise<string[]>;
    /**
     * Returns identity of item from storage.
     * If item is not found, then returns `null`
     */
    indexOf(item: CryptoCertificate): Promise<string | null>;
    /**
     * Import certificate from data
     */
    importCert(type: CryptoCertificateType, data: BufferSource, algorithm: Algorithm, keyUsages: string[]): Promise<CryptoCertificate>;
    /**
     * Exports item in given format
     */
    exportCert(format: "pem" | "raw", cert: CryptoCertificate): Promise<ArrayBuffer | string>;
    /**
     * Adds item to storage and returns it's identity
     */
    setItem(item: CryptoCertificate): Promise<string>;
    /**
     * Returns item by identity
     */
    getItem(key: string): Promise<CryptoCertificate>;
    getItem(key: string, algorithm: Algorithm, usages: string[]): Promise<CryptoCertificate>;
    /**
     * Removes item by identity
     */
    removeItem(key: string): Promise<void>;
    /**
     * Removes all items from storage
     */
    clear(): Promise<void>;
}
```

### Add certificate to storage and use it for verification of signed data

```javascript
const X509_RAW = new Buffer("308203A830820290A003020...", "hex")

crypto.certStorage.importCert("x509", X509_RAW, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, ["verify"])
    .then((x509) => {
        console.log(x509.subjectName); // C=name, O=...
        return crypto.certStorage.setItem(x509)
            .then((index) => {
                console.log(index); // x509-2943...
            })
    })
    .then(() => {
        return crypto.subtle.verify({name: "RSASSA-PKCS1-v1_5"}, SIGNATURE, MESSAGE);
    })
    .then((ok) => {
        console.log("Signature:", ok);
    })
    .catch((err) => {
        console.error(err);
    })
```

## Bug Reporting
Please report bugs either as pull requests or as issues in the issue tracker. Backwater has a full disclosure vulnerability policy. Please do NOT attempt to report any security vulnerability in this code privately to anybody.


## Related 
 - [node-webcrypto-ossl](https://github.com/PeculiarVentures/node-webcrypto-ossl)
 - [webcrypto-liner](https://github.com/PeculiarVentures/webcrypto-liner)
 - [WebCrypto Examples](https://github.com/diafygi/webcrypto-examples)
 - [Graphene](https://github.com/PeculiarVentures/graphene)
 - [pkcs11js](https://github.com/PeculiarVentures/pkcs11js)
 - [OpenCryptoKi](https://sourceforge.net/projects/opencryptoki/)
 - [SoftHSM](https://github.com/opendnssec/SoftHSMv2)
