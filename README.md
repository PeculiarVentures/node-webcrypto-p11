# node-webcrypto-p11

[![license](https://img.shields.io/badge/license-MIT-green.svg?style=flat)](https://raw.githubusercontent.com/PeculiarVentures/node-webcrypto-p11/master/LICENSE)
[![Build Status](https://travis-ci.org/PeculiarVentures/node-webcrypto-p11.svg?branch=master)](https://travis-ci.org/PeculiarVentures/node-webcrypto-p11)
[![Coverage Status](https://coveralls.io/repos/github/PeculiarVentures/node-webcrypto-p11/badge.svg?branch=master)](https://coveralls.io/github/PeculiarVentures/node-webcrypto-p11?branch=master)
[![NPM version](https://badge.fury.io/js/node-webcrypto-p11.png)](http://badge.fury.io/node-webcrypto-p11)

[![NPM](https://nodei.co/npm-dl/node-webcrypto-p11.png?months=2&height=2)](https://nodei.co/npm/node-webcrypto-p11/)

We wanted to be able to write Javascript that used crypto on both the client and the server but we did not want to rely on Javascript implementations of crypto. The only native cryptography availible in browser is [Web Crypto](caniuse.com/#search=cryptography), this resulted in us creating a [native polyfil for WebCrypto based on Openssl](https://github.com/PeculiarVentures/node-webcrypto-ossl).

Our project also required us to utilize Hardware Security Modules and smart cards on the server side so we made a [library called Graphene that made it possible to use PKCS#11 devices from within Nodejs](https://github.com/PeculiarVentures/graphene). 

We then thought that in most cases others did not care about interacting with the token directly and would prefer a higher level API they were already familiar with. We hope that library is `node-webcrypto-p11`, if you have code based on WebCrypto (for example the excelent [js-jose](https://github.com/square/js-jose)) with only a change in a constructor you can work with PKCS#11 devices.

For example to generate a key you this is all it takes:

```javascript
var config = {
    library: "/usr/local/lib/softhsm/libsofthsm2.so",
    name: "SoftHSM v2.0",
    slot: 0,
    sessionFlags: 4, // SERIAL_SESSION
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

## Table Of Contents

* [WARNING](#warning)
* [Installing](#installing)
  * [Clone Repo](#clone-repo)
  * [Install Dependencies](#install-dependencies)
  * [Install SoftHSM2](#install-softhsm2)
  * [Install Graphene](#install-graphene)
  * [Install](#install)
  * [Test](#test)
* [Threat Model](#threat-model)
  * [Assumptions](#assumptions)
  * [Threats From A node-webcrypto-p11 Defect](#threats-from-a-node-webcrypto-p11-defect)
  * [Threats From A HSM Defect](#threats-from-a-hsm-defect)
  * [Threats From Weak Cryptography](#threats-from-weak-cryptography)
  * [Threats From Improper Use Of Cryptography](#threats-from-improper-use-of-cryptography)
* [Bug Reporting](#bug-reporting)
* [Related](#related)

## WARNING

**At this time this solution should be considered suitable for research and experimentation, further code and security review is needed before utilization in a production application.**

## Installation

### Clone Repo

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
Use [config.js](https://github.com/PeculiarVentures/node-webcrypto-p11/blob/master/test/config.js) file for PKCS11 module configuration

config.js file format:
```
module.exports = {
	library: "path/to/pkcs11/module.so",
	name: "Name of PKCS11 module",
    slot: 0,        // number of slot
	pin: "password"
    slotFlags: 4,   // open session flags, optional. Default SERIAL_SESSION(4)
    vendors: []     // list of vendor files, optional
}
```

The threat model is defined in terms of what each possible attacker can achieve. The list is intended to be exhaustive.

### Assumptions

TODO: ADD ASSUMPTIONS

### Threats From A node-webcrypto-p11 Defect

TODO: ADD THREATS FROM A node-webcrypto-p11 DEFECT

### Threats From A HSM Defect

TODO: ADD THREATS FROM A HSM DEFECT

### Threats From Weak Cryptography

TODO: ADD THREATS FROM WEAK CRYPTOGRAPHY

### Threats From Improper Use Of Cryptography

TODO: ADD THREATS FOR IMPROPER USE OF CRYPTOGRAPHY

## Using

### Provider

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
        console.log("token:", tokens > info.providers.length ? "removed" : "inserted");
        console.log(`Providers: ${info.providers.length}`);
        tokens = info.providers.length;
    })
    .on("error", (e) => {
        console.error(e);
    })

provider.open();
```

### Crypto

Example: Generates `ECDSA` key pair with named curve `P-256` and signs/verifies text message.

```javascript
var wcp11 = require("node-webcrypto-p11");

var config = {
    library: "/usr/local/lib/softhsm/libsofthsm2.so",
    name: "SoftHSM v2.0",
    slot: 0,
    sessionFlags: 4, // SERIAL_SESSION
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
