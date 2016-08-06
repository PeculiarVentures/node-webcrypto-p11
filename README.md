# node-webcrypto-p11

[![license](https://img.shields.io/badge/license-MIT-green.svg?style=flat)](https://raw.githubusercontent.com/PeculiarVentures/node-webcrypto-p11/master/LICENSE)
[![Build Status](https://travis-ci.org/PeculiarVentures/node-webcrypto-p11.svg?branch=master)](https://travis-ci.org/PeculiarVentures/node-webcrypto-p11)
[![NPM version](https://badge.fury.io/js/node-webcrypto-p11.png)](http://badge.fury.io/node-webcrypto-p11)


We wanted to be able to write Javascript that used crypto on both the client and the server but we did not want to rely on Javascript implementations of crypto. The only native cryptography availible in browser is [Web Crypto](caniuse.com/#search=cryptography), this resulted in us creating a [native polyfil for WebCrypto based on Openssl](https://github.com/PeculiarVentures/node-webcrypto-ossl).

Our project also required us to utilize Hardware Security Modules and smart cards on the server side so we made a [library called Graphene that made it possible to use PKCS#11 devices from within Nodejs](https://github.com/PeculiarVentures/graphene). 

We then thought that in most cases others did not care about interacting with the token directly and would prefer a higher level API they were already familiar with. We hope that library is `node-webcrypto-p11`, if you have code based on WebCrypto (for example the excelent [js-jose](https://github.com/square/js-jose)) with only a change in a constructor you can work with PKCS#11 devices.

For example to generate a key you this is all it takes:

```
var config = {
    library: "/usr/local/lib/softhsm/libsofthsm2.so",
    name: "SoftHSM v2.0",
    slot: 0,
    sessionFlags: 4, // SERIAL_SESSION
    pin: "12345"
}

var WebCrypto = new WebCrypto(config);

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

### Install Dependencies
- typescript (TypeScript compiler)
- tsd (TypeScript Defenition compiler)
- mocha (test)

```
npm install typescript -g
npm install tsd -g
npm install mocha -g
```

### Install SoftHSM2

**NOTE**: SoftHSM2 is optional, the bellow steps assume Ubuntu

* Install SoftHSM2

    `apt-get install softhsm`

* Initialize the first slot

    `softhsm2-util --init-token --slot 0 --label "My token 1"`

* The PKCS1 #11 module you can now use can be found here:

  `/usr/local/lib/softhsm/libsofthsm.so`
  
* Adjust permissions so the user your code will be able to access the PKCS #11 module:

  ```
  sudo chmod –R 755 /var/lib/softhsm
  sudo chmod –R 755 /usr/local/lib/softhsm
  chown root:softhsmusers /var/lib/softhsm
  chown root:softhsmusers /usr/local/lib/softhsm
  ```
 
  **NOTE**: This may be more generous than needed. It works out to : 0755 = User:rwx Group:r-x World:r-x. 

### Install Graphene
```
cd node_modules
// Remove graphene-pk11
rm -rf graphene-pk11
// download and setup new version of graphene
git clone https://github.com/PeculiarVentures/graphene.git graphene-pk11
cd graphene-pk11
npm install
// Move to root
cd ../../
```

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

## Bug Reporting
Please report bugs either as pull requests or as issues in the issue tracker. Backwater has a full disclosure vulnerability policy. Please do NOT attempt to report any security vulnerability in this code privately to anybody.


## Related
 - [node-webcrypto-ossl](https://github.com/PeculiarVentures/node-webcrypto-ossl)
 - [MSR WebCrypto Polyfill](http://research.microsoft.com/en-us/downloads/29f9385d-da4c-479a-b2ea-2a7bb335d727/)
 - [Graphene](https://github.com/PeculiarVentures/graphene)
 - [WebCrypto Examples](https://github.com/diafygi/webcrypto-examples)
 - [OpenCryptoKi](https://sourceforge.net/projects/opencryptoki/)
 - [SoftHSM](https://github.com/opendnssec/SoftHSMv2)
