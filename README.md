# node-webcrypto-p11
A WebCrypto Polyfill for Node in typescript built on Graphene

## Installation

### Clone Repo

```
git clone https://github.com/PeculiarVentures/node-webcrypto-p11
cd node-webcrypto-p11
```

### Dependencies
- typescript (TypeScript compiler)
- tsd (TypeScript Defenition compiler)
- mocha (test)

```
npm install typescript -g
npm install tsd -g
npm install mocha -g
```

### SoftHSM2 (assumes Ubuntu - optional)
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
  

### Install 

```                          
nom install
```

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

### Related
 - [node-webcrypto-ossl](https://github.com/PeculiarVentures/node-webcrypto-ossl)
 - [MSR WebCrypto Polyfill](http://research.microsoft.com/en-us/downloads/29f9385d-da4c-479a-b2ea-2a7bb335d727/)
 - [Graphene](https://github.com/PeculiarVentures/graphene)
 - [WebCrypto Examples](https://github.com/diafygi/webcrypto-examples)
