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
  

### Install & Compile 

```
npm install
tsd install
tsc
```

> If you experience any errors make sure you have downloaded TypeScript dependencies


### Test

```
mocha
```


### Related
 - [node-webcrypto-ossl](https://github.com/PeculiarVentures/node-webcrypto-ossl)
 - [MSR WebCrypto Polyfill](http://research.microsoft.com/en-us/downloads/29f9385d-da4c-479a-b2ea-2a7bb335d727/)
 - [Graphene](https://github.com/PeculiarVentures/graphene)
 - [WebCrypto Examples](https://github.com/diafygi/webcrypto-examples)
