# node-webcrypto-p11
A WebCrypto Polyfill for Node in typescript built on Graphene

# Installation

## Clone Repo

```
git clone https://github.com/PeculiarVentures/node-webcrypto-p11
cd node-webcrypto-p11
```

## Dependencies
- typescript (TypeScript compiler)
- tsd (TypeScript Defenition compiler)
- mocha (test)

```
npm install typescript -g
npm install tsd -g
npm install mocha -g
```

## SoftHSM (optional)
- Get and install SoftHSM

    `apt-get install softhsm`

- Specify where your configuration file is

    `export SOFTHSM2_CONF=/etc/softhsm/softhsm.conf`

- Fix the configuation file to specify correct path to it's db

    `%s:/lib\/lib/lib`

- Initialize the first slot

    `softhsm2-util --init-token --slot 0 --label "My token 1"`

- The pkcs11 module you can now use can be found here:

  `/usr/lib/softhsm/libsofthsm.so`
  

## Install & Compile 

```
npm install
```

* If you experience any errors make sure you have downloaded TypeScript dependencies

```
tsd install
tsc
```


# Test

```
mocha
```


### Related
 - [node-webcrypto-ossl](https://github.com/PeculiarVentures/node-webcrypto-ossl)
 - [MSR WebCrypto Polyfill](http://research.microsoft.com/en-us/downloads/29f9385d-da4c-479a-b2ea-2a7bb335d727/)
 - [Graphene](https://github.com/PeculiarVentures/graphene)
 - [WebCrypto Examples](https://github.com/diafygi/webcrypto-examples)
