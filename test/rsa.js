var assert = require('assert');
var config = require('./config');
var crypto = require("../built/webcrypto.js");
var WebCrypto = crypto.WebCrypto;

describe("RSA", function () {
    var webcrypto;
    
    function s2ab(text) {
        var uint = new Uint8Array(text.length);
        for (var i = 0, j = text.length; i < j; ++i) {
            uint[i] = text.charCodeAt(i);
        }
        return uint;
    }
    
    var TEST_MESSAGE = s2ab("1234567890123456");

    before(function (done) {
        webcrypto = new WebCrypto(config);
        assert.equal(!!webcrypto, true, "WebCrypto is not initialized");
        done();
    })
    
    after(function (done) {
        webcrypto.close();
        done();
    })
    
    it("RSA generate", function (done) {
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
        .then(done, done);
    })

    it("RSA PKCS1 JWK export/import", function (done) {
        var key = null;
        webcrypto.subtle.generateKey(
            {
                name: "RSASSA-PKCS1-v1_5",
                modulusLength: 1024,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: {
                        name: "SHA-256"
                    }
            },
            true,
            ["sign", "verify"]
        )
        .then(function(k) {
            assert.equal(k.privateKey !== null, true, "Has no private key");
            assert.equal(k.publicKey !== null, true, "Has no public key");
            key = k;
            return webcrypto.subtle.exportKey("jwk", key.privateKey)
        })
        .then(function(jwk) {
            assert.equal(!!jwk, true);
            assert.equal(jwk.kty, "RSA");
            assert.equal(!!jwk.e, true);
            assert.equal(!!jwk.n, true);
            assert.equal(!!jwk.d, true);
            assert.equal(!!jwk.q, true);
            assert.equal(!!jwk.p, true);
            assert.equal(!!jwk.p, true);
            assert.equal(!!jwk.dp, true);
            assert.equal(!!jwk.dq, true);
            assert.equal(!!jwk.qi, true);
            return webcrypto.subtle.importKey(
                "jwk", //can be "jwk" (public or private), "spki" (public only), or "pkcs8" (private only)
                jwk,
                {   //these are the algorithm options
                    name: "RSASSA-PKCS1-v1_5",
                    hash: { name: "SHA-256" }, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
                },
                false, //whether the key is extractable (i.e. can be used in exportKey)
                ["sign"] //"verify" for public key import, "sign" for private key imports
            )
        })
        .then(function(key) {
            assert.equal(!!key, true);
            assert.equal(key.usages.length, 1);
        })
        .then(done, done);    
    });
    
    it("RSA PKCS1 1.5 sign/verify", function (done) {
        var key = null;
		webcrypto.subtle.generateKey({
            name:"RSASSA-PKCS1-v1_5",
            modulusLength: 1024,
            publicExponent: new Uint8Array([1, 0, 1]), 
            hash: {
                name: "SHA-1"
            }}, 
            false, 
            ["sign", "verify"]
        )
        .then(function(k){
            assert.equal(k.privateKey !== null, true, "Has no private key");
            assert.equal(k.publicKey !== null, true, "Has no public key");
            key = k;
            return webcrypto.subtle.sign({name: "RSASSA-PKCS1-v1_5"}, key.privateKey, TEST_MESSAGE) 
        })
        .then(function(sig){
            assert.equal(sig !== null, true, "Has no signature value");
            assert.notEqual(sig.length, 0, "Has empty signature value");
            return webcrypto.subtle.verify({name: "RSASSA-PKCS1-v1_5"}, key.publicKey, sig, TEST_MESSAGE)
        })
        .then(function(v){
            assert.equal(v, true, "Rsa PKCS1 signature is not valid")
        })
        .then(done, done);
    })
    
    it("RSA OAEP encrypt/decrypt", function (done) {
        var key = null;
		webcrypto.subtle.generateKey({
            name:"RSA-OAEP",
            modulusLength: 1024,
            publicExponent: new Uint8Array([1, 0, 1]), 
            hash: {
                name: "SHA-1"
            }}, 
            false, 
            ["encrypt", "decrypt"]
        )
        .then(function(k){
            assert.equal(k.privateKey !== null, true, "Has no private key");
            assert.equal(k.publicKey !== null, true, "Has no public key");
            key = k;
            return webcrypto.subtle.encrypt({name: "RSA-OAEP"}, key.publicKey, TEST_MESSAGE) 
        })
        .then(function(enc){
            assert.equal(enc !== null, true, "Has no encrypted value");
            assert.notEqual(enc.length, 0, "Has empty encrypted value");
            return webcrypto.subtle.decrypt({name: "RSA-OAEP"}, key.privateKey, enc);
        })
        .then(function(dec){
            assert.equal(dec.toString(), TEST_MESSAGE.toString(), "Rsa OAEP encrypt/decrypt is not valid")
        })
        .then(done, done);
    })
    
    it("RSA OAEP wrap/unwrap", function (done) {
        var key = null;
        var skey = null;
		webcrypto.subtle.generateKey({
            name:"RSA-OAEP",
            modulusLength: 1024,
            publicExponent: new Uint8Array([1, 0, 1]), 
            hash: {
                name: "SHA-1"
            }}, 
            false, 
            ["wrapKey", "unwrapKey"]
        )
        .then(function(k){
            assert.equal(k.privateKey !== null, true, "Has no private key");
            assert.equal(k.publicKey !== null, true, "Has no public key");
            key = k;
            return webcrypto.subtle.generateKey({
                name: "AES-GCM",
                length: 128, //can be  128, 192, or 256
            },
            true, //whether the key is extractable (i.e. can be used in exportKey)
            ["encrypt", "decrypt"]); 
        })
        .then(function(sk){
            skey = sk;
            assert.equal(skey.key !== null, true, "Has no secret key");
            return webcrypto.subtle.wrapKey(
                "raw",
                skey, 
                key.publicKey, 
                {
                    name: "RSA-OAEP",
                    hash: {name: "SHA-1"}
                })        
        })
        .then(function(dec){
            return webcrypto.subtle.unwrapKey(
                "raw", //the import format, must be "raw" (only available sometimes)
                dec, //the key you want to unwrap
                key.privateKey, //the private key with "unwrapKey" usage flag
                {   //these are the wrapping key's algorithm options
                    name: "RSA-OAEP",
                    modulusLength: 1024,
                    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                    hash: {name: "SHA-1"},
                },
                {   //this what you want the wrapped key to become (same as when wrapping)
                    name: "AES-GCM",
                    length: 128
                },
                false, //whether the key is extractable (i.e. can be used in exportKey)
                ["encrypt", "decrypt"] //the usages you want the unwrapped key to have
            )
        })
        .then(function(sk){
            assert.equal(sk.key !== null, true, "Has no secret key");
        })
        .then(done, done);
    })
})