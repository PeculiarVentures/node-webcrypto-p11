var assert = require('assert');
var WebCrypto = require("../src/webcrypto.js").default;
var config = require("./config.js")

describe("test", function () {
    var webcrypto;
    
    var TEST_MESSAGE = new Buffer("This is test message for crypto functions");

    before(function () {
        webcrypto = new WebCrypto(config);
    })

    after(function () {
        webcrypto.close();
    })

    it("RSA PKCS1 1.5", function (done) {
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
    
    it("RSA OAEP", function (done) {
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
})