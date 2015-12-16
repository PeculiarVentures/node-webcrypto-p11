var assert = require('assert');
var WebCrypto = require("../src/webcrypto.js").default;
var config = require("./config.js")

describe("test", function () {
    var webcrypto;
    
    var TEST_MESSAGE = new Buffer("This is test message for crypto functions");

    before(function () {
    })

    after(function () {
    })

    it("RSA PKCS1 1.5", function (done) {
		webcrypto = new WebCrypto(config);
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
})