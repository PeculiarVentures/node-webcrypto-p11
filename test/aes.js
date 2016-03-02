var assert = require('assert');
var config = require('./config');
var crypto = require("../built/webcrypto.js");
var WebCrypto = crypto.WebCrypto;

describe("Aes", function () {
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

    it("Aes GCM", function (done) {
        var key = null;
        var iv = webcrypto.getRandomValues(new Uint8Array(12));
        webcrypto.subtle.generateKey({
            name: "AES-GCM",
            length: 256, //can be  128, 192, or 256
        },
            false, //whether the key is extractable (i.e. can be used in exportKey)
            ["encrypt", "decrypt"] //can "encrypt", "decrypt", "wrapKey", or "unwrapKey"
            )
            .then(function (k) {
                assert.equal(k.key !== null, true, "Has no key value");
                key = k;
                return webcrypto.subtle.encrypt(
                    {
                        name: "AES-GCM",

                        //Don't re-use initialization vectors!
                        //Always generate a new iv every time your encrypt!
                        //Recommended to use 12 bytes length
                        iv: iv,

                        //Additional authentication data (optional)
                        additionalData: null,

                        //Tag length (optional)
                        tagLength: 128, //can be 32, 64, 96, 104, 112, 120 or 128 (default)
                    },
                    key, //from generateKey or importKey above
                    TEST_MESSAGE //ArrayBuffer of data you want to encrypt
                    )
            })
            .then(function (enc) {
                assert.equal(enc !== null, true, "Has no encrypted value");
                assert.notEqual(enc.length, 0, "Has empty encrypted value");
                return webcrypto.subtle.decrypt(
                    {
                        name: "AES-GCM",
                        iv: iv, //The initialization vector you used to encrypt
                        additionalData: null, //The addtionalData you used to encrypt (if any)
                        tagLength: 128, //The tagLength you used to encrypt (if any)
                    },
                    key, //from generateKey or importKey above
                    enc //ArrayBuffer of the data
                    );
            })
            .then(function (dec) {
                assert.equal(dec.toString(), TEST_MESSAGE.toString(), "AES-GCM encrypt/decrypt is not valid")
            })
            .then(done, done);
    })

    it("Aes CBC encrypt/decrypt", function (done) {
        var key = null;
        var iv = webcrypto.getRandomValues(new Uint8Array(16));
        webcrypto.subtle.generateKey({
            name: "AES-CBC",
            length: 256, //can be  128, 192, or 256
        },
            false, //whether the key is extractable (i.e. can be used in exportKey)
            ["encrypt", "decrypt"] //can "encrypt", "decrypt", "wrapKey", or "unwrapKey"
            )
            .then(function (k) {
                assert.equal(k.key !== null, true, "Has no key value");
                key = k;
                return webcrypto.subtle.encrypt(
                    {
                        name: "AES-CBC",

                        //Don't re-use initialization vectors!
                        //Always generate a new iv every time your encrypt!
                        iv: iv
                    },
                    key, //from generateKey or importKey above
                    TEST_MESSAGE //ArrayBuffer of data you want to encrypt
                    )
            })
            .then(function (enc) {
                assert.equal(enc !== null, true, "Has no encrypted value");
                assert.notEqual(enc.length, 0, "Has empty encrypted value");
                return webcrypto.subtle.decrypt(
                    {
                        name: "AES-CBC",
                        iv: iv //The initialization vector you used to encrypt
                    },
                    key, //from generateKey or importKey above
                    enc //ArrayBuffer of the data
                    );
            })
            .then(function (dec) {
                assert.equal(dec.toString(), TEST_MESSAGE.toString(), "AES-CBC encrypt/decrypt is not valid")
            })
            .then(done, done);
    })

    it("Aes export/import JWK", function (done) {
        var key = null;
        webcrypto.subtle.generateKey({
            name: "AES-CBC",
            length: 256, //can be  128, 192, or 256
        },
            true, //whether the key is extractable (i.e. can be used in exportKey)
            ["encrypt", "decrypt", "wrapKey", "unwrapKey"] //can "encrypt", "decrypt", "wrapKey", or "unwrapKey"
            )
            .then(function (k) {
                assert.equal(k.key !== null, true, "Has no key value");
                key = k;
                return webcrypto.subtle.exportKey(
                    "jwk",
                    key)
            })
            .then(function (jwk) {
                assert.equal(jwk.kty, "oct");
                assert.equal(!!jwk.k, true);
                assert.equal(jwk.alg, "A256CBC");
                assert.equal(jwk.ext, true);
                return webcrypto.subtle.importKey(
                    "jwk",
                    jwk,
                    {
                        name: "AES-CBC",
                    },
                    true,
                    ["encrypt", "decrypt"]
                    );
            })
            .then(function (key) {
                assert.equal(!!key, true);
            })
            .then(done, done);
    })

    it("AES import/export RAW", function (done) {
        var key = null;
        var k;
        webcrypto.subtle.generateKey({
            name: "AES-CBC",
            length: 256, //can be  128, 192, or 256
        },
            true, //whether the key is extractable (i.e. can be used in exportKey)
            ["encrypt", "decrypt", "wrapKey", "unwrapKey"] //can "encrypt", "decrypt", "wrapKey", or "unwrapKey"
            )
            .then(function (k) {
                assert.equal(k.key !== null, true, "Has no key value");
                key = k;
                return webcrypto.subtle.exportKey(
                    "raw",
                    key)
            })
            .then(function (raw) {
                assert.equal(!!raw, true);
                k = raw;
                return webcrypto.subtle.importKey(
                    "raw",
                    raw,
                    {
                        name: "AES-CBC",
                    },
                    true,
                    ["encrypt", "decrypt"]
                    );
            })
            .then(function (key) {
                assert.equal(!!key, true);
                return webcrypto.subtle.exportKey(
                    "raw",
                    key)
            })
            .then(function (raw) {
                assert.equal(Buffer.compare(new Buffer(raw), new Buffer(k)), 0);
            })
            .then(done, done);
    })

    it("AES wrap/unwrap JWK", function (done) {
        var key = null;
        var iv = webcrypto.getRandomValues(new Uint8Array(16));
        webcrypto.subtle.generateKey({
            name: "AES-CBC",
            length: 256, //can be  128, 192, or 256
        },
            true, //whether the key is extractable (i.e. can be used in exportKey)
            ["encrypt", "decrypt", "wrapKey", "unwrapKey"] //can "encrypt", "decrypt", "wrapKey", or "unwrapKey"
            )
            .then(function (k) {
                assert.equal(k.key !== null, true, "Has no key value");
                key = k;
                return webcrypto.subtle.wrapKey(
                    "jwk", //can be "jwk", "raw", "spki", or "pkcs8"
                    key, //the key you want to wrap, must be able to export to above format
                    key, //the AES-CBC key with "wrapKey" usage flag
                    {   //these are the wrapping key's algorithm options
                        name: "AES-CBC",
                        //Don't re-use initialization vectors!
                        //Always generate a new iv every time your encrypt!
                        iv: iv,
                    })
            })
            .then(function (wrapped) {
                assert.equal(!!wrapped, true);
                return webcrypto.subtle.unwrapKey(
                    "jwk", //"jwk", "raw", "spki", or "pkcs8" (whatever was used in wrapping)
                    wrapped, //the key you want to unwrap
                    key, //the AES-CBC key with "unwrapKey" usage flag
                    {   //these are the wrapping key's algorithm options
                        name: "AES-CBC",
                        iv: iv, //The initialization vector you used to encrypt
                    },
                    {   //this what you want the wrapped key to become (same as when wrapping)
                        name: "AES-CBC",
                        length: 256
                    },
                    true, //whether the key is extractable (i.e. can be used in exportKey)
                    ["encrypt", "decrypt"] //the usages you want the unwrapped key to have
                    )
            })
            .then(function (key) {
                assert.equal(!!key, true);
            })
            .then(done, done);
    })
    
    it("AES wrap/unwrap raw", function (done) {
        var key = null;
        var iv = webcrypto.getRandomValues(new Uint8Array(16));
        webcrypto.subtle.generateKey({
            name: "AES-CBC",
            length: 256, //can be  128, 192, or 256
        },
            true, //whether the key is extractable (i.e. can be used in exportKey)
            ["encrypt", "decrypt", "wrapKey", "unwrapKey"] //can "encrypt", "decrypt", "wrapKey", or "unwrapKey"
            )
            .then(function (k) {
                assert.equal(k.key !== null, true, "Has no key value");
                key = k;
                return webcrypto.subtle.wrapKey(
                    "raw", //can be "jwk", "raw", "spki", or "pkcs8"
                    key, //the key you want to wrap, must be able to export to above format
                    key, //the AES-CBC key with "wrapKey" usage flag
                    {   //these are the wrapping key's algorithm options
                        name: "AES-CBC",
                        //Don't re-use initialization vectors!
                        //Always generate a new iv every time your encrypt!
                        iv: iv,
                    })
            })
            .then(function (wrapped) {
                assert.equal(!!wrapped, true);
                return webcrypto.subtle.unwrapKey(
                    "raw", //"jwk", "raw", "spki", or "pkcs8" (whatever was used in wrapping)
                    wrapped, //the key you want to unwrap
                    key, //the AES-CBC key with "unwrapKey" usage flag
                    {   //these are the wrapping key's algorithm options
                        name: "AES-CBC",
                        iv: iv, //The initialization vector you used to encrypt
                    },
                    {   //this what you want the wrapped key to become (same as when wrapping)
                        name: "AES-CBC",
                        length: 256
                    },
                    true, //whether the key is extractable (i.e. can be used in exportKey)
                    ["encrypt", "decrypt"] //the usages you want the unwrapped key to have
                    )
            })
            .then(function (key) {
                assert.equal(!!key, true);
            })
            .then(done, done);
    })
})