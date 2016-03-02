var assert = require('assert');
var config = require('./config');
var crypto = require("../built/webcrypto.js");
var WebCrypto = crypto.WebCrypto;

function s2ab(text) {
    var uint = new Uint8Array(text.length);
    for (var i = 0, j = text.length; i < j; ++i) {
        uint[i] = text.charCodeAt(i);
    }
    return uint;
}

var TEST_MESSAGE = s2ab("1234567890123456");

var webcrypto = new WebCrypto(config);
assert.equal(!!webcrypto, true, "WebCrypto is not initialized");

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

    .then(function () { console.log("success") }, function (e) { console.log("Error: %s\n%s", e.message, e.stack) });