var assert = require('assert');
var config = require('./config');
var crypto = require("../built/webcrypto.js");
var WebCrypto = crypto.WebCrypto;

describe("Subtle", function() {
    var webcrypto;
    var keys;

    function s2ab(text) {
        var uint = new Uint8Array(text.length);
        for (var i = 0, j = text.length; i < j; ++i) {
            uint[i] = text.charCodeAt(i);
        }
        return uint;
    }

    var TEST_MESSAGE = s2ab("1234567890123456");

    before(function(done) {
        webcrypto = new WebCrypto(config);
        assert.equal(!!webcrypto, true, "WebCrypto is not initialized");
        done();
    })

    after(function(done) {
        webcrypto.close();
        done();
    })

    function test_digest(alg, mdlen, done) {
        webcrypto.subtle.digest(alg, TEST_MESSAGE)
            .then(function(digest) {
                assert.equal(digest.length, mdlen);
            })
            .then(done, done);
    }

    it("Digest SHA-1", function(done) {
        test_digest("sha-1", 20, done);
    });

    it("Digest SHA-224", function(done) {
        test_digest("sha-224", 28, done);
    });

    it("Digest SHA-256", function(done) {
        test_digest("sha-256", 32, done);
    });

    it("Digest SHA-384", function(done) {
        test_digest("sha-384", 48, done);
    });

    it("Digest SHA-512", function(done) {
        test_digest("sha-512", 64, done);
    });

});