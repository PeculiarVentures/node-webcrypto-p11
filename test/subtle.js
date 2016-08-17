var assert = require('assert');
var config = require('./config');
var WebCrypto = require("../built/webcrypto.js");

describe("Subtle", function() {
    var webcrypto;
    var keys;

    var TEST_MESSAGE = new Buffer("1234567890123456");

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
                assert.equal(digest.byteLength, mdlen);
            })
            .then(done, done);
    }
    
    it("random", function(){
       var rnd = webcrypto.getRandomValues(new Uint8Array(16));
       assert.equal(rnd.length, 16);
    });

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