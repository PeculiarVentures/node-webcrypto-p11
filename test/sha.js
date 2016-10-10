var assert = require('assert');
var crypto = require('./config').crypto;
var isSoftHSM = require('./config').isSoftHSM;

describe("WebCrypto digest", function () {

    var TEST_MESSAGE = new Buffer("12345678901234561234567890123456");

    context("Sha", function () {

        ["SHA-1", "SHA-256", "SHA-384", "SHA-512"].forEach(digestAlg =>
            it(`${digestAlg}`, done => {
                crypto.subtle.digest({ name: digestAlg }, TEST_MESSAGE)
                    .then(function (k) {
                        assert.equal(k.key !== null, true, "Digest is empty");
                        return Promise.resolve();
                    })
                    .then(done, done);
            }));

    });

})