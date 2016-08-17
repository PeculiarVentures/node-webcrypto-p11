var assert = require('assert');
var config = require('./config');
var WebCrypto = require("../built/webcrypto.js");

describe("KeyStorage", function() {
    var webcrypto;

    before(function(done) {
        webcrypto = new WebCrypto(config);
        assert.equal(!!webcrypto, true, "WebCrypto is not initialized");
        done();
    })

    after(function(done) {
        webcrypto.close();
        done();
    })

    it("GUID", function() {
        var guid1 = webcrypto.getGUID();
        assert.equal(guid1.length, 23);
        var guid2 = webcrypto.getGUID();
        assert.equal(guid2.length, 23);
        assert.equal(guid1 === guid2, false);
    })

    it("set/get item", function(done) {
        webcrypto.subtle.generateKey({
            name: "AES-GCM",
            length: 256, //can be  128, 192, or 256
        },
            false, //whether the key is extractable (i.e. can be used in exportKey)
            ["encrypt", "decrypt"] //can "encrypt", "decrypt", "wrapKey", or "unwrapKey"
        )
            .then(function(k) {
                assert.equal(!!k.key, true, "Has no key value");
                var id = webcrypto.getGUID();
                webcrypto.keyStorage.setItem(id, k);
                var key = webcrypto.keyStorage.getItem(id);
                assert.equal(!!key, true, "Has no key value");
            })
            .then(done, done);
    })
    
    it("remove item", function(done) {
        webcrypto.subtle.generateKey({
            name: "AES-GCM",
            length: 256, //can be  128, 192, or 256
        },
            false, //whether the key is extractable (i.e. can be used in exportKey)
            ["encrypt", "decrypt"] //can "encrypt", "decrypt", "wrapKey", or "unwrapKey"
        )
            .then(function(k) {
                assert.equal(!!k.key, true, "Has no key value");
                var id = webcrypto.getGUID();
                webcrypto.keyStorage.setItem(id, k);
                var key = webcrypto.keyStorage.getItem(id);
                assert.equal(!!key, true, "Has no key value");
                webcrypto.keyStorage.removeItem(id);
                var key = webcrypto.keyStorage.getItem(id);
                assert.equal(!!key, false, "Has key value");
            })
            .then(done, done);
    })

})