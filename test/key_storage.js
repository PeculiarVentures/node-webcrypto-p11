var assert = require('assert');
var crypto = require('./config').crypto;
var isSoftHSM = require('./config').isSoftHSM;

describe("KeyStorage", function() {

    it("GUID", function() {
        var guid1 = crypto.getGUID();
        assert.equal(guid1.length, 23);
        var guid2 = crypto.getGUID();
        assert.equal(guid2.length, 23);
        assert.equal(guid1 === guid2, false);
    })

    it("set/get item", function(done) {
        crypto.subtle.generateKey({
            name: "AES-GCM",
            length: 256, //can be  128, 192, or 256
        },
            false, //whether the key is extractable (i.e. can be used in exportKey)
            ["encrypt", "decrypt"] //can "encrypt", "decrypt", "wrapKey", or "unwrapKey"
        )
            .then(function(k) {
                assert.equal(!!k.key, true, "Has no key value");
                var id = crypto.getGUID();
                crypto.keyStorage.setItem(id, k);
                var key = crypto.keyStorage.getItem(id);
                assert.equal(!!key, true, "Has no key value");
            })
            .then(done, done);
    })
    
    it("remove item", function(done) {
        crypto.subtle.generateKey({
            name: "AES-GCM",
            length: 256, //can be  128, 192, or 256
        },
            false, //whether the key is extractable (i.e. can be used in exportKey)
            ["encrypt", "decrypt"] //can "encrypt", "decrypt", "wrapKey", or "unwrapKey"
        )
            .then(function(k) {
                assert.equal(!!k.key, true, "Has no key value");
                var id = crypto.getGUID();
                crypto.keyStorage.setItem(id, k);
                var key = crypto.keyStorage.getItem(id);
                assert.equal(!!key, true, "Has no key value");
                crypto.keyStorage.removeItem(id);
                var key = crypto.keyStorage.getItem(id);
                assert.equal(!!key, false, "Has key value");
            })
            .then(done, done);
    })

})
