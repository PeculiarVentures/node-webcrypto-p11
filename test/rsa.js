var assert = require('assert');
var crypto = require('./config').crypto;
var isSoftHSM = require('./config').isSoftHSM;

describe("WebCrypto RSA", () => {

    var TEST_MESSAGE = new Buffer("1234567890123456");
    var KEYS = [
        { alg: "RSASSA-PKCS1-v1_5", usages: ["sign", "verify"] },
        { alg: "RSA-PSS", usages: ["sign", "verify"] },
        { alg: "RSA-OAEP", usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"] },
    ];
    var DIGEST = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];
    var PUBLIC_EXPONENT = [new Uint8Array([3]), new Uint8Array([1, 0, 1])];
    var MODULUS_LENGTH = [1024/*, 2048, /*4096*/];

    var keys = [];

    context("Generate key", () => {
        // Algs
        KEYS.forEach(key => {
            // Digest
            DIGEST.forEach(digest => {
                // publicExponent
                PUBLIC_EXPONENT.forEach(pubExp => {
                    // modulusLength
                    MODULUS_LENGTH.forEach(modLen => {
                        var keyName = `${key.alg} ${digest} e:${pubExp.length === 1 ? 3 : 65535} n:${modLen}`
                        var keyTemplate = {
                            name: keyName,
                            privateKey: null,
                            publicKey: null,
                            usages: key.usages,
                        }
                        keys.push(keyTemplate);
                        it(keyName, done => {
                            var alg = {
                                name: key.alg,
                                hash: { name: digest },
                                modulusLength: modLen,
                                publicExponent: pubExp
                            };
                            crypto.subtle.generateKey(alg, true, key.usages)
                                .then(keyPair => {
                                    assert.equal(!!(keyPair.privateKey || keyPair.publicKey), true, "KeyPair is empty");
                                    // save  keys for next tests
                                    keyTemplate.privateKey = keyPair.privateKey;
                                    keyTemplate.publicKey = keyPair.publicKey;
                                    return Promise.resolve();
                                })
                                .then(done, done);
                        }).timeout(modLen === 2048 ? 4000 : 2000);
                    });
                });
            });
        });
    });

    context("Sign/Verify", () => {

        keys.filter(key => key.usages.some(usage => usage === "sign"))
            .forEach(key => {
                it(key.name, done => {
                    // TODO: Add label
                    crypto.subtle.sign({ name: key.privateKey.algorithm.name, saltLength: 8 }, key.privateKey, TEST_MESSAGE)
                        .then(sig => {
                            assert.equal(!!sig, true, "Has no signature value");
                            assert.notEqual(sig.length, 0, "Has empty signature value");
                            return crypto.subtle.verify({ name: key.publicKey.algorithm.name, saltLength: 8 }, key.publicKey, sig, TEST_MESSAGE)
                        })
                        .then(v => assert.equal(v, true, "Signature is not valid"))
                        .then(done, done);
                });
            });
    });

    context("Encrypt/Decrypt", () => {
        // Select keys for encrypt
        keys.filter(key => key.usages.some(usage => usage === "encrypt"))
            .forEach(key => {
                // Label
                [null, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])].forEach(label => {
                    it(`${label ? "label\t" : "no label"}\t${key.name}`, done => {
                        if (!(!label && key.privateKey.algorithm.hash.name === "SHA-1") && isSoftHSM("RSA-OAPE Encrypt/Decrypt")) return done();
                        crypto.subtle.encrypt({ name: key.privateKey.algorithm.name, label: label }, key.publicKey, TEST_MESSAGE)
                            .then(enc => {
                                assert.equal(!!enc, true, "Has no encrpted value");
                                assert.notEqual(enc.length, 0, "Has empty encrypted value");
                                return crypto.subtle.decrypt({ name: key.publicKey.algorithm.name, label: label }, key.privateKey, enc)
                            })
                            .then(dec => {
                                assert.equal(new Buffer(dec).toString(), TEST_MESSAGE.toString(), "Decrypted message is not valid")
                            })
                            .then(done, done);
                    });
                });
            });
    });

    context("Export/Import", () => {

        // Keys
        keys.forEach(key => {
            // Format
            ["spki", "pkcs8", "jwk"].forEach(format => {
                it(`${format}\t${key.name}`, done => {
                    var promise = Promise.resolve();
                    // Check public and private keys
                    [key.privateKey, key.publicKey].forEach(_key => {
                        if ((format === "spki" && _key.type === "public") || (format === "pkcs8" && _key.type === "private") || format === "jwk")
                            promise = promise.then(() => {
                                return crypto.subtle.exportKey(format, _key)
                                    .then(jwk => {
                                        assert.equal(!!jwk, true, "Has no exported value");
                                        // TODO assert JWK params
                                        return crypto.subtle.importKey(format, jwk, _key.algorithm, true, _key.usages);
                                    })
                            })
                                .then(k => assert.equal(!!k, true, "Imported key is empty"))
                        // TODO assert imported key params
                    });
                    promise.then(done, done);
                });
            });
        });
    });

    context("Wrap/Unwrap", () => {

        var aesKeys = [{}, {}, {}];

        before(done => {
            var promise = Promise.resolve();
            [128, 192, 256].forEach((length, index) => {
                var keyTemplate = aesKeys[index];
                promise = promise.then(() => {
                    return crypto.subtle.generateKey({ name: "AES-CBC", length: length }, true, ["encrypt", "decrypt"])
                        .then(key => {
                            keyTemplate.key = key;
                            // return Promise.resolve();
                        });
                });
            });
            promise.then(done, done);
        });

        // Keys
        keys.filter(key => key.usages.some(usage => "wrapKey" === usage))
            .forEach(key => {
                // AES keys
                aesKeys.forEach(aes => {
                    // Format
                    ["raw"].forEach(format => {
                        [null, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])].forEach(label => {
                            it(`${label ? "label\t" : "no label"}\t${key.name}`, done => {
                                if (!(!label && key.privateKey.algorithm.hash.name === "SHA-1") && isSoftHSM("RSA-OAPE Encrypt/Decrypt")) return done();
                                var _alg = { name: key.publicKey.algorithm.name, label: label };
                                crypto.subtle.wrapKey(format, aes.key, key.publicKey, _alg)
                                    .then(enc => {
                                        assert.equal(!!enc, true, "Has no encrypted value");
                                        return crypto.subtle.unwrapKey(format, enc, key.privateKey, _alg, aes.key.algorithm, true, aes.key.usages);
                                    })
                                    .then(key => {
                                        assert.equal(!!key, true, "Has no unwrapped key");
                                    })
                                    .then(done, done);
                            });
                        });
                    });
                });
            });
    });

});