const assert = require('assert');
const { crypto, isSoftHSM, isNSS } = require('./config');

var keys = [];

describe("WebCrypto Aes", function () {

    var TEST_MESSAGE = new Buffer("1234567890123456");
    var KEYS = [
        { alg: "AES-ECB", usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"] },
        { alg: "AES-CBC", usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"] },
        { alg: "AES-GCM", usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"] },
    ];

    context("Generate key", () => {

        // Algs
        KEYS.forEach(key => {
            // length
            [128, 192, 256].forEach(length => {
                var keyName = `${key.alg} l:${length}`;
                var keyTemplate = {
                    name: keyName,
                    key: null,
                    usages: key.usages,
                };
                keys.push(keyTemplate);
                it(keyName, done => {
                    var alg = {
                        name: key.alg,
                        length: length
                    };
                    crypto.subtle.generateKey(alg, true, key.usages)
                        .then(aesKey => {
                            assert.equal(!!aesKey, true, "Aes key is empty");
                            keyTemplate.key = aesKey;
                        })
                        .then(done, done);
                });
            });
        })

    });

    context("Encrypt/Decrypt", () => {

        context("AES-ECB", () => {

            // Filter CBC
            keys.filter(key => /AES-ECB/.test(key.name))
                .forEach(key => {
                    it(`${key.name}`, done => {
                        var alg = { name: "AES-ECB" };
                        crypto.subtle.encrypt(alg, key.key, TEST_MESSAGE)
                            .then(enc => {
                                assert(!!enc, true, "Encrypted message is empty");
                                return crypto.subtle.decrypt(alg, key.key, enc);
                            })
                            .then(dec => {
                                assert(new Buffer(dec).toString(), TEST_MESSAGE.toString(), "Decrypted message is wrong");
                            })
                            .then(done, done);
                    });
                });
        });

        context("AES-CBC", () => {

            // Filter CBC
            keys.filter(key => /AES-CBC/.test(key.name))
                .forEach(key => {
                    [new Uint8Array(16), new Uint8Array(16)].forEach(iv => {
                        it(`iv:${iv.length}\t${key.name}`, done => {
                            var alg = { name: "AES-CBC", iv: iv };
                            crypto.subtle.encrypt(alg, key.key, TEST_MESSAGE)
                                .then(enc => {
                                    assert(!!enc, true, "Encrypted message is empty");
                                    return crypto.subtle.decrypt(alg, key.key, enc);
                                })
                                .then(dec => {
                                    assert(new Buffer(dec).toString(), TEST_MESSAGE.toString(), "Decrypted message is wrong");
                                })
                                .then(done, done);
                        });
                    });
                });
        });

        context("AES-GCM", () => {
            if (isSoftHSM("AES-GCM Encrypt/Decrypt")) return;
            // Filter GCM
            keys.filter(key => /AES-GCM/.test(key.name))
                .forEach(key => {
                    // IV
                    [new Uint8Array(16)].forEach(iv => {
                        // AAD
                        [new Uint8Array([1, 2, 3, 4, 5]), null].forEach(aad => {
                            // Tag
                            [32, 64, 96, 104, 112, 120, 128].forEach(tag => {
                                it(`aad:${aad ? "+" : "-"} t:${tag}\t${key.name}`, done => {
                                    var alg = { name: "AES-GCM", iv: iv, additionalData: aad, tagLength: tag };
                                    crypto.subtle.encrypt(alg, key.key, TEST_MESSAGE)
                                        .then(enc => {
                                            assert(!!enc, true, "Encrypted message is empty");
                                            return crypto.subtle.decrypt(alg, key.key, enc);
                                        })
                                        .then(dec => {
                                            assert(new Buffer(dec).toString(), TEST_MESSAGE.toString(), "Decrypted message is wrong");
                                        })
                                        .then(done, done);
                                });
                            });
                        });
                    });
                });
        });

    });

    context("Export/Import", () => {

        // Keys
        keys.forEach(key => {
            // Format
            ["jwk", "raw"].forEach(format => {
                it(`${format}\t${key.name}`, done => {
                    crypto.subtle.exportKey(format, key.key)
                        .then(jwk => {
                            assert.equal(!!jwk, true, "Has no jwk value");
                            if (format === "jwk")
                                assert.equal(!!jwk.k, true, "Has no k value");
                            else
                                assert.equal(!!jwk.byteLength, true, "Wrong raw length");
                            return crypto.subtle.importKey(format, jwk, key.key.algorithm, true, key.key.usages);
                        })
                        .then(k => {
                            assert.equal(!!k, true, "Imported key is empty")
                            assert.equal(!!k.p11Object, true, "Has no native key value");
                        })
                        .then(done, done);
                });
            });
        });
    });

    context("Wrap/Unwrap", () => {
        context("AES-ECB", () => {
            // AES keys
            keys.filter(key => /AES-ECB/.test(key.name)).forEach(key => {
                ["jwk", "raw"].forEach(format => {
                    it(`format:${format} ${key.name}`, done => {
                        var _alg = { name: "AES-ECB" }
                        crypto.subtle.wrapKey(format, key.key, key.key, _alg)
                            .then(wrappedKey => {
                                assert.equal(!!wrappedKey, true, "Wrapped key is empty");

                                return crypto.subtle.unwrapKey(format, wrappedKey, key.key, _alg, key.key.algorithm, true, ["encrypt", "decrypt"]);
                            })
                            .then(key => {
                                assert.equal(!!key, true, "Unwrapped key is empty");
                            })
                            .then(done, done);
                    })

                });
            });
        });
        context("AES-CBC", () => {
            // AES keys
            keys.filter(key => /AES-CBC/.test(key.name)).forEach(key => {
                ["jwk", "raw"].forEach(format => {
                    it(`format:${format} ${key.name}`, done => {
                        var _alg = { name: "AES-CBC", iv: new Uint8Array(16) }
                        crypto.subtle.wrapKey(format, key.key, key.key, _alg)
                            .then(wrappedKey => {
                                assert.equal(!!wrappedKey, true, "Wrapped key is empty");

                                return crypto.subtle.unwrapKey(format, wrappedKey, key.key, _alg, key.key.algorithm, true, ["encrypt", "decrypt"]);
                            })
                            .then(key => {
                                assert.equal(!!key, true, "Unwrapped key is empty");
                            })
                            .then(done, done);
                    })

                });
            });
        });
        context("AES-GCM", () => {
            if (isSoftHSM("AES-GCM Wrap/Unwrap")) return;
            // AES keys
            keys.filter(key => /AES-GCM/.test(key.name)).forEach(key => {
                ["jwk", "raw"].forEach(format => {
                    it(`format:${format} ${key.name}`, done => {
                        var _alg = { name: "AES-GCM", iv: new Uint8Array(16) }
                        crypto.subtle.wrapKey(format, key.key, key.key, _alg)
                            .then(wrappedKey => {
                                assert.equal(!!wrappedKey, true, "Wrapped key is empty");

                                return crypto.subtle.unwrapKey(format, wrappedKey, key.key, _alg, key.key.algorithm, true, ["encrypt", "decrypt"]);
                            })
                            .then(key => {
                                assert.equal(!!key, true, "Unwrapped key is empty");
                            })
                            .then(done, done);
                    })

                });
            });
        });
    });

});