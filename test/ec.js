var assert = require('assert');
var crypto = require('./config').crypto;
var { isSoftHSM, isNSS } = require('./config');

describe("WebCrypto EC", () => {

    var TEST_MESSAGE = new Buffer("1234567890123456");
    var KEYS = [
        { alg: "ECDSA", usages: ["sign", "verify"] },
        { alg: "ECDH", usages: ["deriveKey", "deriveBits"] },
    ];
    var DIGEST = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];
    var NAMED_CURVES = ["P-256", "P-384", "P-521", "K-256", "X25519"];

    var keys = [];

    context("Generate key", () => {
        // Algs
        KEYS.forEach(key => {
            // namedCurve
            NAMED_CURVES.forEach(namedCurve => {
                if (namedCurve === "K-256" && isNSS(`Generate key NSS ${key.alg} K-256`)) {
                    return;
                }
                if (namedCurve === "X25519" && isSoftHSM(`Generate key SoftHSM ${key.alg} X25519`)) {
                    return;
                }
                if (namedCurve === "X25519" && key.alg === "ECDSA") { // skip ECDSA for X25529
                    return;
                }

                var keyName = `${key.alg} crv:${namedCurve}`
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
                        namedCurve: namedCurve
                    };
                    crypto.subtle.generateKey(alg, true, key.usages)
                        .then(keyPair => {
                            assert.equal(!!(keyPair.privateKey || keyPair.publicKey), true, "KeyPair is empty");
                            // save  keays for next tests
                            keyTemplate.privateKey = keyPair.privateKey;
                            keyTemplate.publicKey = keyPair.publicKey;
                            return Promise.resolve();
                        })
                        .then(done, done);
                });
            });
        });
    });

    context("Sign/Verify", () => {

        keys.filter(key => key.usages.some(usage => usage === "sign"))
            .forEach(key => {
                // Hash
                DIGEST.forEach(hash => {
                    it(`${hash}  \t${key.name}`, done => {
                        var alg = { name: key.privateKey.algorithm.name, hash: { name: hash } };
                        crypto.subtle.sign(alg, key.privateKey, TEST_MESSAGE)
                            .then(sig => {
                                assert.equal(!!sig, true, "Has no signature value");
                                assert.notEqual(sig.length, 0, "Has empty signature value");
                                return crypto.subtle.verify(alg, key.publicKey, sig, TEST_MESSAGE)
                            })
                            .then(v => assert.equal(v, true, "Signature is not valid"))
                            .then(done, done);
                    });
                });
            });
    });

    context("Derive key", () => {

        keys.filter(key => key.usages.some(usage => usage === "deriveKey"))
            .forEach(key => {
                // AES alg
                ["AES-CBC", "AES-GCM"].forEach(aesAlg => {
                    // AES length
                    [128, 192, 256].forEach(aesLength => {
                        it(`${aesAlg}-${aesLength}\t${key.name}`, done => {
                            if (key.privateKey.algorithm.namedCurve === "P-521" && isSoftHSM()) return done();
                            var alg = {
                                name: key.privateKey.algorithm.name,
                                public: key.publicKey
                            };
                            crypto.subtle.deriveKey(alg, key.privateKey, { name: aesAlg, length: aesLength }, true, ["encrypt"])
                                .then(aesKey => {
                                    assert.equal(!!aesKey, true, "Has no derived key");
                                    assert.equal(aesKey.algorithm.length, aesLength, "Has wrong derived key length");
                                    assert.equal(aesKey.usages.length, 1, "Has wrong key usages length");
                                    assert.equal(aesKey.usages[0], "encrypt", "Has wrong key usage");
                                })
                                .then(done, done);
                        });
                    });
                });
            });
    });

    context("Derive bits", () => {

        keys.filter(key => key.usages.some(usage => usage === "deriveBits"))
            .forEach(key => {
                // length
                [56, 96, 128, 192, 256].forEach(bitsLength => {
                    it(`bits:${bitsLength} \t${key.name}`, done => {
                        if (key.privateKey.algorithm.namedCurve === "P-521" && isSoftHSM()) return done();
                        var alg = {
                            name: key.privateKey.algorithm.name,
                            public: key.publicKey
                        };
                        crypto.subtle.deriveBits(alg, key.privateKey, bitsLength)
                            .then(bits => {
                                assert.equal(!!bits, true, "Has no derived bits");
                                assert.equal(bits.byteLength, bitsLength / 8, "Has wrong derived bits length");
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
            ["jwk", "spki", "pkcs8"].forEach(format => {
                const itName = `${format}\t${key.name}`;
                if (key.name === "ECDH crv:X25519" && format !== "jwk") {
                    it.skip(itName);
                    return;
                }
                it(itName, done => {
                    var promise = Promise.resolve();
                    // Check public and private keys
                    [key.privateKey, key.publicKey].forEach(_key => {
                        if ((format === "spki" && _key.type === "public") || (format === "pkcs8" && _key.type === "private") || format === "jwk")
                            promise = promise.then(() => {
                                return crypto.subtle.exportKey(format, _key)
                                    .then(jwk => {
                                        assert.equal(!!jwk, true, "Has no jwk value");
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

        it("raw", (done) => {
            Promise.resolve()
                .then(() => {
                    const spki = Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200043ff61b3c7afc727338d24da52724abf2f430641be01000549bb81d80ca2e6550c0eaa09e90eca600fef445ddcd131d0a88b61df2802e4b16feac9c1dfe1d92e6", "hex");
                    const alg = { name: "ECDSA", namedCurve: "P-256" };
                    return crypto.subtle.importKey("spki", spki, alg, true, ["verify"]);
                })
                .then((key) => {
                    return crypto.subtle.exportKey("raw", key)
                })
                .then((raw) => {
                    const vector = Buffer.from("043ff61b3c7afc727338d24da52724abf2f430641be01000549bb81d80ca2e6550c0eaa09e90eca600fef445ddcd131d0a88b61df2802e4b16feac9c1dfe1d92e6", "hex");
                    assert.equal(Buffer.from(raw).equals(vector), true);
                })
                .then(done, done);
        });
    });

});