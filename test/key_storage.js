var assert = require('assert');
var crypto = require('./config').crypto;
var isSoftHSM = require('./config').isSoftHSM;

describe("KeyStorage", () => {

    beforeEach((done) => {
        Promise.resolve()
            .then(() => {
                return crypto.keyStorage.keys()
            })
            .then((keys) => {
                if (keys.length) {
                    return Promise.resolve().then(() => {
                        return crypto.keyStorage.clear()
                    })
                    .then(() => {
                        return crypto.keyStorage.keys()
                    })
                    .then((keys) => {
                        assert.equal(keys.length, 0);
                    })
                }
            })
            .then(done, done);
    })

    context("indexOf", () => {
        ["privateKey", "publicKey"].forEach((type) => {
            it(type, (done) => {
                crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 1024 }, false, ["sign", "verify"])
                    .then((keys) => {
                        const key = keys[type];
                        return crypto.keyStorage.setItem(key)
                            .then((index) => {
                                return crypto.keyStorage.indexOf(key)
                                    .then((found) => {
                                        assert.equal(found, null);
                                    })
                                    .then(() => {
                                        return crypto.keyStorage.getItem(index);
                                    })
                                    .then((key) => {
                                        return crypto.keyStorage.indexOf(key)
                                    })
                                    .then((found) => {
                                        assert.equal(found, index);
                                    })
                            })
                    })
                    .then(done, done);
            });
        });
    });

    it("set/get item", (done) => {
        crypto.keyStorage.keys()
            .then((indexes) => {
                assert.equal(indexes.length, 0);
                return crypto.subtle.generateKey({
                    name: "AES-CBC",
                    length: 256
                },
                    true,
                    ["encrypt", "decrypt"]
                )
            })
            .then((k) => {
                assert.equal(!!k, true, "Has no key value");
                return crypto.keyStorage.setItem(k);
            })
            .then((index) => {
                return crypto.keyStorage.keys()
                    .then((indexes) => {
                        assert.equal(indexes.length, 1, "Wrong amount of indexes in storage");
                        assert.equal(indexes[0], index, "Wrong index of item in storage");

                        return crypto.keyStorage.getItem(index);
                    })
                    .then((key) => {
                        return crypto.subtle.exportKey("raw", key);
                    })
                    .then((raw) => {
                        assert.equal(raw.byteLength, 32);
                    });
            })
            .then(done, done);
    })

    it("remove item", (done) => {
        crypto.subtle.generateKey({
            name: "RSASSA-PKCS1-v1_5",
            hash: "SHA-256",
            publicExponent: new Uint8Array([1, 0, 1]),
            modulusLength: 2048,
        },
            false,
            ["sign", "verify"]
        )
            .then((keys) => {
                return crypto.keyStorage.setItem(keys.publicKey)
                    .then(() => {
                        return crypto.keyStorage.setItem(keys.privateKey)
                    })
                    .then(() => {
                        return crypto.keyStorage.keys();
                    })
                    .then((indexes) => {
                        assert.equal(indexes.length, 2);
                        return crypto.keyStorage.removeItem(indexes[0]);
                    })
                    .then(() => {
                        return crypto.keyStorage.keys();
                    })
                    .then((indexes) => {
                        assert.equal(indexes.length, 1);
                    })
            })
            .then(done, done);
    })

    context("getItem", () => {

        it("wrong key identity", (done) => {
            crypto.keyStorage.getItem("key not exist")
                .then((key) => {
                    assert.equal(key, null);
                })
                .then(done, done);
        })

        context("with algorithm", () => {
            it("RSASSA-PKCS1-v1_5", (done) => {
                crypto.subtle.generateKey({
                    name: "RSA-PSS",
                    hash: "SHA-1",
                    publicExponent: new Uint8Array([1, 0, 1]),
                    modulusLength: 2048,
                },
                    false,
                    ["sign", "verify"]
                )
                    .then((keys) => {
                        return crypto.keyStorage.setItem(keys.publicKey)
                            .then((index) => {
                                return crypto.keyStorage.keys()
                                    .then((indexes) => {
                                        assert.equal(indexes.length, 1);
                                        return crypto.keyStorage.getItem(index, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" }, ["verify"]);
                                    })
                                    .then((key) => {
                                        assert.equal(key.algorithm.name, "RSASSA-PKCS1-v1_5");
                                        assert.equal(key.algorithm.hash.name, "SHA-512");
                                        assert.equal(key.usages.join(","), "verify");
                                    });
                            });
                    })
                    .then(done, done);
            })
        })

        context("with default algorithm", () => {

            it("RSASSA-PKCS1-v1_5", (done) => {
                crypto.subtle.generateKey({
                    name: "RSA-PSS",
                    hash: "SHA-1",
                    publicExponent: new Uint8Array([1, 0, 1]),
                    modulusLength: 2048,
                },
                    false,
                    ["sign", "verify"]
                )
                    .then((keys) => {
                        return crypto.keyStorage.setItem(keys.publicKey)
                            .then((index) => {
                                return crypto.keyStorage.keys()
                                    .then((indexes) => {
                                        assert.equal(indexes.length, 1);
                                        return crypto.keyStorage.getItem(index);
                                    })
                                    .then((key) => {
                                        assert.equal(key.algorithm.name, "RSASSA-PKCS1-v1_5");
                                        assert.equal(key.algorithm.hash.name, "SHA-256");
                                        assert.equal(key.usages.join(","), "verify");
                                    });
                            });
                    })
                    .then(done, done);
            })

            it("ECDSA P-256", (done) => {
                crypto.subtle.generateKey({
                    name: "ECDSA",
                    namedCurve: "P-256",
                },
                    false,
                    ["sign", "verify"]
                )
                    .then((keys) => {
                        return crypto.keyStorage.setItem(keys.publicKey)
                            .then((index) => {
                                return crypto.keyStorage.keys()
                                    .then((indexes) => {
                                        assert.equal(indexes.length, 1);
                                        return crypto.keyStorage.getItem(index);
                                    })
                                    .then((key) => {
                                        assert.equal(key.algorithm.name, "ECDSA");
                                        assert.equal(key.algorithm.namedCurve, "P-256");
                                        assert.equal(key.usages.join(","), "verify");
                                    });
                            });
                    })
                    .then(done, done);
            })

            it("ECDSA P-521", (done) => {
                crypto.subtle.generateKey({
                    name: "ECDSA",
                    namedCurve: "P-521",
                },
                    false,
                    ["sign", "verify"]
                )
                    .then((keys) => {
                        return crypto.keyStorage.setItem(keys.publicKey)
                            .then((index) => {
                                return crypto.keyStorage.keys()
                                    .then((indexes) => {
                                        assert.equal(indexes.length, 1);
                                        return crypto.keyStorage.getItem(index);
                                    })
                                    .then((key) => {
                                        assert.equal(key.algorithm.name, "ECDSA");
                                        assert.equal(key.algorithm.namedCurve, "P-521");
                                        assert.equal(key.usages.join(","), "verify");
                                    });
                            });
                    })
                    .then(done, done);
            })

            it("AES-HMAC", (done) => {
                done();
                return;
                // TODO: AES-HMAC is not supported yet
                crypto.subtle.generateKey({
                    name: "AES-HMAC",
                    length: 256
                },
                    false,
                    ["sign", "verify"]
                )
                    .then((key) => {
                        return crypto.keyStorage.setItem(key)
                            .then((index) => {
                                return crypto.keyStorage.keys()
                                    .then((indexes) => {
                                        assert.equal(indexes.length, 1);
                                        return crypto.keyStorage.getItem(index);
                                    })
                                    .then((key) => {
                                        assert.equal(key.algorithm.name, "AES-HMAC");
                                        assert.equal(key.usages.join(","), "sign,verify");
                                    });
                            });
                    })
                    .then(done, done);
            })

            it("RSA-OAEP", (done) => {
                crypto.subtle.generateKey({
                    name: "RSA-OAEP",
                    hash: "SHA-1",
                    publicExponent: new Uint8Array([1, 0, 1]),
                    modulusLength: 2048,
                },
                    false,
                    ["encrypt", "decrypt"]
                )
                    .then((keys) => {
                        return crypto.keyStorage.setItem(keys.publicKey)
                            .then((index) => {
                                return crypto.keyStorage.keys()
                                    .then((indexes) => {
                                        assert.equal(indexes.length, 1);
                                        return crypto.keyStorage.getItem(index);
                                    })
                                    .then((key) => {
                                        assert.equal(key.algorithm.name, "RSA-OAEP");
                                        assert.equal(key.algorithm.hash.name, "SHA-256");
                                        assert.equal(key.usages.join(","), "encrypt");
                                    });
                            });
                    })
                    .then(done, done);
            })

            it("AES-CBC", (done) => {
                crypto.subtle.generateKey({
                    name: "AES-CBC",
                    length: 256
                },
                    false,
                    ["encrypt", "decrypt"]
                )
                    .then((key) => {
                        return crypto.keyStorage.setItem(key)
                            .then((index) => {
                                return crypto.keyStorage.keys()
                                    .then((indexes) => {
                                        assert.equal(indexes.length, 1);
                                        return crypto.keyStorage.getItem(index);
                                    })
                                    .then((key) => {
                                        assert.equal(key.algorithm.name, "AES-CBC");
                                        assert.equal(key.usages.join(","), "encrypt,decrypt");
                                    });
                            });
                    })
                    .then(done, done);
            })

            it("ECDH", (done) => {
                crypto.subtle.generateKey({
                    name: "ECDH",
                    namedCurve: "P-384"
                },
                    false,
                    ["deriveBits"]
                )
                    .then((keys) => {
                        return crypto.keyStorage.setItem(keys.privateKey)
                            .then((index) => {
                                return crypto.keyStorage.keys()
                                    .then((indexes) => {
                                        assert.equal(indexes.length, 1);
                                        return crypto.keyStorage.getItem(index);
                                    })
                                    .then((key) => {
                                        assert.equal(key.algorithm.name, "ECDH");
                                        assert.equal(key.algorithm.namedCurve, "P-384");
                                        assert.equal(key.usages.join(","), "deriveKey,deriveBits");
                                    });
                            });
                    })
                    .then(done, done);
            })

        })
    })

})
