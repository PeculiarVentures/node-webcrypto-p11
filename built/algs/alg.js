"use strict";
var key_1 = require("../key");
var error = require("../error");
exports.RSA_HASH_ALGS = ["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"];
var AlgorithmBase = (function () {
    function AlgorithmBase() {
    }
    AlgorithmBase.onCheck = function (method, paramName, paramValue) { };
    AlgorithmBase.generateKey = function (session, alg, extractable, keyUsages, callback) {
        try {
            throw new Error(error.ERROR_NOT_SUPPORTED_METHOD);
        }
        catch (e) {
            callback(e, null);
        }
    };
    AlgorithmBase.sign = function (session, alg, key, data, callback) {
        try {
            this.checkAlgorithmIdentifier(alg);
            this.onCheck("sign", "alg", alg);
            this.onCheck("sign", "key", key);
            this.onCheck("sign", "data", data);
            var p11Alg = this.wc2pk11(alg, key);
            var signer_1 = session.createSign(p11Alg, key.key);
            signer_1.update(data, function (err) {
                if (err)
                    callback(err, null);
                else
                    signer_1.final(callback);
            });
        }
        catch (e) {
            callback(e, null);
        }
    };
    AlgorithmBase.verify = function (session, alg, key, signature, data, callback) {
        try {
            this.checkAlgorithmIdentifier(alg);
            this.onCheck("verify", "alg", alg);
            this.onCheck("verify", "key", key);
            this.onCheck("verify", "data", data);
            this.onCheck("verify", "signature", signature);
            var p11Alg = this.wc2pk11(alg, key);
            var signer_2 = session.createVerify(p11Alg, key.key);
            signer_2.update(data, function (err) {
                if (err)
                    callback(err, null);
                else
                    signer_2.final(signature, callback);
            });
        }
        catch (e) {
            callback(e, null);
        }
    };
    AlgorithmBase.encrypt = function (session, alg, key, data, callback) {
        try {
            this.checkAlgorithmIdentifier(alg);
            this.onCheck("encrypt", "alg", alg);
            this.onCheck("encrypt", "key", key);
            this.onCheck("encrypt", "data", data);
            var p11Alg = this.wc2pk11(alg, key);
            var cipher_1 = session.createCipher(p11Alg, key.key);
            var msg_1 = new Buffer(0);
            cipher_1.update(data, function (err, enc) {
                if (err)
                    callback(err, null);
                else {
                    msg_1 = enc;
                    cipher_1.final(function (err, enc) {
                        if (err)
                            callback(err, null);
                        else {
                            msg_1 = Buffer.concat([msg_1, enc]);
                            callback(null, msg_1);
                        }
                    });
                }
            });
        }
        catch (e) {
            callback(e, null);
        }
    };
    AlgorithmBase.decrypt = function (session, alg, key, data, callback) {
        try {
            this.checkAlgorithmIdentifier(alg);
            this.onCheck("decrypt", "alg", alg);
            this.onCheck("decrypt", "key", key);
            this.onCheck("decrypt", "data", data);
            var p11Alg = this.wc2pk11(alg, key);
            var cipher_2 = session.createDecipher(p11Alg, key.key);
            var msg_2 = new Buffer(0);
            cipher_2.update(data, function (err, enc) {
                if (err)
                    callback(err, null);
                else {
                    msg_2 = enc;
                    cipher_2.final(function (err, enc) {
                        if (err)
                            callback(err, null);
                        else {
                            msg_2 = Buffer.concat([msg_2, enc]);
                            callback(null, msg_2);
                        }
                    });
                }
            });
        }
        catch (e) {
            callback(e, null);
        }
    };
    AlgorithmBase.wrapKey = function (session, format, key, wrappingKey, alg, callback) {
        try {
            var that_1 = this;
            var KeyClass = null;
            switch (key.algorithm.name.toUpperCase()) {
                case aes.ALG_NAME_AES_CBC:
                    KeyClass = aes.AesCBC;
                    break;
                case aes.ALG_NAME_AES_GCM:
                    KeyClass = aes.AesGCM;
                    break;
                default:
                    throw new error.AlgorithmError(error.ERROR_WRONG_ALGORITHM, key.algorithm.name);
            }
            KeyClass.exportKey(session, format, key, function (err, data) {
                if (err) {
                    callback(err, null);
                }
                else {
                    if (!Buffer.isBuffer(data)) {
                        data = new Buffer(JSON.stringify(data));
                    }
                }
                that_1.encrypt(session, alg, wrappingKey, data, callback);
            });
        }
        catch (e) {
            callback(e, null);
        }
    };
    AlgorithmBase.unwrapKey = function (session, format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedAlgorithm, extractable, keyUsages, callback) {
        var that = this;
        try {
            this.decrypt(session, unwrapAlgorithm, unwrappingKey, wrappedKey, function (err, dec) {
                if (err) {
                    callback(err, null);
                }
                else {
                    try {
                        var ikey = dec;
                        if (format === "jwk") {
                            ikey = JSON.parse(dec.toString());
                        }
                        that.importKey(session, format, ikey, unwrappedAlgorithm, extractable, keyUsages, callback);
                    }
                    catch (e) {
                        callback(e, null);
                    }
                }
            });
        }
        catch (e) {
            callback(e, null);
        }
    };
    AlgorithmBase.deriveKey = function (session, algorithm, baseKey, derivedKeyType, extractable, keyUsages, callback) {
        try {
            throw new Error(error.ERROR_NOT_SUPPORTED_METHOD);
        }
        catch (e) {
            callback(e, null);
        }
    };
    AlgorithmBase.exportKey = function (session, format, key, callback) {
        try {
            throw new Error(error.ERROR_NOT_SUPPORTED_METHOD);
        }
        catch (e) {
            callback(e, null);
        }
    };
    AlgorithmBase.importKey = function (session, format, keyData, algorithm, extractable, keyUsages, callback) {
        try {
            throw new Error(error.ERROR_NOT_SUPPORTED_METHOD);
        }
        catch (e) {
            callback(e, null);
        }
    };
    AlgorithmBase.checkAlgorithmIdentifier = function (alg) {
        if (alg.name.toLowerCase() !== this.ALGORITHM_NAME.toLowerCase())
            throw new error.AlgorithmError("Wrong algorithm name. Must be '" + this.ALGORITHM_NAME + "''");
        alg.name = this.ALGORITHM_NAME;
    };
    AlgorithmBase.checkAlgorithmHashedParams = function (alg) {
        if (!alg.hash)
            throw new error.AlgorithmError("Missing required property hash");
        if (typeof alg.hash !== "object")
            throw new error.AlgorithmError("Algorithm must be an Object");
        if (!(alg.hash.name && typeof (alg.hash.name) === "string"))
            throw new error.AlgorithmError("Missing required property name");
    };
    AlgorithmBase.checkKey = function (key, type) {
        if (!key)
            throw new error.CryptoKeyError("Key can not be null");
        if (!(key instanceof key_1.P11CryptoKey))
            throw new error.CryptoKeyError("CryptoKey os not instance of P11CryptoKey");
        if (key.type !== type)
            throw new error.CryptoKeyError("Wrong key type in use. Must be '" + type + "'");
    };
    AlgorithmBase.checkPrivateKey = function (key) {
        this.checkKey(key, key_1.KT_PRIVATE);
    };
    AlgorithmBase.checkPublicKey = function (key) {
        this.checkKey(key, key_1.KT_PUBLIC);
    };
    AlgorithmBase.checkSecretKey = function (key) {
        this.checkKey(key, key_1.KT_SECRET);
    };
    AlgorithmBase.wc2pk11 = function (alg, key) {
        throw new Error("Not implemented");
    };
    AlgorithmBase.ALGORITHM_NAME = "";
    return AlgorithmBase;
}());
exports.AlgorithmBase = AlgorithmBase;
var aes = require("./aes");
