"use strict";
var error = require("./error");
var aes = require("./algs/aes");
var rsa = require("./algs/rsa");
var ec = require("./algs/ec");
function prepare_algorithm(alg) {
    var _alg = (typeof alg === "string") ? { name: alg } : alg;
    if (typeof _alg !== "object")
        throw new error.AlgorithmError("Algorithm must be an Object");
    if (!(_alg.name && typeof (_alg.name) === "string"))
        throw new error.AlgorithmError("Missing required property name");
    return _alg;
}
function ab2b(data) {
    return new Buffer(new Uint8Array(data.buffer));
}
function b2ab(data) {
    var ab = new Uint8Array(data.length);
    for (var i = 0; i < data.length; i++)
        ab[i] = data[i];
    return ab;
}
var P11SubtleCrypto = (function () {
    function P11SubtleCrypto(session) {
        this.session = session;
    }
    P11SubtleCrypto.prototype.generateKey = function (algorithm, extractable, keyUsages) {
        var that = this;
        return new Promise(function (resolve, reject) {
            var _alg = prepare_algorithm(algorithm);
            var AlgClass = null;
            switch (_alg.name.toLowerCase()) {
                case rsa.RsaPKCS1.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaPKCS1;
                    break;
                case rsa.RsaPSS.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaPSS;
                    break;
                case rsa.RsaOAEP.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaOAEP;
                    break;
                case aes.AesGCM.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesGCM;
                    break;
                case aes.AesCBC.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesCBC;
                    break;
                case ec.Ecdsa.ALGORITHM_NAME.toLowerCase():
                    AlgClass = ec.Ecdsa;
                    break;
                case ec.Ecdh.ALGORITHM_NAME.toLowerCase():
                    AlgClass = ec.Ecdh;
                    break;
                default:
                    throw new error.AlgorithmError(error.ERROR_WRONG_ALGORITHM, _alg.name);
            }
            AlgClass.generateKey(that.session, _alg, extractable, keyUsages, function (err, key) {
                if (err)
                    reject(err);
                else
                    resolve(key);
            });
        });
    };
    P11SubtleCrypto.prototype.sign = function (algorithm, key, data) {
        var that = this;
        return new Promise(function (resolve, reject) {
            var _data = ab2b(data);
            var _alg = prepare_algorithm(algorithm);
            var AlgClass = null;
            switch (_alg.name.toLowerCase()) {
                case rsa.RsaPKCS1.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaPKCS1;
                    break;
                case rsa.RsaPSS.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaPSS;
                    break;
                case ec.Ecdsa.ALGORITHM_NAME.toLowerCase():
                    AlgClass = ec.Ecdsa;
                    break;
                default:
                    throw new error.AlgorithmError(error.ERROR_WRONG_ALGORITHM, _alg.name);
            }
            AlgClass.sign(that.session, _alg, key, _data, function (err, signature) {
                if (err)
                    reject(err);
                else
                    resolve(b2ab(signature));
            });
        });
    };
    P11SubtleCrypto.prototype.verify = function (algorithm, key, signature, data) {
        var that = this;
        return new Promise(function (resolve, reject) {
            var _signature = ab2b(signature);
            var _data = ab2b(data);
            var _alg = prepare_algorithm(algorithm);
            var AlgClass = null;
            switch (_alg.name.toLowerCase()) {
                case rsa.RsaPKCS1.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaPKCS1;
                    break;
                case rsa.RsaPSS.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaPSS;
                    break;
                case ec.Ecdsa.ALGORITHM_NAME.toLowerCase():
                    AlgClass = ec.Ecdsa;
                    break;
                default:
                    throw new error.AlgorithmError(error.ERROR_WRONG_ALGORITHM, _alg.name);
            }
            AlgClass.verify(that.session, _alg, key, _signature, _data, function (err, verify) {
                if (err)
                    reject(err);
                else
                    resolve(verify);
            });
        });
    };
    P11SubtleCrypto.prototype.encrypt = function (algorithm, key, data) {
        var that = this;
        return new Promise(function (resolve, reject) {
            var _data = ab2b(data);
            var _alg = prepare_algorithm(algorithm);
            var AlgClass = null;
            switch (_alg.name.toLowerCase()) {
                case rsa.RsaOAEP.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaOAEP;
                    break;
                case aes.AesGCM.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesGCM;
                    break;
                case aes.AesCBC.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesCBC;
                    break;
                default:
                    throw new error.AlgorithmError(error.ERROR_WRONG_ALGORITHM, _alg.name);
            }
            AlgClass.encrypt(that.session, _alg, key, _data, function (err, enc) {
                if (err)
                    reject(err);
                else
                    resolve(b2ab(enc));
            });
        });
    };
    P11SubtleCrypto.prototype.decrypt = function (algorithm, key, data) {
        var that = this;
        return new Promise(function (resolve, reject) {
            var _data = ab2b(data);
            var _alg = prepare_algorithm(algorithm);
            var AlgClass = null;
            switch (_alg.name.toLowerCase()) {
                case rsa.RsaOAEP.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaOAEP;
                    break;
                case aes.AesGCM.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesGCM;
                    break;
                case aes.AesCBC.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesCBC;
                    break;
                default:
                    throw new error.AlgorithmError(error.ERROR_WRONG_ALGORITHM, _alg.name);
            }
            AlgClass.decrypt(that.session, _alg, key, _data, function (err, enc) {
                if (err)
                    reject(err);
                else
                    resolve(b2ab(enc));
            });
        });
    };
    P11SubtleCrypto.prototype.wrapKey = function (format, key, wrappingKey, wrapAlgorithm) {
        var that = this;
        return new Promise(function (resolve, reject) {
            var _alg = prepare_algorithm(wrapAlgorithm);
            var KeyClass;
            switch (_alg.name) {
                case aes.ALG_NAME_AES_CBC:
                    KeyClass = aes.AesCBC;
                    break;
                case aes.ALG_NAME_AES_GCM:
                    KeyClass = aes.AesGCM;
                    break;
                case rsa.ALG_NAME_RSA_OAEP:
                    KeyClass = rsa.RsaOAEP;
                    break;
                default:
                    throw new error.AlgorithmError(error.ERROR_WRONG_ALGORITHM, _alg.name);
            }
            KeyClass.wrapKey(that.session, format, key, wrappingKey, _alg, function (err, wkey) {
                if (err)
                    reject(err);
                else
                    resolve(b2ab(wkey));
            });
        });
    };
    P11SubtleCrypto.prototype.unwrapKey = function (format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages) {
        var that = this;
        return new Promise(function (resolve, reject) {
            var KeyClass;
            switch (unwrappingKey.algorithm.name) {
                case aes.ALG_NAME_AES_CBC:
                    KeyClass = aes.AesCBC;
                    break;
                case aes.ALG_NAME_AES_GCM:
                    KeyClass = aes.AesGCM;
                    break;
                case rsa.ALG_NAME_RSA_OAEP:
                    KeyClass = rsa.RsaOAEP;
                    break;
                default:
                    throw new error.AlgorithmError(error.ERROR_WRONG_ALGORITHM, unwrappingKey.algorithm.name);
            }
            var wrappedKeyBuffer = ab2b(wrappedKey);
            KeyClass.unwrapKey(that.session, format, wrappedKeyBuffer, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages, function (err, uwkey) {
                if (err)
                    reject(err);
                else
                    resolve(uwkey);
            });
        });
    };
    P11SubtleCrypto.prototype.deriveKey = function (algorithm, baseKey, derivedKeyType, extractable, keyUsages) {
        var that = this;
        return new Promise(function (resolve, reject) {
            var _alg1 = prepare_algorithm(algorithm);
            var _alg2 = prepare_algorithm(derivedKeyType);
            var AlgClass = null;
            switch (_alg1.name.toLowerCase()) {
                case ec.Ecdh.ALGORITHM_NAME.toLowerCase():
                    AlgClass = ec.Ecdh;
                    break;
                default:
                    throw new error.AlgorithmError(error.ERROR_WRONG_ALGORITHM, _alg1.name);
            }
            AlgClass.deriveKey(that.session, algorithm, baseKey, derivedKeyType, extractable, keyUsages, function (err, key) {
                if (err)
                    reject(err);
                else
                    resolve(key);
            });
        });
    };
    P11SubtleCrypto.prototype.exportKey = function (format, key) {
        var that = this;
        return new Promise(function (resolve, reject) {
            var KeyClass;
            switch (key.algorithm.name) {
                case aes.ALG_NAME_AES_CBC:
                    KeyClass = aes.AesCBC;
                    break;
                case aes.ALG_NAME_AES_GCM:
                    KeyClass = aes.AesGCM;
                    break;
                case rsa.ALG_NAME_RSA_PKCS1:
                    KeyClass = rsa.RsaPKCS1;
                    break;
                case rsa.ALG_NAME_RSA_OAEP:
                    KeyClass = rsa.RsaOAEP;
                    break;
                case ec.ALG_NAME_ECDSA:
                    KeyClass = ec.Ecdsa;
                    break;
                case ec.ALG_NAME_ECDH:
                    KeyClass = ec.Ecdh;
                    break;
                default:
                    throw new error.AlgorithmError(error.ERROR_WRONG_ALGORITHM, key.algorithm.name);
            }
            KeyClass.exportKey(that.session, format, key, function (err, data) {
                if (err)
                    reject(err);
                else {
                    if (Buffer.isBuffer(data)) {
                        var ubuf = new Uint8Array(data);
                        resolve(ubuf);
                    }
                    else
                        resolve(data);
                }
            });
        });
    };
    P11SubtleCrypto.prototype.importKey = function (format, keyData, algorithm, extractable, keyUsages) {
        var that = this;
        return new Promise(function (resolve, reject) {
            var _alg = prepare_algorithm(algorithm);
            var KeyClass;
            switch (_alg.name) {
                case aes.ALG_NAME_AES_CBC:
                    KeyClass = aes.AesCBC;
                    break;
                case aes.ALG_NAME_AES_GCM:
                    KeyClass = aes.AesGCM;
                    break;
                case rsa.ALG_NAME_RSA_PKCS1:
                    KeyClass = rsa.RsaPKCS1;
                    break;
                case rsa.ALG_NAME_RSA_OAEP:
                    KeyClass = rsa.RsaOAEP;
                    break;
                case ec.ALG_NAME_ECDSA:
                    KeyClass = ec.Ecdsa;
                    break;
                case ec.ALG_NAME_ECDH:
                    KeyClass = ec.Ecdh;
                    break;
                default:
                    throw new error.AlgorithmError(error.ERROR_WRONG_ALGORITHM, _alg.name);
            }
            var data;
            if (ArrayBuffer.isView(keyData)) {
                data = ab2b(keyData);
            }
            else
                data = keyData;
            KeyClass.importKey(that.session, format, data, _alg, extractable, keyUsages, function (err, key) {
                if (err)
                    reject(err);
                else
                    resolve(key);
            });
        });
    };
    P11SubtleCrypto.prototype.deriveBits = function (algorithm, baseKey, length) {
        var that = this;
        return new Promise(function (resolve, reject) {
            reject(new Error("Method is not implemented"));
        });
    };
    P11SubtleCrypto.prototype.digest = function (algorithm, data) {
        var that = this;
        return new Promise(function (resolve, reject) {
            var alg = prepare_algorithm(algorithm);
            var hashAlg = alg.name.toUpperCase();
            switch (hashAlg) {
                case "SHA-1":
                case "SHA-224":
                case "SHA-256":
                case "SHA-384":
                case "SHA-512":
                    hashAlg = hashAlg.replace("-", "");
            }
            var digest = that.session.createDigest(hashAlg);
            var buf = ab2b(data);
            digest.update(buf, function (err) {
                if (err)
                    reject(err);
                else
                    digest.final(function (err, md) {
                        if (err)
                            reject(err);
                        else
                            resolve(b2ab(md));
                    });
            });
        });
    };
    return P11SubtleCrypto;
}());
exports.P11SubtleCrypto = P11SubtleCrypto;
