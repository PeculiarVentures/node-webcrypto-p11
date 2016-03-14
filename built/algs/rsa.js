"use strict";
var __extends = (this && this.__extends) || function (d, b) {
    for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p];
    function __() { this.constructor = d; }
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
};
var graphene_pk11_1 = require("graphene-pk11");
var error = require("../error");
var base64url = require("base64url");
var alg_1 = require("./alg");
var key_1 = require("../key");
var aes = require("./aes");
exports.ALG_NAME_RSA_PKCS1 = "RSASSA-PKCS1-v1_5";
var ALG_NAME_RSA_PSS = "RSA-PSS";
exports.ALG_NAME_RSA_OAEP = "RSA-OAEP";
function create_template(alg, extractable, keyUsages) {
    var label = "RSA-" + alg.modulusLength;
    var id = new Buffer(new Date().getTime().toString());
    return {
        privateKey: {
            token: !!process.env["WEBCRYPTO_PKCS11_TOKEN"],
            class: graphene_pk11_1.ObjectClass.PRIVATE_KEY,
            keyType: graphene_pk11_1.KeyType.RSA,
            private: true,
            label: label,
            id: id,
            extractable: extractable,
            derive: false,
            sign: keyUsages.indexOf(key_1.KU_SIGN) !== -1,
            decrypt: keyUsages.indexOf(key_1.KU_DECRYPT) !== -1,
            unwrap: keyUsages.indexOf(key_1.KU_UNWRAP) !== -1
        },
        publicKey: {
            token: !!process.env["WEBCRYPTO_PKCS11_TOKEN"],
            class: graphene_pk11_1.ObjectClass.PUBLIC_KEY,
            keyType: graphene_pk11_1.KeyType.RSA,
            label: label,
            id: id,
            verify: keyUsages.indexOf(key_1.KU_VERIFY) !== -1,
            encrypt: keyUsages.indexOf(key_1.KU_ENCRYPT) !== -1,
            wrap: keyUsages.indexOf(key_1.KU_WRAP) !== -1,
        }
    };
}
var Rsa = (function (_super) {
    __extends(Rsa, _super);
    function Rsa() {
        _super.apply(this, arguments);
    }
    Rsa.generateKey = function (session, alg, extractable, keyUsages, callback) {
        try {
            var _alg_1 = alg;
            this.checkAlgorithmIdentifier(alg);
            this.checkAlgorithmHashedParams(alg);
            this.checkKeyGenAlgorithm(_alg_1);
            var template = create_template(_alg_1, extractable, keyUsages);
            template.publicKey.publicExponent = new Buffer(_alg_1.publicExponent),
                template.publicKey.modulusBits = _alg_1.modulusLength;
            session.generateKeyPair(graphene_pk11_1.KeyGenMechanism.RSA, template.publicKey, template.privateKey, function (err, keys) {
                try {
                    if (err)
                        callback(err, null);
                    else {
                        var wcKeyPair = {
                            privateKey: new key_1.P11CryptoKey(keys.privateKey, _alg_1),
                            publicKey: new key_1.P11CryptoKey(keys.publicKey, _alg_1)
                        };
                        callback(null, wcKeyPair);
                    }
                }
                catch (e) {
                    callback(e, null);
                }
            });
        }
        catch (e) {
            callback(e, null);
        }
    };
    Rsa.checkKeyGenAlgorithm = function (alg) {
        if (!alg.modulusLength)
            throw new TypeError("RsaKeyGenParams: modulusLength: Missing required property");
        if (alg.modulusLength < 256 || alg.modulusLength > 16384)
            throw new TypeError("RsaKeyGenParams: The modulus length must be a multiple of 8 bits and >= 256 and <= 16384");
        if (!(alg.publicExponent && alg.publicExponent instanceof Uint8Array))
            throw new TypeError("RsaKeyGenParams: publicExponent: Missing or not a Uint8Array");
    };
    Rsa.checkAlgorithmHashedParams = function (alg) {
        _super.checkAlgorithmHashedParams.call(this, alg);
        var _alg = alg.hash;
        _alg.name = _alg.name.toUpperCase();
        if (alg_1.RSA_HASH_ALGS.indexOf(_alg.name) === -1)
            throw new error.AlgorithmError(error.ERROR_WRONG_ALGORITHM, _alg.name);
    };
    Rsa.jwkAlgName = function (alg) {
        throw new Error("Not implemented");
    };
    Rsa.exportJwkPublicKey = function (session, key, callback) {
        try {
            this.checkPublicKey(key);
            var pkey = key.key.getAttribute({
                publicExponent: null,
                modulus: null
            });
            var alg = this.jwkAlgName(key.algorithm);
            var jwk = {
                kty: "RSA",
                alg: alg,
                ext: true,
                key_ops: key.usages,
                e: base64url(pkey.publicExponent),
                n: base64url(pkey.modulus)
            };
            callback(null, jwk);
        }
        catch (e) {
            callback(e, null);
        }
    };
    Rsa.exportJwkPrivateKey = function (session, key, callback) {
        try {
            this.checkPrivateKey(key);
            var pkey = key.key.getAttribute({
                publicExponent: null,
                modulus: null,
                privateExponent: null,
                prime1: null,
                prime2: null,
                exp1: null,
                exp2: null,
                coefficient: null
            });
            var alg = this.jwkAlgName(key.algorithm);
            var jwk = {
                kty: "RSA",
                alg: alg,
                ext: true,
                key_ops: key.usages,
                e: base64url(pkey.publicExponent),
                n: base64url(pkey.modulus),
                d: base64url(pkey.privateExponent),
                p: base64url(pkey.prime1),
                q: base64url(pkey.prime2),
                dp: base64url(pkey.exp1),
                dq: base64url(pkey.exp2),
                qi: base64url(pkey.coefficient)
            };
            callback(null, jwk);
        }
        catch (e) {
            callback(e, null);
        }
    };
    Rsa.exportKey = function (session, format, key, callback) {
        try {
            switch (format.toLowerCase()) {
                case "jwk":
                    if (key.type === "private")
                        this.exportJwkPrivateKey(session, key, callback);
                    else
                        this.exportJwkPublicKey(session, key, callback);
                default:
                    throw new Error("Not supported format '" + format + "'");
            }
        }
        catch (e) {
            callback(e, null);
        }
    };
    Rsa.importJwkPrivateKey = function (session, jwk, algorithm, extractable, keyUsages, callback) {
        try {
            var template = create_template(algorithm, extractable, keyUsages).privateKey;
            template.publicExponent = base64url.toBuffer(jwk.e);
            template.modulus = base64url.toBuffer(jwk.n);
            template.privateExponent = base64url.toBuffer(jwk.d);
            template.prime1 = base64url.toBuffer(jwk.p);
            template.prime2 = base64url.toBuffer(jwk.q);
            template.exp1 = base64url.toBuffer(jwk.dp);
            template.exp2 = base64url.toBuffer(jwk.dq);
            template.coefficient = base64url.toBuffer(jwk.qi);
            var p11key = session.create(template);
            callback(null, new key_1.P11CryptoKey(p11key, algorithm));
        }
        catch (e) {
            callback(e, null);
        }
    };
    Rsa.importJwkPublicKey = function (session, jwk, algorithm, extractable, keyUsages, callback) {
        try {
            var template = create_template(algorithm, extractable, keyUsages).publicKey;
            template.publicExponent = base64url.toBuffer(jwk.e);
            template.modulus = base64url.toBuffer(jwk.n);
            var p11key = session.create(template);
            callback(null, new key_1.P11CryptoKey(p11key, algorithm));
        }
        catch (e) {
            callback(e, null);
        }
    };
    Rsa.importKey = function (session, format, keyData, algorithm, extractable, keyUsages, callback) {
        try {
            switch (format.toLowerCase()) {
                case "jwk":
                    var jwk = keyData;
                    if (jwk.d)
                        this.importJwkPrivateKey(session, jwk, algorithm, extractable, keyUsages, callback);
                    else
                        this.importJwkPublicKey(session, jwk, algorithm, extractable, keyUsages, callback);
                default:
                    throw new Error("Not supported format '" + format + "'");
            }
        }
        catch (e) {
            callback(e, null);
        }
    };
    return Rsa;
}(alg_1.AlgorithmBase));
var RsaPKCS1 = (function (_super) {
    __extends(RsaPKCS1, _super);
    function RsaPKCS1() {
        _super.apply(this, arguments);
    }
    RsaPKCS1.wc2pk11 = function (alg, key) {
        var res = null;
        switch (key.algorithm.hash.name.toUpperCase()) {
            case "SHA-1":
                res = "SHA1_RSA_PKCS";
                break;
            case "SHA-224":
                res = "SHA224_RSA_PKCS";
                break;
            case "SHA-256":
                res = "SHA256_RSA_PKCS";
                break;
            case "SHA-384":
                res = "SHA384_RSA_PKCS";
                break;
            case "SHA-512":
                res = "SHA512_RSA_PKCS";
                break;
            default:
                throw new error.AlgorithmError(error.ERROR_WRONG_ALGORITHM, alg.hash.name);
        }
        return { name: res, params: null };
    };
    RsaPKCS1.jwkAlgName = function (alg) {
        var algName = /(\d+)$/.exec(alg.hash.name)[1];
        return "RS" + (algName === "1" ? "" : algName);
    };
    RsaPKCS1.onCheck = function (method, paramName, paramValue) {
        switch (method) {
            case "sign":
                switch (paramName) {
                    case "alg":
                        break;
                    case "key":
                        this.checkPrivateKey(paramValue);
                        break;
                    case "data":
                        break;
                }
                break;
            case "verify":
                switch (paramName) {
                    case "alg":
                        break;
                    case "key":
                        this.checkPublicKey(paramValue);
                        break;
                    case "data":
                        break;
                }
                break;
        }
    };
    RsaPKCS1.ALGORITHM_NAME = exports.ALG_NAME_RSA_PKCS1;
    return RsaPKCS1;
}(Rsa));
exports.RsaPKCS1 = RsaPKCS1;
var RsaOAEP = (function (_super) {
    __extends(RsaOAEP, _super);
    function RsaOAEP() {
        _super.apply(this, arguments);
    }
    RsaOAEP.jwkAlgName = function (alg) {
        var algName = /(\d+)$/.exec(alg.hash.name)[1];
        return "RSA-OAEP" + (algName === "1" ? "" : ("-" + algName));
    };
    RsaOAEP.onCheck = function (method, paramName, paramValue) {
        switch (method) {
            case "encrypt":
                switch (paramName) {
                    case "alg":
                        break;
                    case "key":
                        this.checkPublicKey(paramValue);
                        break;
                    case "data":
                        break;
                }
                break;
            case "decrypt":
                switch (paramName) {
                    case "alg":
                        break;
                    case "key":
                        this.checkPrivateKey(paramValue);
                        break;
                    case "data":
                        break;
                }
                break;
        }
    };
    RsaOAEP.wrapKey = function (session, format, key, wrappingKey, alg, callback) {
        try {
            if (format === "raw") {
                var _alg = this.wc2pk11(alg, wrappingKey);
                session.wrapKey(_alg, wrappingKey.key, key.key, callback);
            }
            else
                _super.wrapKey.apply(this, arguments);
        }
        catch (e) {
            callback(e, null);
        }
    };
    RsaOAEP.unwrapKey = function (session, format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedAlgorithm, extractable, keyUsages, callback) {
        try {
            if (format === "raw") {
                var _alg = this.wc2pk11(unwrapAlgorithm, unwrappingKey);
                var template = aes.create_template(unwrappedAlgorithm, extractable, keyUsages);
                session.unwrapKey(_alg, unwrappingKey.key, wrappedKey, template, function (err, p11key) {
                    if (err)
                        callback(err, null);
                    else
                        callback(null, new key_1.P11CryptoKey(p11key, unwrappedAlgorithm));
                });
            }
            else
                _super.unwrapKey.apply(this, arguments);
        }
        catch (e) {
            callback(e, null);
        }
    };
    RsaOAEP.wc2pk11 = function (alg, key) {
        var params = null;
        switch (key.algorithm.hash.name.toUpperCase()) {
            case "SHA-1":
                params = new graphene_pk11_1.RsaOaepParams(graphene_pk11_1.MechanismEnum.SHA1, graphene_pk11_1.RsaMgf.MGF1_SHA1);
                break;
            case "SHA-224":
                params = new graphene_pk11_1.RsaOaepParams(graphene_pk11_1.MechanismEnum.SHA224, graphene_pk11_1.RsaMgf.MGF1_SHA224);
                break;
            case "SHA-256":
                params = new graphene_pk11_1.RsaOaepParams(graphene_pk11_1.MechanismEnum.SHA256, graphene_pk11_1.RsaMgf.MGF1_SHA256);
                break;
            case "SHA-384":
                params = new graphene_pk11_1.RsaOaepParams(graphene_pk11_1.MechanismEnum.SHA384, graphene_pk11_1.RsaMgf.MGF1_SHA384);
                break;
            case "SHA-512":
                params = new graphene_pk11_1.RsaOaepParams(graphene_pk11_1.MechanismEnum.SHA512, graphene_pk11_1.RsaMgf.MGF1_SHA512);
                break;
            default:
                throw new error.AlgorithmError(error.ERROR_WRONG_ALGORITHM, key.algorithm.hash.name);
        }
        var res = { name: "RSA_PKCS_OAEP", params: params };
        return res;
    };
    RsaOAEP.ALGORITHM_NAME = exports.ALG_NAME_RSA_OAEP;
    return RsaOAEP;
}(Rsa));
exports.RsaOAEP = RsaOAEP;
var RsaPSS = (function (_super) {
    __extends(RsaPSS, _super);
    function RsaPSS() {
        _super.apply(this, arguments);
    }
    RsaPSS.ALGORITHM_NAME = ALG_NAME_RSA_PSS;
    return RsaPSS;
}(Rsa));
exports.RsaPSS = RsaPSS;
