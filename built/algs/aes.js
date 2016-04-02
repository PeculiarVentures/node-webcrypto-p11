"use strict";
var __extends = (this && this.__extends) || function (d, b) {
    for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p];
    function __() { this.constructor = d; }
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
};
var graphene_pk11_1 = require("graphene-pk11");
var error = require("../error");
var base64url = require("base64url");
var utils = require("../utils");
var alg_1 = require("./alg");
var key_1 = require("../key");
exports.ALG_NAME_AES_CTR = "AES-CTR";
exports.ALG_NAME_AES_CBC = "AES-CBC";
exports.ALG_NAME_AES_CMAC = "AES-CMAC";
exports.ALG_NAME_AES_GCM = "AES-GCM";
exports.ALG_NAME_AES_CFB = "AES-CFB";
exports.ALG_NAME_AES_KW = "AES-KW";
var AesError = (function (_super) {
    __extends(AesError, _super);
    function AesError() {
        _super.apply(this, arguments);
    }
    return AesError;
}(error.WebCryptoError));
function create_template(session, alg, extractable, keyUsages) {
    var id = utils.GUID(session);
    return {
        token: !!process.env["WEBCRYPTO_PKCS11_TOKEN"],
        sensitive: !!process.env["WEBCRYPTO_PKCS11_SENSITIVE"],
        class: graphene_pk11_1.ObjectClass.SECRET_KEY,
        keyType: graphene_pk11_1.KeyType.AES,
        label: "AES-" + alg.length,
        id: new Buffer(id),
        extractable: extractable,
        derive: false,
        sign: keyUsages.indexOf(key_1.KU_SIGN) !== -1,
        verify: keyUsages.indexOf(key_1.KU_VERIFY) !== -1,
        encrypt: keyUsages.indexOf(key_1.KU_ENCRYPT) !== -1,
        decrypt: keyUsages.indexOf(key_1.KU_DECRYPT) !== -1,
        wrap: keyUsages.indexOf(key_1.KU_WRAP) !== -1,
        unwrap: keyUsages.indexOf(key_1.KU_UNWRAP) !== -1,
    };
}
exports.create_template = create_template;
var Aes = (function (_super) {
    __extends(Aes, _super);
    function Aes() {
        _super.apply(this, arguments);
    }
    Aes.generateKey = function (session, alg, extractable, keyUsages, callback) {
        try {
            var _alg_1 = alg;
            this.checkAlgorithmIdentifier(alg);
            this.checkKeyGenAlgorithm(_alg_1);
            var template = create_template(session, _alg_1, extractable, keyUsages);
            template.valueLen = alg.length / 8;
            session.generateKey(graphene_pk11_1.KeyGenMechanism.AES, template, function (err, key) {
                try {
                    if (err)
                        callback(err, null);
                    else {
                        var wcKey = new key_1.P11CryptoKey(key, _alg_1);
                        callback(null, wcKey);
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
    Aes.onCheck = function (method, paramName, paramValue) {
        switch (method) {
            case "encrypt":
                switch (paramName) {
                    case "alg":
                        break;
                    case "key":
                        this.checkSecretKey(paramValue);
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
                        this.checkSecretKey(paramValue);
                        break;
                    case "data":
                        break;
                }
                break;
        }
    };
    Aes.exportKey = function (session, format, key, callback) {
        try {
            var vals = key.key.getAttribute({ value: null, valueLen: null });
            switch (format.toLowerCase()) {
                case "jwk":
                    var aes = /AES-(\w+)/.exec(key.algorithm.name)[1];
                    var jwk = {
                        kty: "oct",
                        k: base64url.encode(vals.value),
                        alg: "A" + vals.valueLen * 8 + aes,
                        ext: true
                    };
                    callback(null, jwk);
                    break;
                case "raw":
                    callback(null, vals.value);
            }
        }
        catch (e) {
            callback(e, null);
        }
    };
    Aes.importKey = function (session, format, keyData, algorithm, extractable, keyUsages, callback) {
        try {
            var value = void 0;
            if (format === "jwk")
                value = base64url.toBuffer(keyData.k);
            else
                value = keyData;
            var _alg = {
                name: algorithm.name,
                length: value.length * 8
            };
            var template = create_template(session, _alg, extractable, keyUsages);
            template.value = value;
            var sobj = session.create(template);
            callback(null, new key_1.P11CryptoKey(sobj.toType(), _alg));
        }
        catch (e) {
            callback(e, null);
        }
    };
    Aes.checkAlgorithmParams = function (alg) { };
    Aes.checkKeyGenAlgorithm = function (alg) {
        this.checkAlgorithmIdentifier(alg);
        if (!alg.length)
            throw new AesError("length: Missing required property");
        switch (alg.length) {
            case 128:
            case 192:
            case 256:
                break;
            default:
                throw new AesError("length: Wrong value. Can be 128, 192, or 256");
        }
    };
    Aes.checkAlgorithmHashedParams = function (alg) {
        _super.checkAlgorithmHashedParams.call(this, alg);
        var _alg = alg.hash;
        _alg.name = _alg.name.toUpperCase();
        if (alg_1.RSA_HASH_ALGS.indexOf(_alg.name) === -1)
            throw new error.AlgorithmError(error.ERROR_WRONG_ALGORITHM, _alg.name);
    };
    Aes.wc2pk11 = function (alg, key) {
        throw new Error("Not realized");
    };
    return Aes;
}(alg_1.AlgorithmBase));
var AesGCM = (function (_super) {
    __extends(AesGCM, _super);
    function AesGCM() {
        _super.apply(this, arguments);
    }
    AesGCM.wc2pk11 = function (alg) {
        var aad = alg.additionalData ? new Buffer(new Uint8Array(alg.additionalData)) : null;
        var params = new graphene_pk11_1.AesGcmParams(alg.iv, aad, alg.tagLength);
        return { name: "AES_GCM", params: params };
    };
    AesGCM.checkAlgorithmParams = function (alg) {
        this.checkAlgorithmIdentifier(alg);
        if (!alg.iv)
            throw new error.AlgorithmError("iv: Missing required property");
        if (!alg.tagLength)
            alg.tagLength = 128;
        switch (alg.tagLength) {
            case 32:
            case 64:
            case 96:
            case 104:
            case 112:
            case 120:
            case 128:
                break;
            default:
                throw new error.AlgorithmError("tagLength: Wrong value, can be 32, 64, 96, 104, 112, 120 or 128 (default)");
        }
    };
    AesGCM.ALGORITHM_NAME = exports.ALG_NAME_AES_GCM;
    return AesGCM;
}(Aes));
exports.AesGCM = AesGCM;
var AesCBC = (function (_super) {
    __extends(AesCBC, _super);
    function AesCBC() {
        _super.apply(this, arguments);
    }
    AesCBC.wc2pk11 = function (alg, key) {
        return { name: "AES_CBC_PAD", params: alg.iv };
    };
    AesCBC.checkAlgorithmParams = function (alg) {
        this.checkAlgorithmIdentifier(alg);
        if (!alg.iv)
            throw new error.AlgorithmError("iv: Missing required property");
    };
    AesCBC.ALGORITHM_NAME = exports.ALG_NAME_AES_CBC;
    return AesCBC;
}(Aes));
exports.AesCBC = AesCBC;
