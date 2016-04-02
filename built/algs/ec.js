"use strict";
var __extends = (this && this.__extends) || function (d, b) {
    for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p];
    function __() { this.constructor = d; }
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
};
var graphene_pk11_1 = require("graphene-pk11");
var error = require("../error");
var aes = require("./aes");
var base64url = require("base64url");
var utils = require("../utils");
var alg_1 = require("./alg");
var key_1 = require("../key");
exports.ALG_NAME_ECDH = "ECDH";
exports.ALG_NAME_ECDSA = "ECDSA";
function create_template(session, alg, extractable, keyUsages) {
    var label = "EC-" + alg.namedCurve;
    var id_pk = new Buffer(utils.GUID(session));
    var id_pubk = new Buffer(utils.GUID(session));
    var keyType = graphene_pk11_1.KeyType.ECDSA;
    return {
        privateKey: {
            token: !!process.env["WEBCRYPTO_PKCS11_TOKEN"],
            sensitive: !!process.env["WEBCRYPTO_PKCS11_SENSITIVE"],
            class: graphene_pk11_1.ObjectClass.PRIVATE_KEY,
            keyType: keyType,
            private: true,
            label: label,
            id: id_pk,
            extractable: extractable,
            derive: keyUsages.indexOf(key_1.KU_DERIVE) !== -1,
            sign: keyUsages.indexOf(key_1.KU_SIGN) !== -1,
            decrypt: keyUsages.indexOf(key_1.KU_DECRYPT) !== -1,
            unwrap: keyUsages.indexOf(key_1.KU_UNWRAP) !== -1
        },
        publicKey: {
            token: !!process.env["WEBCRYPTO_PKCS11_TOKEN"],
            class: graphene_pk11_1.ObjectClass.PUBLIC_KEY,
            keyType: keyType,
            label: label,
            id: id_pubk,
            derive: keyUsages.indexOf(key_1.KU_DERIVE) !== -1,
            verify: keyUsages.indexOf(key_1.KU_VERIFY) !== -1,
            encrypt: keyUsages.indexOf(key_1.KU_ENCRYPT) !== -1,
            wrap: keyUsages.indexOf(key_1.KU_WRAP) !== -1,
        }
    };
}
var Ec = (function (_super) {
    __extends(Ec, _super);
    function Ec() {
        _super.apply(this, arguments);
    }
    Ec.getNamedCurve = function (name) {
        var namedCurve;
        switch (name) {
            case "P-192":
                namedCurve = "secp192r1";
                break;
            case "P-256":
                namedCurve = "secp256r1";
                break;
            case "P-384":
                namedCurve = "secp384r1";
                break;
            case "P-521":
                namedCurve = "secp521r1";
                break;
            default:
                throw new Error("Unsupported namedCurve in use " + namedCurve);
        }
        return graphene_pk11_1.NamedCurve.getByName(namedCurve);
    };
    Ec.generateKey = function (session, alg, extractable, keyUsages, callback) {
        try {
            var _alg_1 = alg;
            this.checkAlgorithmIdentifier(alg);
            this.checkKeyGenAlgorithm(_alg_1);
            var template = create_template(session, _alg_1, extractable, keyUsages);
            template.publicKey.paramsEC = this.getNamedCurve(_alg_1.namedCurve).value;
            session.generateKeyPair(graphene_pk11_1.KeyGenMechanism.EC, template.publicKey, template.privateKey, function (err, keys) {
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
    Ec.checkKeyGenAlgorithm = function (alg) {
        this.checkAlgorithmParams(alg);
    };
    Ec.checkAlgorithmParams = function (alg) {
        this.checkAlgorithmIdentifier(alg);
        if (!alg.namedCurve)
            throw new TypeError("EcParams: namedCurve: Missing required property");
        switch (alg.namedCurve.toUpperCase()) {
            case "P-192":
            case "P-256":
            case "P-384":
            case "P-521":
                break;
            default:
                throw new TypeError("EcParams: namedCurve: Wrong value. Can be P-256, P-384, or P-521");
        }
        alg.namedCurve = alg.namedCurve.toUpperCase();
    };
    Ec.checkAlgorithmHashedParams = function (alg) {
        _super.checkAlgorithmHashedParams.call(this, alg);
        var _alg = alg.hash;
        _alg.name = _alg.name.toUpperCase();
        if (alg_1.RSA_HASH_ALGS.indexOf(_alg.name) === -1)
            throw new error.AlgorithmError(error.ERROR_WRONG_ALGORITHM, _alg.name);
    };
    Ec.exportJwkPublicKey = function (session, key, callback) {
        try {
            this.checkPublicKey(key);
            var pkey = key.key.getAttribute({
                pointEC: null
            });
            var curve = this.getNamedCurve(key.algorithm.namedCurve);
            var ecPoint = EcUtils.decodePoint(pkey.pointEC, curve);
            var jwk = {
                kty: "EC",
                crv: key.algorithm.namedCurve,
                ext: true,
                key_ops: key.usages,
                x: base64url(ecPoint.x),
                y: base64url(ecPoint.y),
            };
            callback(null, jwk);
        }
        catch (e) {
            callback(e, null);
        }
    };
    Ec.exportJwkPrivateKey = function (session, key, callback) {
        try {
            this.checkPrivateKey(key);
            var pkey = key.key.getAttribute({
                value: null
            });
            var jwk = {
                kty: "EC",
                crv: key.algorithm.namedCurve,
                ext: true,
                key_ops: key.usages,
                d: base64url(pkey.value)
            };
            callback(null, jwk);
        }
        catch (e) {
            callback(e, null);
        }
    };
    Ec.exportKey = function (session, format, key, callback) {
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
    Ec.importJwkPrivateKey = function (session, jwk, algorithm, extractable, keyUsages, callback) {
        try {
            var namedCurve = this.getNamedCurve(jwk.crv);
            var template = create_template(session, algorithm, extractable, keyUsages).privateKey;
            template.paramsEC = namedCurve.value;
            template.value = base64url.toBuffer(jwk.d);
            var p11key = session.create(template);
            callback(null, new key_1.P11CryptoKey(p11key, algorithm));
        }
        catch (e) {
            callback(e, null);
        }
    };
    Ec.importJwkPublicKey = function (session, jwk, algorithm, extractable, keyUsages, callback) {
        try {
            var namedCurve = this.getNamedCurve(jwk.crv);
            var template = create_template(session, algorithm, extractable, keyUsages).publicKey;
            template.paramsEC = namedCurve.value;
            var pointEc = EcUtils.encodePoint({ x: base64url.toBuffer(jwk.x), y: base64url.toBuffer(jwk.y) }, namedCurve);
            template.pointEC = pointEc;
            var p11key = session.create(template);
            callback(null, new key_1.P11CryptoKey(p11key, algorithm));
        }
        catch (e) {
            callback(e, null);
        }
    };
    Ec.importKey = function (session, format, keyData, algorithm, extractable, keyUsages, callback) {
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
    return Ec;
}(alg_1.AlgorithmBase));
exports.Ec = Ec;
var Ecdsa = (function (_super) {
    __extends(Ecdsa, _super);
    function Ecdsa() {
        _super.apply(this, arguments);
    }
    Ecdsa.wc2pk11 = function (alg, key) {
        var _alg = null;
        switch (alg.hash.name.toUpperCase()) {
            case "SHA-1":
                _alg = "ECDSA_SHA1";
                break;
            case "SHA-224":
                _alg = "ECDSA_SHA224";
                break;
            case "SHA-256":
                _alg = "ECDSA_SHA256";
                break;
            case "SHA-384":
                _alg = "ECDSA_SHA384";
                break;
            case "SHA-512":
                _alg = "ECDSA_SHA512";
                break;
            default:
                throw new error.AlgorithmError(error.ERROR_WRONG_ALGORITHM, key.algorithm.hash.name);
        }
        return { name: _alg, params: null };
    };
    Ecdsa.onCheck = function (method, paramName, paramValue) {
        switch (method) {
            case "sign":
                switch (paramName) {
                    case "alg":
                        this.checkAlgorithmHashedParams(paramValue);
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
                        this.checkAlgorithmHashedParams(paramValue);
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
    Ecdsa.ALGORITHM_NAME = exports.ALG_NAME_ECDSA;
    return Ecdsa;
}(Ec));
exports.Ecdsa = Ecdsa;
var Ecdh = (function (_super) {
    __extends(Ecdh, _super);
    function Ecdh() {
        _super.apply(this, arguments);
    }
    Ecdh.deriveKey = function (session, algorithm, baseKey, derivedKeyType, extractable, keyUsages, callback) {
        try {
            this.checkAlgorithmParams(algorithm);
            if (!algorithm.public)
                throw new TypeError("EcParams: public: Missing required property");
            this.checkPublicKey(algorithm.public);
            this.checkPrivateKey(baseKey);
            if (typeof derivedKeyType !== "object")
                throw TypeError("derivedKeyType: AlgorithmIdentifier: Algorithm must be an Object");
            if (!(derivedKeyType.name && typeof (derivedKeyType.name) === "string"))
                throw TypeError("derivedKeyType: AlgorithmIdentifier: Missing required property name");
            var AesClass = null;
            switch (derivedKeyType.name.toLowerCase()) {
                case aes.AesGCM.ALGORITHM_NAME.toLowerCase():
                    AesClass = aes.AesGCM;
                    break;
                case aes.AesCBC.ALGORITHM_NAME.toLowerCase():
                    AesClass = aes.AesCBC;
                    break;
                default:
                    throw new Error("derivedKeyType: Unknown Algorithm name in use");
            }
            AesClass.checkKeyGenAlgorithm(derivedKeyType);
            var template = aes.create_template(session, derivedKeyType, extractable, keyUsages);
            template.valueLen = derivedKeyType.length / 8;
            session.deriveKey({
                name: "ECDH1_DERIVE",
                params: new graphene_pk11_1.EcdhParams(graphene_pk11_1.EcKdf.NULL, null, algorithm.public.key.getAttribute({ pointEC: null }).pointEC)
            }, baseKey.key, template, function (err, key) {
                if (err)
                    callback(err, null);
                else
                    callback(null, new key_1.P11CryptoKey(key, derivedKeyType));
            });
        }
        catch (e) {
            callback(e, null);
        }
    };
    Ecdh.ALGORITHM_NAME = exports.ALG_NAME_ECDH;
    return Ecdh;
}(Ec));
exports.Ecdh = Ecdh;
var EcUtils = (function () {
    function EcUtils() {
    }
    EcUtils.getData = function (data) {
        var octet = false;
        for (var i = 0; i < data.length; i++) {
            if (data[i] === 4) {
                if (octet)
                    return data.slice(i);
                else
                    octet = true;
            }
        }
        throw new Error("Wrong data");
    };
    EcUtils.decodePoint = function (data, curve) {
        data = this.getData(data);
        if ((data.length === 0) || (data[0] !== 4)) {
            throw new Error("Only uncompressed point format supported");
        }
        var n = (data.length - 1) / 2;
        if (n !== (curve.size / 8)) {
            throw new Error("Point does not match field size");
        }
        var xb = data.slice(1, 1 + n);
        var yb = data.slice(n + 1, n + 1 + n);
        return { x: xb, y: yb };
    };
    EcUtils.encodePoint = function (point, curve) {
        var n = curve.size / 8;
        var xb = this.trimZeroes(point.x);
        var yb = this.trimZeroes(point.y);
        if ((xb.length > n) || (yb.length > n)) {
            throw new Error("Point coordinates do not match field size");
        }
        var b = Buffer.concat([new Buffer([4]), xb, yb]);
        var octet = Buffer.concat([new Buffer([4]), this.encodeAsn1Length(b.length), b]);
        return octet;
    };
    EcUtils.trimZeroes = function (b) {
        var i = 0;
        while ((i < b.length - 1) && (b[i] === 0)) {
            i++;
        }
        if (i === 0) {
            return b;
        }
        return b.slice(i, b.length);
    };
    EcUtils.encodeAsn1Length = function (length) {
        var enc = [];
        if (length !== (length & 0x7F)) {
            var code = length.toString(16);
            var _length = Math.round(code.length / 2);
            enc[0] = _length | 0x80;
            if (Math.floor(code.length % 2) > 0)
                code = "0" + code;
            for (var i = 0; i < code.length; i = i + 2) {
                enc[1 + (i / 2)] = parseInt(code.substring(i, i + 2), 16);
            }
        }
        else {
            enc[0] = length;
        }
        return new Buffer(enc);
    };
    return EcUtils;
}());
