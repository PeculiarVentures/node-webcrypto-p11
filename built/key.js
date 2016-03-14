"use strict";
var graphene_pk11_1 = require("graphene-pk11");
var error = require("./error");
exports.KT_PRIVATE = "private";
exports.KT_PUBLIC = "public";
exports.KT_SECRET = "secret";
exports.KU_ENCRYPT = "encrypt";
exports.KU_DECRYPT = "decrypt";
exports.KU_SIGN = "sign";
exports.KU_VERIFY = "verify";
exports.KU_WRAP = "wrapKey";
exports.KU_UNWRAP = "unwrapKey";
exports.KU_DERIVE = "deriveKey";
var P11CryptoKey = (function () {
    function P11CryptoKey(key, alg) {
        this.usages = [];
        switch (key.class) {
            case graphene_pk11_1.ObjectClass.PUBLIC_KEY:
                this.initPublicKey(key.toType());
                break;
            case graphene_pk11_1.ObjectClass.PRIVATE_KEY:
                this.initPrivateKey(key.toType());
                break;
            case graphene_pk11_1.ObjectClass.SECRET_KEY:
                this.initSecretKey(key.toType());
                break;
            default:
                throw new error.WebCryptoError("Wrong incoming session object '" + graphene_pk11_1.ObjectClass[key.class] + "'");
        }
        this.algorithm = alg;
    }
    Object.defineProperty(P11CryptoKey.prototype, "key", {
        get: function () {
            return this._key;
        },
        enumerable: true,
        configurable: true
    });
    P11CryptoKey.prototype.initPrivateKey = function (key) {
        this._key = key;
        this.type = exports.KT_PRIVATE;
        this.extractable = key.extractable;
        this.usages = [];
        if (key.decrypt)
            this.usages.push(exports.KU_DECRYPT);
        if (key.derive)
            this.usages.push(exports.KU_DERIVE);
        if (key.sign)
            this.usages.push(exports.KU_SIGN);
        if (key.unwrap)
            this.usages.push(exports.KU_UNWRAP);
    };
    P11CryptoKey.prototype.initPublicKey = function (key) {
        this._key = key;
        this.type = exports.KT_PUBLIC;
        this.extractable = true;
        if (key.encrypt)
            this.usages.push(exports.KU_ENCRYPT);
        if (key.verify)
            this.usages.push(exports.KU_VERIFY);
        if (key.wrap)
            this.usages.push(exports.KU_WRAP);
    };
    P11CryptoKey.prototype.initSecretKey = function (key) {
        this._key = key;
        this.type = exports.KT_SECRET;
        this.extractable = key.extractable;
        if (key.encrypt)
            this.usages.push(exports.KU_ENCRYPT);
        if (key.verify)
            this.usages.push(exports.KU_VERIFY);
        if (key.wrap)
            this.usages.push(exports.KU_WRAP);
        if (key.decrypt)
            this.usages.push(exports.KU_DECRYPT);
        if (key.derive)
            this.usages.push(exports.KU_DERIVE);
        if (key.sign)
            this.usages.push(exports.KU_SIGN);
        if (key.unwrap)
            this.usages.push(exports.KU_UNWRAP);
    };
    return P11CryptoKey;
}());
exports.P11CryptoKey = P11CryptoKey;
