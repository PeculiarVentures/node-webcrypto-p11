"use strict";
var __extends = (this && this.__extends) || function (d, b) {
    for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p];
    function __() { this.constructor = d; }
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
};
exports.ERROR_WRONG_ALGORITHM = "Unsupported algorithm in use '%1'";
exports.ERROR_NOT_SUPPORTED_METHOD = "Method is not supported";
function printf(text) {
    var args = [];
    for (var _i = 1; _i < arguments.length; _i++) {
        args[_i - 1] = arguments[_i];
    }
    var msg = text;
    var regFind = /[^%](%\d+)/g;
    var match = null;
    var matches = [];
    while (match = regFind.exec(msg)) {
        matches.push({ arg: match[1], index: match.index });
    }
    for (var i = matches.length - 1; i >= 0; i--) {
        var item = matches[i];
        var arg = item.arg.substring(1);
        var index = item.index + 1;
        msg = msg.substring(0, index) + arguments[+arg] + msg.substring(index + 1 + arg.length);
    }
    msg = msg.replace("%%", "%");
    return msg;
}
var WebCryptoError = (function (_super) {
    __extends(WebCryptoError, _super);
    function WebCryptoError(template) {
        var args = [];
        for (var _i = 1; _i < arguments.length; _i++) {
            args[_i - 1] = arguments[_i];
        }
        _super.call(this);
        this.message = printf.apply(this, arguments);
        this.stack = (new Error(this.message)).stack;
    }
    return WebCryptoError;
}(Error));
exports.WebCryptoError = WebCryptoError;
var AlgorithmError = (function (_super) {
    __extends(AlgorithmError, _super);
    function AlgorithmError() {
        _super.apply(this, arguments);
    }
    return AlgorithmError;
}(WebCryptoError));
exports.AlgorithmError = AlgorithmError;
var CryptoKeyError = (function (_super) {
    __extends(CryptoKeyError, _super);
    function CryptoKeyError() {
        _super.apply(this, arguments);
    }
    return CryptoKeyError;
}(WebCryptoError));
exports.CryptoKeyError = CryptoKeyError;
