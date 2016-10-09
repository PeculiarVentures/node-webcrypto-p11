"use strict";
var assert = require('assert');
var crypto = require('./config').crypto;

describe("WebCrypto", () => {

    it("get random values", () => {
        var buf = new Uint8Array(16);
        var check = new Buffer(buf).toString("base64");
        assert.notEqual(new Buffer(crypto.getRandomValues(buf)).toString("base64"), check, "Has no random values");
    })

    it("get random values with large buffer", () => {
        var buf = new Uint8Array(65600);
        assert.throws(() => {
            crypto.getRandomValues(buf);
        }, Error);
    })
})