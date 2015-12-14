var assert = require('assert');
var WebCrypto = require("../src/webcrypto.js").default;
var config = require("./config.js")

describe("test", function () {
    var webcrypto;

    before(function () {
    })

    after(function () {
    })

    it("generate RSA PKCS1 1.5", function () {
		webcrypto = new WebCrypto(config);
        
		webcrypto.subtle.generateKey({
            name:"RSASSA-PKCS1-v1_5",
            modulusLength: 1024,
            publicExponent: new Uint8Array([1, 0, 1]), 
            hash: {
                name: "SHA-1"
            }}, 
            false, 
            ["sign", "verify"]
        )
        .then(function(k){
            console.log(k);
        })
        .catch(function(e){
            console.error('Error:', e.message, e.stack);
        })
    })
})