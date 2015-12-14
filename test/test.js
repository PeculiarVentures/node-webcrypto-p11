var assert = require('assert');
var WebCrypto = require("../src/webcrypto.js").P11WebCrypto;
var config = require("./config.js")
describe("test", function () {
    var webcrypto;

    before(function () {
		webcrypto = new WebCrypto(config);
    })

    after(function () {
		webcrypto.close();
    })

    it("generate RSA PKCS1 1.5", function () {
		webcrypto.subtle.generateKey({name:"RSASSA-PKCS1-v1_5", hash: "SHA-1"}, false, ["sign", "verify"])
        .then(function(k){
            console.log(k)
        })
        .catch(function(e){
            console.error('Error:', e.message, e.stack);
        })
    })
})