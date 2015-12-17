var assert = require('assert');
var WebCrypto = require("../src/webcrypto.js").default;
var config = require("./config.js")

describe("Init", function () {
    var webcrypto;
    var keys = [];
    
    it("Init", function(){
        webcrypto = new WebCrypto(config);
		
		global.webcrypto = webcrypto;
		global.keys = keys;
        assert.notEqual(webcrypto == null, true, "WebCrypto is not initialized");
    })
})