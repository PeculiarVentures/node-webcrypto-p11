var assert = require('assert');

describe("EC", function () {
    var webcrypto;
    var keys;
    
    before(function(done){
        webcrypto = global.webcrypto;
        keys = global.keys;
        done();
    })
    
    var TEST_MESSAGE = new Buffer("This is test message for crypto functions");

    it("Ecdsa", function (done) {
        
        var key = null;
		webcrypto.subtle.generateKey(
			{
				name: "ECDSA",
				namedCurve: "P-256", 	//can be "P-256", "P-384", or "P-521"
			},
			false, 						//whether the key is extractable (i.e. can be used in exportKey)
			["sign", "verify"] 			//can be any combination of "sign" and "verify"
        )
        .then(function(k){
            assert.equal(k.privateKey !== null, true, "Has no private key");
            assert.equal(k.publicKey !== null, true, "Has no public key");
            key = k;
            keys.push(key)
            return webcrypto.subtle.sign(
				{
					name: "ECDSA",
					hash: {name: "SHA-256"}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
				}, 
				key.privateKey, 
				TEST_MESSAGE) 
        })
        .then(function(sig){
            assert.equal(sig !== null, true, "Has no signature value");
            assert.notEqual(sig.length, 0, "Has empty signature value");
            return webcrypto.subtle.verify(
                {
                    name: "ECDSA",
                    hash: {name: "SHA-256"}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
                }, 
                key.publicKey, 
                sig, 
                TEST_MESSAGE
            )
        })
        .then(function(v){
            assert.equal(v, true, "Ecdsa signature is not valid")
            console.log("TEST")
        })
        .then(done, done);
    })
    
})