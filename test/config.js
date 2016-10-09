var config = {
	library: "/usr/local/lib/softhsm/libsofthsm2.so",
	name: "SoftHSMv2",
	slot: 0,
    sessionFlags: 2 | 4,
	pin: "12345"
}

var WebCrypto = require("../built/webcrypto.js").WebCrypto;     
    
module.exports.crypto = new WebCrypto(config);

function test_manufacturer(manufacturerID, message) {
	if (config.name === manufacturerID) {
		console.warn("    \x1b[33mWARN:\x1b[0m Test is not supported for %s. %s", manufacturerID, message || "");
		return true;
	}
	return false;
}

module.exports.isSoftHSM = function isSoftHSM(message) {
	return test_manufacturer("SoftHSMv2", message);
}