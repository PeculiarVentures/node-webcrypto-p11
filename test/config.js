require("babel-polyfill");
var os = require("os");

var config = process.env.PV_CRYPTO === "nss" ?
	{
		library: os.platform() === "darwin" ?  "/usr/local/opt/nss/lib/libsoftokn3.dylib" : "/usr/lib/x86_64-linux-gnu/nss/libsoftokn3.so",
		libraryParameters: `configdir='' certPrefix='' keyPrefix='' secmod='' flags=readOnly,noCertDB,noModDB,forceOpen,optimizeSpace`,
		name: "NSS",
		slot: 1,
		readWrite: true,
	}
	:
	{
		library: "/usr/local/lib/softhsm/libsofthsm2.so",
		name: "SoftHSMv2",
		slot: 0,
		readWrite: true,
		pin: "12345"
	};
module.exports.config = config;

var WebCrypto = require("../").WebCrypto;

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

module.exports.isNSS = function isNSS(message) {
	return test_manufacturer("NSS", message);
}