module.exports = {
	library: "/usr/local/lib/softhsm/libsofthsm2.so",
	name: "SoftHSMv2",
	slot: 0,
    sessionFlags: 2 | 4,
	pin: "12345"
}

function test_manufacturer(manufacturerID) {
	if (module.exports.name === manufacturerID) {
		console.warn("    \x1b[33mWARN:\x1b[0m Test is not supported for %s", manufacturerID);
		return true;
	}
	return false;
}

module.exports.isSoftHSM = function isSoftHSM() {
	return test_manufacturer("SoftHSMv2");
}