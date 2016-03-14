module.exports = {
	library: "/usr/local/lib/softhsm/libsofthsm2.so",
	name: "SoftHSM v2.0",
	slot: 0,
    sessionFlags: 4, // SERIAL_SESSION
	pin: "12345"
}