module.exports = {
	library: "/usr/local/lib/softhsm/libsofthsm2.so",
	name: "SoftHSMv2",
	slot: 0,
    sessionFlags: 4, // SERIAL_SESSION
	pin: "12345"
}
