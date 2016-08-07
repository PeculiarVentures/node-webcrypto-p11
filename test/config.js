module.exports = {
	library: "/usr/lib/softhsm/libsofthsm.so",
	name: "SoftHSM",
	slot: 0,
    sessionFlags: 4, // SERIAL_SESSION
	pin: "12345"
}
