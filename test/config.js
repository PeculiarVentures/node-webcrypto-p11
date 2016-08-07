module.exports = {
	library: "/usr/lib/libsofthsm.so",
	name: "SoftHSM",
	slot: 0,
    sessionFlags: 4, // SERIAL_SESSION
	pin: "6789"
}
