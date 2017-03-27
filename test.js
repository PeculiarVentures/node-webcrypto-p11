// const library = "/usr/local/lib/libykcs11.dylib";
const library = "/usr/local/lib/softhsm/libsofthsm2.so";

const p11crypto = require(".");


const MESSAGE = new Buffer("test message");

const crypto = new p11crypto.WebCrypto({
    library,
    readWrite: true,
    pin: "12345",
});

console.log(crypto.info);

crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
    .then((keys) => {
        return crypto.keyStorage.clear()
            .then(() => {
                return crypto.keyStorage.keys()
            })
            .then((indexes) => {
                console.log(indexes);
                // return crypto.keyStorage.setItem(keys.privateKey);
            })
            .then((index) => {
                console.log(index);
                return crypto.keyStorage.getItem(index);
            })
            .then((key) => {
                console.log(key.toJSON());
            })
    })
    .catch((err) => {
        console.error(err);
    })