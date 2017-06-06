const assert = require('assert');
const { crypto, config } = require('./config');

describe("WebCrypto", () => {

    it("get random values", () => {
        var buf = new Uint8Array(16);
        var check = new Buffer(buf).toString("base64");
        assert.notEqual(new Buffer(crypto.getRandomValues(buf)).toString("base64"), check, "Has no random values");
    })

    it("get random values with large buffer", () => {
        var buf = new Uint8Array(65600);
        assert.throws(() => {
            crypto.getRandomValues(buf);
        }, Error);
    })

    it("reset", (done) => {
        const currentHandle = crypto.session.handle.toString("hex");
        crypto.reset()
            .then(() => {
                crypto.login(config.pin);
                const newHandle = crypto.session.handle.toString("hex");
                assert(currentHandle !== newHandle, true, "handle of session wasn't changed");
            })
            .then(done, done);
    })
})