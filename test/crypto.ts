import * as assert from "assert";
import { config, crypto } from "./config";

context("Crypto", () => {

  it("get random values", () => {
    const buf = new Uint8Array(16);
    const check = Buffer.from(buf).toString("base64");
    assert.notEqual(Buffer.from(crypto.getRandomValues(buf)).toString("base64"), check, "Has no random values");
  });

  it("get random values with large buffer", () => {
    const buf = new Uint8Array(65600);
    assert.throws(() => {
      crypto.getRandomValues(buf);
    }, Error);
  });

  it("reset", () => {
    const currentHandle = crypto.session.value.handle.toString("hex");
    crypto.reset();

    if (config.pin) {
      crypto.login(config.pin);
    }
    const newHandle = crypto.session.value.handle.toString("hex");
    assert.equal(currentHandle !== newHandle, true, "handle of session wasn't changed");
  });

});
