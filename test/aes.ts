import * as assert from "assert";
import { AesCryptoKey } from "../src/mechs";
import { crypto } from "./config";

context("AES", () => {

  context("token", () => {

    it("generate", async () => {
      const alg: AesKeyGenParams = {
        name: "AES-CBC",
        length: 128,
      };

      const key = await crypto.subtle.generateKey(alg, false, ["encrypt", "decrypt"],
        {
          label: "custom",
          token: true,
          sensitive: true,
        }) as AesCryptoKey;

      assert.strictEqual(key.token, true);
      assert.strictEqual(key.label, "custom");
      assert.strictEqual(key.sensitive, true);
    });

    it("import", async () => {
      const alg: Algorithm = {
        name: "AES-CBC",
      };
      const raw = Buffer.from("1234567890abcdef1234567809abcdef");

      const key = await crypto.subtle.importKey("raw", raw, alg, false, ["encrypt", "decrypt"],
        {
          label: "custom",
          token: true,
          sensitive: true,
        }) as AesCryptoKey;

      assert.strictEqual(key.token, true);
      assert.strictEqual(key.label, "custom");
      assert.strictEqual(key.sensitive, true);
    });

  });

});
