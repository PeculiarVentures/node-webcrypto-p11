import * as assert from "assert";
import { HmacCryptoKey } from "../src/mechs";
import { crypto } from "./config";

context("HMAC", () => {

  context("token", () => {

    it("generate", async () => {
      const alg: HmacKeyGenParams = {
        name: "HMAC",
        hash: "SHA-256",
      };

      const key = await crypto.subtle.generateKey(alg, false, ["sign", "verify"],
        {
          label: "custom",
          token: true,
          sensitive: true,
        }) as HmacCryptoKey;

      assert.strictEqual(key.token, true);
      assert.strictEqual(key.label, "custom");
      assert.strictEqual(key.sensitive, true);
    });

    it("import", async () => {
      const alg: HmacImportParams = {
        name: "HMAC",
        hash: "SHA-256",
      };
      const raw = Buffer.from("1234567890abcdef1234567809abcdef");

      const key = await crypto.subtle.importKey("raw", raw, alg, false, ["sign", "verify"],
        {
          label: "custom",
          token: true,
          sensitive: true,
        }) as HmacCryptoKey;

      assert.strictEqual(key.token, true);
      assert.strictEqual(key.label, "custom");
      assert.strictEqual(key.sensitive, true);
    });

  });

});
