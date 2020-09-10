import * as assert from "assert";
import { Convert } from "pvtsutils";
import { EcCryptoKey } from "../src/mechs";
import { crypto } from "./config";

context("EC", () => {

  context("token", () => {

    it("generate", async () => {
      const alg: EcKeyGenParams = {
        name: "ECDSA",
        namedCurve: "P-256",
      };

      const keys = await crypto.subtle.generateKey(alg, false, ["sign", "verify"],
      {
        label: "custom",
        token: true,
        sensitive: true,
      }) as CryptoKeyPair;

      const privateKey = keys.privateKey as EcCryptoKey;
      assert.strictEqual(privateKey.token, true);
      assert.strictEqual(privateKey.label, "custom");
      assert.strictEqual(privateKey.sensitive, true);

      const publicKey = keys.publicKey as EcCryptoKey;
      assert.strictEqual(publicKey.token, true);
      assert.strictEqual(publicKey.label, "custom");
      assert.strictEqual(publicKey.sensitive, undefined);
    });

    it("import", async () => {
      const alg: EcKeyGenParams = {
        name: "ECDSA",
        namedCurve: "P-256",
      };
      const spki = Convert.FromBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEc7MvmXG6zXIRe0q6S9IWJxqeiAl++411K6TGJKtAbs32jxVnLvWGR+QElM0CRs/Xgit5g1xGywroh0cN3cJBbA==");

      const publicKey = await crypto.subtle.importKey("spki", spki, alg, false, ["verify"],
      {
        label: "custom",
        token: true,
        sensitive: true,
      }) as EcCryptoKey;

      assert.strictEqual(publicKey.token, true);
      assert.strictEqual(publicKey.label, "custom");
      assert.strictEqual(publicKey.sensitive, undefined);
    });

  });

});
