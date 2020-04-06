import * as assert from "assert";
import { Convert } from "pvtsutils";
import { EcCryptoKey } from "../src/mechs";
import { crypto } from "./config";

context("EC", () => {

  context("token", () => {

    it("generate", async () => {
      const alg: Pkcs11EcKeyGenParams = {
        name: "ECDSA",
        namedCurve: "P-256",
        label: "custom",
        token: true,
        sensitive: true,
      };

      const keys = await crypto.subtle.generateKey(alg, false, ["sign", "verify"]) as CryptoKeyPair;

      const privateKey = keys.privateKey as EcCryptoKey;
      assert.equal(privateKey.algorithm.token, true);
      assert.equal(privateKey.algorithm.label, alg.label);
      assert.equal(privateKey.algorithm.sensitive, true);

      const publicKey = keys.publicKey as EcCryptoKey;
      assert.equal(publicKey.algorithm.token, true);
      assert.equal(publicKey.algorithm.label, alg.label);
      assert.equal(publicKey.algorithm.sensitive, false);
    });

    it("import", async () => {
      const alg: Pkcs11EcKeyGenParams = {
        name: "ECDSA",
        namedCurve: "P-256",
        label: "custom",
        token: true,
        sensitive: true,
      };
      const spki = Convert.FromBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEc7MvmXG6zXIRe0q6S9IWJxqeiAl++411K6TGJKtAbs32jxVnLvWGR+QElM0CRs/Xgit5g1xGywroh0cN3cJBbA==");

      const publicKey = await crypto.subtle.importKey("spki", spki, alg, false, ["verify"]) as EcCryptoKey;

      assert.equal(publicKey.algorithm.token, true);
      assert.equal(publicKey.algorithm.label, alg.label);
      assert.equal(publicKey.algorithm.sensitive, false);
    });

  });

});
