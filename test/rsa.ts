import * as assert from "assert";
import { RsaCryptoKey } from "../src/mechs";
import { crypto } from "./config";

context("RSA", () => {

  context("token", () => {

    it("generate", async () => {
      const alg: RsaHashedKeyGenParams = {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256",
        publicExponent: new Uint8Array([1, 0, 1]),
        modulusLength: 2048,
      };

      const keys = await crypto.subtle.generateKey(alg, false, ["sign", "verify"],
        {
          label: "custom",
          token: true,
          sensitive: true,
        }) as CryptoKeyPair;

      const privateKey = keys.privateKey as RsaCryptoKey;
      assert.strictEqual(privateKey.token, true);
      assert.strictEqual(privateKey.label, "custom");
      assert.strictEqual(privateKey.sensitive, true);

      const publicKey = keys.publicKey as RsaCryptoKey;
      assert.strictEqual(publicKey.token, true);
      assert.strictEqual(publicKey.label, "custom");
      assert.strictEqual(publicKey.sensitive, undefined);
    });

    it("import", async () => {
      const alg: RsaHashedImportParams = {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256",
      };
      const jwk = {
        alg: "RS256",
        e: "AQAB",
        ext: true,
        key_ops: ["verify"],
        kty: "RSA",
        n: "vqpvdxuyZ6rKYnWTj_ZzDBFZAAAlpe5hpoiYHqa2j5kK7v8U5EaPY2bLib9m4B40j-n3FV9xUCGiplWdqMJJKT-4PjGO5E3S4N9kjFhu57noYT7z7302J0sJXeoFbXxlgE-4G55Oxlm52ID2_RJesP5nzcGTriQwoRbrJP5OEt0",
      };

      const publicKey = await crypto.subtle.importKey("jwk", jwk, alg, true, ["verify"],
      {
        label: "custom",
        token: true,
        sensitive: true,
      }) as RsaCryptoKey;

      assert.strictEqual(publicKey.token, true);
      assert.strictEqual(publicKey.label, "custom");
      assert.strictEqual(publicKey.sensitive, undefined);
    });

  });

});
