import * as assert from "assert";
import { Pkcs11RsaHashedImportParams, Pkcs11RsaHashedKeyGenParams } from "../src";
import { RsaCryptoKey } from "../src/mechs";
import { crypto } from "./config";

context("RSA", () => {

  context("token", () => {

    it("generate", async () => {
      const alg: Pkcs11RsaHashedKeyGenParams = {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256",
        publicExponent: new Uint8Array([1, 0, 1]),
        modulusLength: 2048,
        label: "custom",
        token: true,
        sensitive: true,
      };

      const keys = await crypto.subtle.generateKey(alg, false, ["sign", "verify"]);

      const privateKey = keys.privateKey as RsaCryptoKey;
      assert.strictEqual(privateKey.algorithm.token, true);
      assert.strictEqual(privateKey.algorithm.label, alg.label);
      assert.strictEqual(privateKey.algorithm.sensitive, true);

      const publicKey = keys.publicKey as RsaCryptoKey;
      assert.strictEqual(publicKey.algorithm.token, true);
      assert.strictEqual(publicKey.algorithm.label, alg.label);
      assert.strictEqual(publicKey.algorithm.sensitive, false);
    });

    it("import", async () => {
      const alg: Pkcs11RsaHashedImportParams = {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256",
        label: "custom",
        token: true,
        sensitive: true,
      };
      const jwk = {
        alg: "RS256",
        e: "AQAB",
        ext: true,
        key_ops: ["verify"],
        kty: "RSA",
        n: "vqpvdxuyZ6rKYnWTj_ZzDBFZAAAlpe5hpoiYHqa2j5kK7v8U5EaPY2bLib9m4B40j-n3FV9xUCGiplWdqMJJKT-4PjGO5E3S4N9kjFhu57noYT7z7302J0sJXeoFbXxlgE-4G55Oxlm52ID2_RJesP5nzcGTriQwoRbrJP5OEt0",
      };

      const publicKey = await crypto.subtle.importKey("jwk", jwk, alg, true, ["verify"]) as RsaCryptoKey;

      assert.strictEqual(publicKey.algorithm.token, true);
      assert.strictEqual(publicKey.algorithm.label, alg.label);
      assert.strictEqual(publicKey.algorithm.sensitive, false);
    });

  });

  it("RSA 3072bits", async () => {
    const alg: globalThis.RsaHashedKeyGenParams = {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
      publicExponent: new Uint8Array([1, 0, 1]),
      modulusLength: 3072,
    };
    const keys = await crypto.subtle.generateKey(alg, false, ["sign", "verify"]);

    assert.strictEqual((keys.privateKey.algorithm as unknown as RsaHashedKeyAlgorithm).modulusLength, 3072);
  });

  context("RSAES-PKCS1-v1_5", () => {
    it("generate + encrypt/decrypt", async () => {
      const alg = {
        name: "RSAES-PKCS1-v1_5",
        publicExponent: new Uint8Array([1, 0, 1]),
        modulusLength: 2048,
      } as RsaHashedKeyGenParams;
      const keys = await crypto.subtle.generateKey(alg, true, ["encrypt", "decrypt"]);

      const data = Buffer.from("test message");

      const enc = await crypto.subtle.encrypt(alg, keys.publicKey, data);
      const dec = await crypto.subtle.decrypt(alg, keys.privateKey, enc);

      assert.deepStrictEqual(Buffer.from(dec), data);
    });

    it("generate + encrypt/decrypt (with alwaysAuthenticate)", async () => {
      const alg = {
        name: "RSAES-PKCS1-v1_5",
        publicExponent: new Uint8Array([1, 0, 1]),
        modulusLength: 2048,
        alwaysAuthenticate: true,
      } as unknown as RsaHashedKeyGenParams;
      const keys = await crypto.subtle.generateKey(alg, true, ["encrypt", "decrypt"]);

      const data = Buffer.from("test message");

      const enc = await crypto.subtle.encrypt(alg, keys.publicKey, data);
      const dec = await crypto.subtle.decrypt(alg, keys.privateKey, enc);

      assert.deepStrictEqual(Buffer.from(dec), data);
    });
  });
});
