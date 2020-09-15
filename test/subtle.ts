import * as assert from "assert";
import * as graphene from "graphene-pk11";
import { ID_DIGEST } from "../src/const";
import { CryptoKey as P11CryptoKey } from "../src/key";
import { crypto } from "./config";

context("Subtle", () => {

  async function getId(publicKey: CryptoKey) {
    const raw = await crypto.subtle.exportKey("spki", publicKey);
    const hash = await (await crypto.subtle.digest(ID_DIGEST, raw)).slice(0, 16);
    return Buffer.from(hash).toString("hex");
  }

  context("key must have id equals to SHA-1 of public key raw", () => {

    context("generate key", () => {

      before(async () => {
        crypto.keyStorage.clear();
      });

      after(async () => {
        crypto.keyStorage.clear();
      });

      [
        { name: "RSA-PSS", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 1024 },
        { name: "ECDSA", namedCurve: "P-256" },
      ].map((alg) => {
        it(alg.name, async () => {
          const keys = await crypto.subtle.generateKey(alg, false, ["sign", "verify"]) as CryptoKeyPair;

          const id = await getId(keys.publicKey);
          assert.strictEqual((keys.publicKey as P11CryptoKey).key.id.toString("hex"), id);
          assert.strictEqual((keys.publicKey as P11CryptoKey).id.includes(id), true);
          assert.strictEqual((keys.publicKey as P11CryptoKey).p11Object.token, false);
          assert.strictEqual((keys.privateKey as P11CryptoKey).p11Object.token, false);
          assert.strictEqual(((keys.privateKey as P11CryptoKey).p11Object as graphene.PrivateKey).sensitive, false);
        });
      });

      context("pkcs11 attributes", () => {
        [
          {
            alg: { name: "RSA-PSS", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 1024 },
            attrs: { token: true, sensitive: true, label: "RSA-PSS" }
          },
          {
            alg: { name: "ECDSA", namedCurve: "P-256" },
            attrs: { token: true, sensitive: true, label: "ECDSA" }
          },
        ].map(({ alg, attrs }) => {
          it(alg.name, async () => {
            const keys = await crypto.subtle.generateKey(alg, false, ["sign", "verify"], attrs) as CryptoKeyPair;

            const id = await getId(keys.publicKey);
            assert.strictEqual((keys.publicKey as P11CryptoKey).key.id.toString("hex"), id);
            assert.strictEqual((keys.publicKey as P11CryptoKey).id.includes(id), true);
            assert.strictEqual((keys.publicKey as P11CryptoKey).p11Object.token, true);
            assert.strictEqual((keys.publicKey as P11CryptoKey).p11Object.label, alg.name);
            assert.strictEqual((keys.privateKey as P11CryptoKey).p11Object.token, true);
            assert.strictEqual(((keys.privateKey as P11CryptoKey).p11Object as graphene.PrivateKey).sensitive, true);
            assert.strictEqual((keys.privateKey as P11CryptoKey).p11Object.label, alg.name);
          });
        });
      });

    });

    context("import key", () => {

      const spki = Buffer.from("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEoZMMqyfA16N6bvloFHmalk/SGMisr3zSXFZdR8F9UkaY7hF13hHiQtwp2YO+1zd7jwYi1Y7SMA9iUrC+ap2OCw==", "base64");

      it("extractable public key", async () => {
        const key = await crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" } as EcKeyImportParams, true, ["verify"]);

        const id = await getId(key);
        assert.strictEqual((key as P11CryptoKey).key.id.toString("hex"), id);
        assert.strictEqual((key as P11CryptoKey).id.includes(id), true);
      });

      it("don't try to update id if key is not extractable", async () => {
        const key = await crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" } as EcKeyImportParams, false, ["verify"]);

        assert.notEqual((key as P11CryptoKey).key.id.toString("hex"), "69e4556056c8d300eff3d4523fc6515d9f833fe6");
      });

    });

  });

});
