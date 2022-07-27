import * as assert from "assert";
import { Convert } from "pvtsutils";
import { CryptoKey, Pkcs11RsaHashedImportParams, Pkcs11RsaHashedKeyGenParams } from "../src";
import { config, crypto } from "./config";
import { is } from "./helper";

const ERROR_METHOD_REQUIRED = "Crypto key requires re-authentication, but Crypto doesn't have 'onAlwaysAuthenticate' method";

(is(config.pin === undefined, "Tests require PIN usage")
  ? context.skip
  : context)
  ("CKA_ALWAYS_AUTHENTICATE", () => {

    type RsaSsaAlgorithm = RsaHashedKeyGenParams;
    type RsaPssAlgorithm = RsaHashedKeyGenParams & RsaPssParams;
    type RsaOaepAlgorithm = RsaHashedKeyGenParams & RsaOaepParams;
    type EcdsaAlgorithm = EcKeyGenParams & EcdsaParams;
    type VectorAlgorithms =
      RsaSsaAlgorithm |
      RsaPssAlgorithm |
      RsaOaepAlgorithm |
      EcdsaAlgorithm;

    interface Vector {
      algorithm: VectorAlgorithms,
      keyUsage: "sign" | "encrypt",
    }

    const vectors: Vector[] = [
      {
        algorithm: {
          name: "RSASSA-PKCS1-v1_5",
          hash: "SHA-256",
          publicExponent: new Uint8Array([1, 0, 1]),
          modulusLength: 2048,
        },
        keyUsage: "sign",
      },
      {
        algorithm: {
          name: "RSA-PSS",
          hash: "SHA-256",
          publicExponent: new Uint8Array([1, 0, 1]),
          modulusLength: 2048,
          saltLength: 10,
        },
        keyUsage: "sign",
      },
      {
        algorithm: {
          name: "RSA-OAEP",
          hash: "SHA-1",
          publicExponent: new Uint8Array([1, 0, 1]),
          modulusLength: 2048,
        },
        keyUsage: "encrypt",
      },
      {
        algorithm: {
          name: "ECDSA",
          hash: "SHA-256",
          namedCurve: "P-256",
        },
        keyUsage: "sign",
      },
    ];

    vectors.forEach(v => {
      context(v.algorithm.name, () => {

        let keys: CryptoKeyPair;
        let pin: string;
        const usages: KeyUsage[] = [];
        switch (v.keyUsage) {
          case "sign":
            usages.push("sign", "verify");
            break;
          case "encrypt":
            usages.push("encrypt", "decrypt");
            break;
        }

        before(async () => {
          assert.ok(config.pin, "PIN is required");
          pin = config.pin;

          keys = await crypto.subtle.generateKey({
            ...v.algorithm,
            alwaysAuthenticate: true,
          } as Pkcs11RsaHashedKeyGenParams, true, usages);

          assert.strictEqual((keys.privateKey as CryptoKey).alwaysAuthenticate, true);
          assert.strictEqual((keys.publicKey as CryptoKey).alwaysAuthenticate, undefined);
        });

        it("importKey", async () => {
          const pkcs8 = await crypto.subtle.exportKey("pkcs8", keys.privateKey);
          const key = await crypto.subtle.importKey("pkcs8", pkcs8, {
            ...v.algorithm,
            alwaysAuthenticate: true,
          } as Pkcs11RsaHashedImportParams, false, usages);
          assert.strictEqual(key.alwaysAuthenticate, true);
        });

        switch (v.keyUsage) {
          case "sign":
            it("onAlwaysAuthenticate is undefined", async () => {
              crypto.onAlwaysAuthenticate = undefined;

              await assert.rejects(async () => {
                await crypto.subtle.sign(v.algorithm, keys.privateKey, new Uint8Array(10));
              },
                new Error(ERROR_METHOD_REQUIRED));
            });

            it("skip C_Login", async () => {
              crypto.onAlwaysAuthenticate = () => null;

              await assert.rejects(async () => {
                await crypto.subtle.sign(v.algorithm, keys.privateKey, new Uint8Array(10));
              },
                (e) => e instanceof Error && e.message.includes("CKR_USER_NOT_LOGGED_IN"));
            });

            it(v.keyUsage, async () => {
              crypto.onAlwaysAuthenticate = () => pin;

              const signature1 = await crypto.subtle.sign(v.algorithm, keys.privateKey, new Uint8Array(10));
              assert.ok(signature1);
              const signature2 = await crypto.subtle.sign(v.algorithm, keys.privateKey, new Uint8Array(10));
              assert.ok(signature2);
            });

            it(`${v.keyUsage} with incorrect PIN`, async () => {
              const pin = config.pin;
              assert.ok(pin, "PIN is required");
              crypto.onAlwaysAuthenticate = () => `${pin}!`;

              await assert.rejects(async () => {
                await crypto.subtle.sign(v.algorithm, keys.privateKey, new Uint8Array(10));
              },
                (e) => {
                  return e instanceof Error && e.message.includes("CKR_PIN_INCORRECT");
                });
            });
            break;
          case "encrypt":
            const data = new Uint8Array(10);
            it("onAlwaysAuthenticate is undefined", async () => {
              crypto.onAlwaysAuthenticate = undefined;

              await assert.rejects(async () => {
                await crypto.subtle.decrypt(v.algorithm, keys.privateKey, data);
              },
                new Error(ERROR_METHOD_REQUIRED));
            });

            it("skip C_Login", async () => {
              crypto.onAlwaysAuthenticate = () => null;

              await assert.rejects(async () => {
                await crypto.subtle.decrypt(v.algorithm, keys.privateKey, data);
              },
                (e) => e instanceof Error && e.message.includes("CKR_USER_NOT_LOGGED_IN"));
            });

            it(v.keyUsage, async () => {
              crypto.onAlwaysAuthenticate = () => pin;

              let i = 2;
              while (i--) {
                const enc = await crypto.subtle.encrypt(v.algorithm, keys.publicKey, data);
                const dec = await crypto.subtle.decrypt(v.algorithm, keys.privateKey, enc);
                assert.strictEqual(Convert.ToHex(dec), Convert.ToHex(data));
              }
            });

            it(`${v.keyUsage} with incorrect PIN`, async () => {
              const pin = config.pin;
              assert.ok(pin, "PIN is required");
              crypto.onAlwaysAuthenticate = () => `${pin}!`;

              await assert.rejects(async () => {
                await crypto.subtle.decrypt(v.algorithm, keys.privateKey, data);
              },
                (e) => {
                  return e instanceof Error && e.message.includes("CKR_PIN_INCORRECT");
                });
            });
            break;
        }
      });
    });
  });
