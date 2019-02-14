import { Convert } from "pvtsutils";
import * as core from "webcrypto-core";
import { crypto } from "./config";
import { testCrypto } from "./helper";

context("AES", () => {

  testCrypto(crypto, [
    //#region AES-CBC
    {
      name: "AES-128-CBC",
      actions: {
        generateKey: [
          {
            algorithm: { name: "AES-CBC", length: 128 } as AesKeyGenParams,
            extractable: true,
            keyUsages: ["encrypt", "decrypt"] as KeyUsage[],
          },
        ],
        encrypt: [
          {
            algorithm: {
              name: "AES-CBC",
              iv: Buffer.from("1234567890abcdef"),
            } as AesCbcParams,
            data: Buffer.from("test message"),
            encData: Buffer.from("d5df3ea1598defe7446420802baef28e", "hex"),
            key: {
              format: "raw" as KeyFormat,
              data: Buffer.from("1234567890abcdef"),
              algorithm: { name: "AES-CBC" },
              extractable: true,
              keyUsages: ["encrypt", "decrypt"] as KeyUsage[],
            },
          },
        ],
        import: [
          {
            name: "raw",
            format: "raw" as KeyFormat,
            data: Buffer.from("1234567890abcdef"),
            algorithm: "AES-CBC",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"] as KeyUsage[],
          },
          {
            name: "wrong key size",
            error: core.OperationError,
            format: "raw" as KeyFormat,
            data: Buffer.from("12345678"),
            algorithm: "AES-CBC",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"] as KeyUsage[],
          },
          {
            name: "jwk",
            format: "jwk" as KeyFormat,
            data: {
              kty: "oct",
              alg: "A128CBC",
              k: "MTIzNDU2Nzg5MGFiY2RlZg",
              ext: true,
              key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            algorithm: "AES-CBC",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"] as KeyUsage[],
          },
        ],
        wrapKey: [
          {
            key: {
              format: "raw",
              algorithm: "AES-CBC",
              data: Convert.FromBase64("AQIDBAUGBwgJAAECAwQFBg"),
              extractable: true,
              keyUsages: ["wrapKey", "unwrapKey"],
            },
            wKey: {
              format: "raw" as KeyFormat,
              data: Buffer.from("1234567890abcdef"),
              algorithm: "AES-CBC",
              extractable: true,
              keyUsages: ["encrypt", "decrypt"],
            },
            algorithm: {
              name: "AES-CBC",
              iv: Buffer.from("1234567890abcdef"),
            } as AesCbcParams,
          },
        ],
      },
    },
    {
      name: "AES-192-CBC",
      actions: {
        generateKey: [
          {
            algorithm: { name: "AES-CBC", length: 192 } as AesKeyGenParams,
            extractable: true,
            keyUsages: ["encrypt", "decrypt"] as KeyUsage[],
          },
        ],
        encrypt: [
          {
            algorithm: {
              name: "AES-CBC",
              iv: Buffer.from("1234567890abcdef"),
            } as AesCbcParams,
            data: Buffer.from("test message"),
            encData: Buffer.from("67d0b3022149829bf009ad4aff19963a", "hex"),
            key: {
              format: "raw" as KeyFormat,
              data: Buffer.from("1234567890abcdef12345678"),
              algorithm: { name: "AES-CBC" },
              extractable: true,
              keyUsages: ["encrypt", "decrypt"] as KeyUsage[],
            },
          },
        ],
        import: [
          {
            name: "raw",
            format: "raw" as KeyFormat,
            data: Buffer.from("1234567890abcdef12345678"),
            algorithm: "AES-CBC",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"] as KeyUsage[],
          },
          {
            name: "jwk",
            format: "jwk",
            data: {
              kty: "oct",
              alg: "A192CBC",
              k: "MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4",
              ext: true,
              key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            algorithm: "AES-CBC",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
        ],
      },
    },
    {
      name: "AES-256-CBC",
      actions: {
        generateKey: [
          {
            algorithm: { name: "AES-CBC", length: 256 } as AesKeyGenParams,
            extractable: true,
            keyUsages: ["encrypt", "decrypt"],
          },
        ],
        encrypt: [
          {
            algorithm: {
              name: "AES-CBC",
              iv: Buffer.from("1234567890abcdef"),
            } as AesCbcParams,
            data: Buffer.from("test message"),
            encData: Buffer.from("d827c1c6aee9f0f552c62f30ddee83af", "hex"),
            key: {
              format: "raw",
              data: Buffer.from("1234567890abcdef1234567809abcdef"),
              algorithm: { name: "AES-CBC" },
              extractable: true,
              keyUsages: ["encrypt", "decrypt"],
            },
          },
        ],
        import: [
          {
            name: "raw",
            format: "raw",
            data: Buffer.from("1234567890abcdef1234567890abcdef"),
            algorithm: "AES-CBC",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
          {
            name: "jwk",
            format: "jwk",
            data: {
              kty: "oct",
              alg: "A256CBC",
              k: "MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4OTBhYmNkZWY",
              ext: true,
              key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            algorithm: "AES-CBC",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
        ],
      },
    },
    //#endregion

    //#region AES-GCM
    {
      name: "AES-128-GCM",
      actions: {
        generateKey: [
          {
            algorithm: { name: "AES-GCM", length: 128 } as AesKeyGenParams,
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
        ],
        encrypt: [
          {
            algorithm: {
              name: "AES-GCM",
              iv: Buffer.from("1234567890ab"),
            } as AesGcmParams,
            data: Buffer.from("test message"),
            encData: Buffer.from("68d645649ddf8152a253304d698185072f28cdcf7644ac6064bcb240", "hex"),
            key: {
              format: "raw",
              data: Buffer.from("1234567890abcdef"),
              algorithm: { name: "AES-GCM" },
              extractable: true,
              keyUsages: ["encrypt", "decrypt"],
            },
          },
        ],
        import: [
          {
            name: "raw",
            format: "raw",
            data: Buffer.from("1234567890abcdef"),
            algorithm: "AES-GCM",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
          {
            name: "jwk",
            format: "jwk",
            data: {
              kty: "oct",
              alg: "A128GCM",
              k: "MTIzNDU2Nzg5MGFiY2RlZg",
              ext: true,
              key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            algorithm: "AES-GCM",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
        ],
      },
    },
    {
      name: "AES-192-GCM",
      actions: {
        generateKey: [
          {
            algorithm: { name: "AES-GCM", length: 192 } as AesKeyGenParams,
            extractable: true,
            keyUsages: ["encrypt", "decrypt"],
          },
        ],
        encrypt: [
          {
            algorithm: {
              name: "AES-GCM",
              iv: Buffer.from("1234567890ab"),
            } as AesGcmParams,
            data: Buffer.from("test message"),
            encData: Buffer.from("d8eab579ed2418f41ca9c4567226f54cb391d3ca2cb6819dace35691", "hex"),
            key: {
              format: "raw",
              data: Buffer.from("1234567890abcdef12345678"),
              algorithm: { name: "AES-GCM" },
              extractable: true,
              keyUsages: ["encrypt", "decrypt"],
            },
          },
        ],
        import: [
          {
            name: "raw",
            format: "raw",
            data: Buffer.from("1234567890abcdef12345678"),
            algorithm: "AES-GCM",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
          {
            name: "jwk",
            format: "jwk",
            data: {
              kty: "oct",
              alg: "A192GCM",
              k: "MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4",
              ext: true,
              key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            algorithm: "AES-GCM",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
        ],
      },
    },
    {
      name: "AES-256-GCM",
      actions: {
        generateKey: [
          {
            algorithm: { name: "AES-GCM", length: 256 } as AesKeyGenParams,
            extractable: true,
            keyUsages: ["encrypt", "decrypt"],
          },
        ],
        encrypt: [
          {
            algorithm: {
              name: "AES-GCM",
              iv: Buffer.from("1234567890ab"),
            } as AesGcmParams,
            data: Buffer.from("test message"),
            encData: Buffer.from("f961f2aadbe689ffce86fcaf2619ab647950afcf19e55b71b857c79d", "hex"),
            key: {
              format: "raw",
              data: Buffer.from("1234567890abcdef1234567809abcdef"),
              algorithm: { name: "AES-GCM" },
              extractable: true,
              keyUsages: ["encrypt", "decrypt"],
            },
          },
        ],
        import: [
          {
            name: "raw",
            format: "raw",
            data: Buffer.from("1234567890abcdef1234567890abcdef"),
            algorithm: "AES-GCM",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
          {
            name: "jwk",
            format: "jwk",
            data: {
              kty: "oct",
              alg: "A256GCM",
              k: "MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4OTBhYmNkZWY",
              ext: true,
              key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            algorithm: "AES-GCM",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
        ],
      },
    },
    //#endregion

    //#region AES-ECB
    {
      name: "AES-128-ECB",
      actions: {
        generateKey: [
          {
            algorithm: { name: "AES-ECB", length: 128 } as AesKeyGenParams,
            extractable: true,
            keyUsages: ["encrypt", "decrypt"] as KeyUsage[],
          },
        ],
        encrypt: [
          {
            algorithm: { name: "AES-ECB" },
            data: Buffer.from("test message"),
            encData: Buffer.from("c6ec2f91a9f48e10062ae41e86cb299f", "hex"),
            key: {
              format: "raw" as KeyFormat,
              data: Buffer.from("1234567890abcdef"),
              algorithm: { name: "AES-ECB" },
              extractable: true,
              keyUsages: ["encrypt", "decrypt"] as KeyUsage[],
            },
          },
        ],
        import: [
          {
            name: "raw",
            format: "raw" as KeyFormat,
            data: Buffer.from("1234567890abcdef"),
            algorithm: "AES-ECB",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"] as KeyUsage[],
          },
          {
            name: "wrong key size",
            error: core.OperationError,
            format: "raw" as KeyFormat,
            data: Buffer.from("12345678"),
            algorithm: "AES-ECB",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"] as KeyUsage[],
          },
          {
            name: "jwk",
            format: "jwk" as KeyFormat,
            data: {
              kty: "oct",
              alg: "A128ECB",
              k: "MTIzNDU2Nzg5MGFiY2RlZg",
              ext: true,
              key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            algorithm: "AES-ECB",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"] as KeyUsage[],
          },
        ],
        wrapKey: [
          {
            key: {
              format: "raw",
              algorithm: "AES-ECB",
              data: Convert.FromBase64("AQIDBAUGBwgJAAECAwQFBg"),
              extractable: true,
              keyUsages: ["wrapKey", "unwrapKey"],
            },
            wKey: {
              format: "raw" as KeyFormat,
              data: Buffer.from("1234567890abcdef"),
              algorithm: "AES-ECB",
              extractable: true,
              keyUsages: ["encrypt", "decrypt"],
            },
            algorithm: {
              name: "AES-ECB",
            },
          },
        ],
      },
    },
    {
      name: "AES-192-ECB",
      actions: {
        generateKey: [
          {
            algorithm: { name: "AES-ECB", length: 192 } as AesKeyGenParams,
            extractable: true,
            keyUsages: ["encrypt", "decrypt"] as KeyUsage[],
          },
        ],
        encrypt: [
          {
            algorithm: {
              name: "AES-ECB",
            },
            data: Buffer.from("test message"),
            encData: Buffer.from("8C9F297827AD6AAA9E7501E79FB45CA5", "hex"),
            key: {
              format: "raw" as KeyFormat,
              data: Buffer.from("1234567890abcdef12345678"),
              algorithm: { name: "AES-ECB" },
              extractable: true,
              keyUsages: ["encrypt", "decrypt"] as KeyUsage[],
            },
          },
        ],
        import: [
          {
            name: "raw",
            format: "raw" as KeyFormat,
            data: Buffer.from("1234567890abcdef12345678"),
            algorithm: "AES-ECB",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"] as KeyUsage[],
          },
          {
            name: "jwk",
            format: "jwk",
            data: {
              kty: "oct",
              alg: "A192ECB",
              k: "MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4",
              ext: true,
              key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            algorithm: "AES-ECB",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
        ],
      },
    },
    {
      name: "AES-256-ECB",
      actions: {
        generateKey: [
          {
            algorithm: { name: "AES-ECB", length: 256 } as AesKeyGenParams,
            extractable: true,
            keyUsages: ["encrypt", "decrypt"],
          },
        ],
        encrypt: [
          {
            algorithm: {
              name: "AES-ECB",
            },
            data: Buffer.from("test message"),
            encData: Buffer.from("84CCEF71A364B112EB2B3B8B99587A95", "hex"),
            key: {
              format: "raw",
              data: Buffer.from("1234567890abcdef1234567809abcdef"),
              algorithm: { name: "AES-ECB" },
              extractable: true,
              keyUsages: ["encrypt", "decrypt"],
            },
          },
        ],
        import: [
          {
            name: "raw",
            format: "raw",
            data: Buffer.from("1234567890abcdef1234567890abcdef"),
            algorithm: "AES-ECB",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
          {
            name: "jwk",
            format: "jwk",
            data: {
              kty: "oct",
              alg: "A256ECB",
              k: "MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4OTBhYmNkZWY",
              ext: true,
              key_ops: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
            },
            algorithm: "AES-ECB",
            extractable: true,
            keyUsages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          },
        ],
      },
    },
    //#endregion

  ]);

});
