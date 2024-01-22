import * as graphene from "graphene-pk11";
import * as pvtsutils from "pvtsutils";
import * as core from "webcrypto-core";

import { CryptoKey } from "../../key";
import * as utils from "../../utils";
import * as types from "../../types";

import { AesCryptoKey } from "./key";

interface AesGcmPkcs11Algorithm {
  name: "AES_GCM";
  params: graphene.AesGcmParams;
}

interface AesCbcPkcs11Algorithm {
  name: "AES_CBC_PAD";
  params: Buffer;
}

interface AecEcbPkcs11Algorithm {
  name: "AES_ECB";
  params: null;
}

type AesPkcs11Algorithms = AesGcmPkcs11Algorithm | AesCbcPkcs11Algorithm | AecEcbPkcs11Algorithm;

export class AesCrypto implements types.IContainer {

  constructor(public container: types.ISessionContainer) {
  }

  public async generateKey(algorithm: types.Pkcs11AesKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    return new Promise<CryptoKey>((resolve, reject) => {
      const template = this.container.templateBuilder.build({
        action: "generate",
        type: "secret",
        attributes: {
          id: utils.GUID(),
          label: algorithm.label || `AES-${algorithm.length}`,
          token: algorithm.token,
          sensitive: algorithm.sensitive,
          extractable,
          usages: keyUsages,
        },
      });
      template.keyType = graphene.KeyType.AES;
      template.valueLen = algorithm.length >> 3;

      // PKCS11 generation
      this.container.session.generateKey(graphene.KeyGenMechanism.AES, template, (err, aesKey) => {
        try {
          if (err) {
            reject(new core.CryptoError(`Aes: Can not generate new key\n${err.message}`));
          } else {
            if (!aesKey) {
              throw new Error("Cannot get key from callback function");
            }
            resolve(new AesCryptoKey(aesKey, algorithm));
          }
        } catch (e) {
          reject(e);
        }
      });
    });
  }

  public async exportKey(format: string, key: AesCryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    const template = key.key.getAttribute({ value: null, valueLen: null });
    switch (format.toLowerCase()) {
      case "jwk": {
        const aes: string = /AES-(\w+)/.exec(key.algorithm.name!)![1];
        const jwk: JsonWebKey = {
          kty: "oct",
          k: pvtsutils.Convert.ToBase64Url(template.value!),
          alg: `A${template.valueLen! * 8}${aes}`,
          ext: true,
          key_ops: key.usages,
        };
        return jwk;
      }
      case "raw":
        return new Uint8Array(template.value!).buffer;
        break;
      default:
        throw new core.OperationError("format: Must be 'jwk' or 'raw'");
    }
  }

  public async importKey(format: string, keyData: JsonWebKey | ArrayBuffer, algorithm: types.Pkcs11KeyImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    // get key value
    const formatLower = format.toLowerCase();
    if (formatLower !== "jwk" && formatLower !== "raw") {
      throw new core.OperationError("format: Must be 'jwk' or 'raw'");
    }

    if (formatLower === "jwk") {
      const jwk = keyData as JsonWebKey;
      if (!jwk.k) {
        throw new core.OperationError("jwk.k: Cannot get required property");
      }
      keyData = pvtsutils.Convert.FromBase64Url(jwk.k);
    }

    const value = keyData as ArrayBuffer;
    if (value.byteLength !== 16 && value.byteLength !== 24 && value.byteLength !== 32) {
      throw new core.OperationError("keyData: Is wrong key length");
    }

    // prepare key algorithm
    const aesAlg: types.Pkcs11AesKeyAlgorithm = {
      ...AesCryptoKey.defaultKeyAlgorithm(),
      ...algorithm,
      length: value.byteLength * 8,
    };
    const template: graphene.ITemplate = this.container.templateBuilder.build({
      action: "import",
      type: "secret",
      attributes: {
        id: utils.GUID(),
        label: algorithm.label || `AES-${aesAlg.length}`,
        token: algorithm.token,
        sensitive: algorithm.sensitive,
        extractable,
        usages: keyUsages,
      },
    });
    template.keyType = graphene.KeyType.AES;
    template.value = Buffer.from(value);

    // create session object
    const sessionObject = this.container.session.create(template);
    const key = new AesCryptoKey(sessionObject.toType<graphene.SecretKey>(), aesAlg);
    return key;
  }

  public async encrypt(padding: boolean, algorithm: Algorithm, key: AesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    // add padding if needed
    if (padding) {
      const blockLength = 16;
      const mod = blockLength - (data.byteLength % blockLength);
      const pad = Buffer.alloc(mod);
      pad.fill(mod);
      data = Buffer.concat([Buffer.from(data), pad]);
    }

    return new Promise<ArrayBuffer>((resolve, reject) => {
      const enc = Buffer.alloc(this.getOutputBufferSize(key.algorithm, true, data.byteLength));
      const mechanism = this.wc2pk11(algorithm);
      this.container.session.createCipher(mechanism, key.key)
        .once(Buffer.from(data), enc, (err, data2) => {
          if (err) {
            reject(err);
          } else {
            resolve(new Uint8Array(data2).buffer);
          }
        });
    });
  }

  public async decrypt(padding: boolean, algorithm: Algorithm, key: AesCryptoKey, data: Uint8Array): Promise<ArrayBuffer> {
    const dec = await new Promise<Buffer>((resolve, reject) => {
      const buf = Buffer.alloc(this.getOutputBufferSize(key.algorithm, false, data.length));
      const mechanism = this.wc2pk11(algorithm);
      this.container.session.createDecipher(mechanism, key.key)
        .once(Buffer.from(data), buf, (err, data2) => {
          if (err) {
            reject(err);
          } else {
            resolve(data2);
          }
        });
    });
    if (padding) {
      // Remove padding
      const paddingLength = dec[dec.length - 1];

      const res = new Uint8Array(dec.slice(0, dec.length - paddingLength));
      return res.buffer;
    } else {
      return new Uint8Array(dec).buffer;
    }
  }

  protected isAesGCM(algorithm: Algorithm): algorithm is AesGcmParams {
    return algorithm.name.toUpperCase() === "AES-GCM";
  }

  protected isAesCBC(algorithm: Algorithm): algorithm is AesCbcParams {
    return algorithm.name.toUpperCase() === "AES-CBC";
  }

  protected isAesECB(algorithm: Algorithm): algorithm is Algorithm {
    return algorithm.name.toUpperCase() === "AES-ECB";
  }

  protected wc2pk11(algorithm: Algorithm): AesPkcs11Algorithms {
    const session = this.container.session;
    if (this.isAesGCM(algorithm)) {
      const aad = algorithm.additionalData ? utils.prepareData(algorithm.additionalData) : undefined;
      let AesGcmParamsClass = graphene.AesGcmParams;
      if (session.slot.module.cryptokiVersion.major >= 2 &&
        session.slot.module.cryptokiVersion.minor >= 40) {
        AesGcmParamsClass = graphene.AesGcm240Params;
      }
      const params = new AesGcmParamsClass(utils.prepareData(algorithm.iv), aad, algorithm.tagLength || 128);
      return { name: "AES_GCM", params };
    } else if (this.isAesCBC(algorithm)) {
      return { name: "AES_CBC_PAD", params: utils.prepareData(algorithm.iv) };
    } else if (this.isAesECB(algorithm)) {
      return { name: "AES_ECB", params: null };
    } else {
      throw new core.OperationError("Unrecognized algorithm name");
    }
  }

  /**
   * Returns a size of output buffer of enc/dec operation
   * @param keyAlg key algorithm
   * @param enc type of operation
   * `true` - encryption operation
   * `false` - decryption operation
   * @param dataSize size of incoming data
   */
  protected getOutputBufferSize(keyAlg: types.Pkcs11AesKeyAlgorithm, enc: boolean, dataSize: number): number {
    const len = keyAlg.length >> 3;
    if (enc) {
      return (Math.ceil(dataSize / len) * len) + len;
    } else {
      return dataSize;
    }
  }

}
