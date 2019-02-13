import { ITemplate, KeyGenMechanism, KeyType, ObjectClass, SecretKey } from "graphene-pk11";
import * as graphene from "graphene-pk11";
import { Convert } from "pvtsutils";
import * as core from "webcrypto-core";
import { CryptoKey } from "../../key";
import { P11Session } from "../../p11_session";
import * as utils from "../../utils";

export class AesCrypto {

  public static async generateKey(session: P11Session, algorithm: AesKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    return new Promise<CryptoKey>((resolve, reject) => {
      const template = this.createTemplate(session!, algorithm, extractable, keyUsages);
      template.valueLen = algorithm.length >> 3;

      // PKCS11 generation
      session.value.generateKey(KeyGenMechanism.AES, template, (err, aesKey) => {
        try {
          if (err) {
            reject(new core.CryptoError(`Aes: Can not generate new key\n${err.message}`));
          } else {
            resolve(new CryptoKey(aesKey, algorithm));
          }
        } catch (e) {
          reject(e);
        }
      });
    });
  }

  public static async exportKey(session: P11Session, format: string, key: CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    const template = key.key.getAttribute({ value: null, valueLen: null });
    switch (format.toLowerCase()) {
      case "jwk":
        const aes: string = /AES-(\w+)/.exec(key.algorithm.name!)![1];
        const jwk: JsonWebKey = {
          kty: "oct",
          k: Convert.ToBase64Url(template.value!),
          alg: `A${template.valueLen! * 8}${aes}`,
          ext: true,
          key_ops: key.usages,
        };
        return jwk;
      case "raw":
        return new Uint8Array(template.value).buffer;
        break;
      default:
        throw new core.OperationError("format: Must be 'jwk' or 'raw'");
    }
  }

  public static async importKey(session: P11Session, format: string, keyData: JsonWebKey | ArrayBuffer, algorithm: any, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    // get key value
    let value: ArrayBuffer;

    switch (format.toLowerCase()) {
      case "jwk":
        if (!("k" in keyData)) {
          throw new core.OperationError("jwk.k: Cannot get required property");
        }
        keyData = Convert.FromBase64Url(keyData.k);
      case "raw":
        value = keyData as ArrayBuffer;
        switch (value.byteLength) {
          case 16:
          case 24:
          case 32:
            break;
          default:
            throw new core.OperationError("keyData: Is wrong key length");
        }
        break;
      default:
        throw new core.OperationError("format: Must be 'jwk' or 'raw'");
    }

    // prepare key algorithm
    const aesAlg: AesKeyGenParams = {
      name: (algorithm as Algorithm).name,
      length: value.byteLength * 8,
    };
    const template: ITemplate = this.createTemplate(session, aesAlg, extractable, keyUsages);
    template.value = Buffer.from(value);

    // create session object
    const sessionObject = session.value.create(template);
    const key = new CryptoKey(sessionObject.toType<SecretKey>(), aesAlg);
    return key;
  }

  public static async encrypt(session: P11Session, padding: boolean, algorithm: Algorithm, key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    // add padding if needed
    if (padding) {
      const blockLength = 16;
      const mod = blockLength - (data.byteLength % blockLength);
      const pad = Buffer.alloc(mod);
      pad.fill(mod);
      data = Buffer.concat([Buffer.from(data), pad]);
    }

    return new Promise<ArrayBuffer>((resolve, reject) => {
      const enc = Buffer.alloc(this.getOutputBufferSize(key.algorithm as AesKeyAlgorithm, true, data.byteLength));
      const mechanism = this.wc2pk11(session, algorithm);
      session.value.createCipher(mechanism, key.key)
        .once(Buffer.from(data), enc, (err, data2) => {
          if (err) {
            reject(err);
          } else {
            resolve(new Uint8Array(data2).buffer);
          }
        });
    });
  }

  public static async decrypt(session: P11Session, padding: boolean, algorithm: Algorithm, key: CryptoKey, data: Uint8Array): Promise<ArrayBuffer> {
    const dec = await new Promise<Buffer>((resolve, reject) => {
      const buf = Buffer.alloc(this.getOutputBufferSize(key.algorithm as AesKeyAlgorithm, false, data.length));
      const mechanism = this.wc2pk11(session, algorithm);
      session.value.createDecipher(mechanism, key.key)
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

  protected static createTemplate(session: P11Session, alg: AesKeyGenParams, extractable: boolean, keyUsages: string[]): ITemplate {

    const id = utils.GUID(session.value);
    return {
      token: !!process.env.WEBCRYPTO_PKCS11_TOKEN,
      sensitive: !!process.env.WEBCRYPTO_PKCS11_SENSITIVE,
      class: ObjectClass.SECRET_KEY,
      keyType: KeyType.AES,
      label: `AES-${alg.length}`,
      id,
      extractable,
      derive: false,
      sign: keyUsages.indexOf("sign") !== -1,
      verify: keyUsages.indexOf("verify") !== -1,
      encrypt: keyUsages.indexOf("encrypt") !== -1 || keyUsages.indexOf("wrapKey") !== -1,
      decrypt: keyUsages.indexOf("decrypt") !== -1 || keyUsages.indexOf("unwrapKey") !== -1,
      wrap: keyUsages.indexOf("wrapKey") !== -1,
      unwrap: keyUsages.indexOf("unwrapKey") !== -1,
    };
  }

  protected static isAesGCM(algorithm: Algorithm): algorithm is AesGcmParams {
    return algorithm.name.toUpperCase() === "AES-GCM";
  }

  protected static isAesCBC(algorithm: Algorithm): algorithm is AesCbcParams {
    return algorithm.name.toUpperCase() === "AES-CBC";
  }

  protected static isAesECB(algorithm: Algorithm): algorithm is Algorithm {
    return algorithm.name.toUpperCase() === "AES-ECB";
  }

  protected static wc2pk11(session: P11Session, algorithm: Algorithm) {
    if (this.isAesGCM(algorithm)) {
      const aad = algorithm.additionalData ? utils.prepareData(algorithm.additionalData) : undefined;
      let AesGcmParamsClass = graphene.AesGcmParams;
      if (session &&
        session.slot.module.cryptokiVersion.major >= 2 &&
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
  protected static getOutputBufferSize(keyAlg: AesKeyAlgorithm, enc: boolean, dataSize: number): number {
    const len = keyAlg.length >> 3;
    if (enc) {
      return (Math.ceil(dataSize / len) * len) + len;
    } else {
      return dataSize;
    }
  }

}
