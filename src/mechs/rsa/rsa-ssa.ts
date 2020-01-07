import { IAlgorithm } from "graphene-pk11";
import * as core from "webcrypto-core";
import { Crypto } from "../../crypto";
import { CryptoKey } from "../../key";
import { RsaCrypto } from "./crypto";
import { RsaCryptoKey } from "./key";

export class RsaSsaProvider extends core.RsaSsaProvider {

  constructor(private crypto: Crypto) {
    super();
  }

  public async onGenerateKey(algorithm: RsaHashedKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    const key = await RsaCrypto.generateKey(
      this.crypto.session,
      { ...algorithm, name: this.name },
      extractable,
      keyUsages);

    return key;
  }

  public async onSign(algorithm: Algorithm, key: RsaCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return new Promise<ArrayBuffer>((resolve, reject) => {
      let buf = Buffer.from(data);
      const mechanism = this.wc2pk11(algorithm, key.algorithm as RsaHashedKeyAlgorithm);
      mechanism.name = RsaCrypto.getAlgorithm(this.crypto.session, this.name, mechanism.name);
      if (mechanism.name === "RSA_PKCS") {
        buf = RsaCrypto.prepareData((key as any).algorithm.hash.name, buf);
      }
      this.crypto.session.createSign(mechanism, key.key).once(buf, (err, data2) => {
        if (err) {
          reject(err);
        } else {
          resolve(new Uint8Array(data2).buffer);
        }
      });
    });
  }

  public async onVerify(algorithm: Algorithm, key: RsaCryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    return new Promise<boolean>((resolve, reject) => {
      let buf = Buffer.from(data);
      const mechanism = this.wc2pk11(algorithm, key.algorithm as RsaHashedKeyAlgorithm);
      mechanism.name = RsaCrypto.getAlgorithm(this.crypto.session, this.name, mechanism.name);
      if (mechanism.name === "RSA_PKCS") {
        buf = RsaCrypto.prepareData((key as any).algorithm.hash.name, buf);
      }
      this.crypto.session.createVerify(mechanism, key.key).once(buf, Buffer.from(signature), (err, data2) => {
        if (err) {
          reject(err);
        } else {
          resolve(data2);
        }
      });
    });
  }

  public async onExportKey(format: KeyFormat, key: RsaCryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    return RsaCrypto.exportKey(this.crypto.session, format, key);
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: RsaHashedImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    const key = await RsaCrypto.importKey(this.crypto.session, format, keyData, { ...algorithm, name: this.name }, extractable, keyUsages);
    return key;
  }

  public checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    if (!(key instanceof RsaCryptoKey)) {
      throw new TypeError("key: Is not PKCS11 CryptoKey");
    }
  }

  protected wc2pk11(alg: Algorithm, keyAlg: RsaHashedKeyAlgorithm): IAlgorithm {
    let res: string;
    switch (keyAlg.hash.name.toUpperCase()) {
      case "SHA-1":
        res = "SHA1_RSA_PKCS";
        break;
      case "SHA-224":
        res = "SHA224_RSA_PKCS";
        break;
      case "SHA-256":
        res = "SHA256_RSA_PKCS";
        break;
      case "SHA-384":
        res = "SHA384_RSA_PKCS";
        break;
      case "SHA-512":
        res = "SHA512_RSA_PKCS";
        break;
      default:
        throw new core.OperationError(`Cannot create PKCS11 mechanism from algorithm '${keyAlg.hash.name}'`);
    }
    return { name: res, params: null };
  }

}
