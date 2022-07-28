import * as core from "webcrypto-core";

import { CryptoKey } from "../../key";
import * as types from "../../types";
import { alwaysAuthenticate } from "../../utils";

import { RsaCrypto } from "./crypto";
import { RsaCryptoKey } from "./key";

export class RsaSsaProvider extends core.RsaSsaProvider implements types.IContainer {

  public override usages: core.ProviderKeyPairUsage = {
    privateKey: ["sign", "decrypt", "unwrapKey"],
    publicKey: ["verify", "encrypt", "wrapKey"],
  };
  public crypto: RsaCrypto;

  constructor(public container: types.ISessionContainer) {
    super();

    this.crypto = new RsaCrypto(container);
  }

  public async onGenerateKey(algorithm: RsaHashedKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    const key = await this.crypto.generateKey(
      { ...algorithm, name: this.name },
      extractable,
      keyUsages);

    return key;
  }

  public async onSign(algorithm: Algorithm, key: RsaCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    let buf = Buffer.from(data);
    const mechanism = this.wc2pk11(algorithm, key.algorithm as RsaHashedKeyAlgorithm);
    mechanism.name = this.crypto.getAlgorithm(this.name, mechanism.name);
    if (mechanism.name === "RSA_PKCS") {
      buf = this.crypto.prepareData((key as any).algorithm.hash.name, buf);
    }
    const signer = this.container.session.createSign(mechanism, key.key);
    try {
      await alwaysAuthenticate(key, this.container);
    } catch (e) {
      try {
        // call C_SignFinal to close the active state
        signer.once(buf);
      } catch {
        // nothing
      }
      throw e;
    }
    return new Promise<ArrayBuffer>((resolve, reject) => {
      signer.once(buf, (err, data2) => {
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
      mechanism.name = this.crypto.getAlgorithm(this.name, mechanism.name);
      if (mechanism.name === "RSA_PKCS") {
        buf = this.crypto.prepareData((key as any).algorithm.hash.name, buf);
      }
      this.container.session.createVerify(mechanism, key.key).once(buf, Buffer.from(signature), (err, data2) => {
        if (err) {
          reject(err);
        } else {
          resolve(data2);
        }
      });
    });
  }

  public async onExportKey(format: KeyFormat, key: RsaCryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    return this.crypto.exportKey(format, key);
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: RsaHashedImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    const key = await this.crypto.importKey(format, keyData, { ...algorithm, name: this.name }, extractable, keyUsages);
    return key;
  }

  public override checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage): void {
    super.checkCryptoKey(key, keyUsage);
    if (!(key instanceof RsaCryptoKey)) {
      throw new TypeError("key: Is not PKCS11 CryptoKey");
    }
  }

  protected wc2pk11(alg: Algorithm, keyAlg: RsaHashedKeyAlgorithm): { name: string, params: null; } {
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
