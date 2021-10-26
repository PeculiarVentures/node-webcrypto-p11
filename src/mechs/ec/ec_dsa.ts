import * as core from "webcrypto-core";

import { CryptoKey } from "../../key";
import * as types from "../../types";

import { EcCrypto } from "./crypto";
import { EcCryptoKey } from "./key";

export class EcdsaProvider extends core.EcdsaProvider implements types.IContainer {

  public namedCurves = core.EcCurves.names;

  public usages: core.ProviderKeyPairUsage = {
    privateKey: ["sign", "deriveKey", "deriveBits"],
    publicKey: ["verify"],
  };

  public crypto: EcCrypto;

  constructor(public container: types.ISessionContainer) {
    super();

    this.crypto = new EcCrypto(container);
  }

  public async onGenerateKey(algorithm: Pkcs11EcKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<core.CryptoKeyPair> {
    const key = await this.crypto.generateKey(
      { ...algorithm, name: this.name },
      extractable,
      keyUsages);

    return key;
  }

  public async onSign(algorithm: EcdsaParams, key: EcCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return new Promise<ArrayBuffer>((resolve, reject) => {
      let buf = Buffer.from(data);
      const mechanism = this.wc2pk11(algorithm, algorithm);
      mechanism.name = this.crypto.getAlgorithm(mechanism.name);
      if (mechanism.name === "ECDSA") {
        buf = this.crypto.prepareData((algorithm.hash as Algorithm).name, buf);
      }
      this.container.session.createSign(mechanism, key.key).once(buf, (err, data2) => {
        if (err) {
          reject(err);
        } else {
          resolve(new Uint8Array(data2).buffer);
        }
      });
    });
  }

  public async onVerify(algorithm: EcdsaParams, key: EcCryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    return new Promise<boolean>((resolve, reject) => {
      let buf = Buffer.from(data);
      const mechanism = this.wc2pk11(algorithm, algorithm);
      mechanism.name = this.crypto.getAlgorithm(mechanism.name);
      if (mechanism.name === "ECDSA") {
        buf = this.crypto.prepareData((algorithm.hash as Algorithm).name, buf);
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

  public async onExportKey(format: KeyFormat, key: EcCryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    return this.crypto.exportKey(format, key);
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: Pkcs11EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    const key = await this.crypto.importKey(format, keyData, { ...algorithm, name: this.name }, extractable, keyUsages);
    return key;
  }

  public checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    if (!(key instanceof EcCryptoKey)) {
      throw new TypeError("key: Is not EC CryptoKey");
    }
  }

  protected wc2pk11(alg: EcdsaParams, keyAlg: KeyAlgorithm): { name: string, params: null } {
    let algName: string;
    const hashAlg = (alg.hash as Algorithm).name.toUpperCase();
    switch (hashAlg) {
      case "SHA-1":
        algName = "ECDSA_SHA1";
        break;
      case "SHA-224":
        algName = "ECDSA_SHA224";
        break;
      case "SHA-256":
        algName = "ECDSA_SHA256";
        break;
      case "SHA-384":
        algName = "ECDSA_SHA384";
        break;
      case "SHA-512":
        algName = "ECDSA_SHA512";
        break;
      default:
        throw new core.OperationError(`Cannot create PKCS11 mechanism from algorithm '${hashAlg}'`);
    }
    return { name: algName, params: null };
  }

}
