import * as graphene from "graphene-pk11";
import * as core from "webcrypto-core";
import { Crypto } from "../../crypto";
import { CryptoKey } from "../../key";
import { EcCrypto } from "./crypto";
import { EcCryptoKey } from "./key";

export class EcdsaProvider extends core.EcdsaProvider {

  public namedCurves = ["P-256", "P-384", "P-521", "K-256"];

  constructor(private crypto: Crypto) {
    super();
  }

  public async onGenerateKey(algorithm: Pkcs11EcKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    Crypto.assertSession(this.crypto.session);

    const key = await EcCrypto.generateKey(
      this.crypto.session,
      { ...algorithm, name: this.name },
      extractable,
      keyUsages);

    return key;
  }

  public async onSign(algorithm: EcdsaParams, key: EcCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return new Promise<ArrayBuffer>((resolve, reject) => {
      Crypto.assertSession(this.crypto.session);

      let buf = Buffer.from(data);
      const mechanism = this.wc2pk11(algorithm, algorithm);
      mechanism.name = EcCrypto.getAlgorithm(this.crypto.session, mechanism.name);
      if (mechanism.name === "ECDSA") {
        buf = EcCrypto.prepareData((algorithm.hash as Algorithm).name, buf);
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

  public async onVerify(algorithm: EcdsaParams, key: EcCryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    return new Promise<boolean>((resolve, reject) => {
      Crypto.assertSession(this.crypto.session);

      let buf = Buffer.from(data);
      const mechanism = this.wc2pk11(algorithm, algorithm);
      mechanism.name = EcCrypto.getAlgorithm(this.crypto.session, mechanism.name);
      if (mechanism.name === "ECDSA") {
        buf = EcCrypto.prepareData((algorithm.hash as Algorithm).name, buf);
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

  public async onExportKey(format: KeyFormat, key: EcCryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    Crypto.assertSession(this.crypto.session);

    return EcCrypto.exportKey(this.crypto.session, format, key);
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: Pkcs11EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    Crypto.assertSession(this.crypto.session);

    const key = await EcCrypto.importKey(this.crypto.session, format, keyData, { ...algorithm, name: this.name }, extractable, keyUsages);
    return key;
  }

  public checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    if (!(key instanceof EcCryptoKey)) {
      throw new TypeError("key: Is not EC CryptoKey");
    }
  }

  protected wc2pk11(alg: EcdsaParams, keyAlg: KeyAlgorithm): graphene.IAlgorithm {
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
