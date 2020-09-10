import { IAlgorithm } from "graphene-pk11";
import * as graphene from "graphene-pk11";
import * as core from "webcrypto-core";
import { Crypto } from "../../crypto";
import { CryptoKey } from "../../key";
import { RsaCrypto } from "./crypto";
import { RsaCryptoKey } from "./key";

export class RsaPssProvider extends core.RsaPssProvider {

  public usages: core.ProviderKeyPairUsage = {
    privateKey: ["sign", "decrypt", "unwrapKey"],
    publicKey: ["verify", "encrypt", "wrapKey"],
  };

  constructor(private crypto: Crypto) {
    super();
  }

  public async onGenerateKey(algorithm: RsaHashedKeyGenParams, extractable: boolean, keyUsages: KeyUsage[], attrs: Partial<Pkcs11KeyAttributes> = {}): Promise<CryptoKeyPair> {
    Crypto.assertSession(this.crypto.session);

    const key = await RsaCrypto.generateKey(
      this.crypto.session,
      { ...algorithm, name: this.name },
      extractable,
      keyUsages,
      attrs);

    return key;
  }

  public async onSign(algorithm: RsaPssParams, key: RsaCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return new Promise<ArrayBuffer>((resolve, reject) => {
      Crypto.assertSession(this.crypto.session);

      let buf = Buffer.from(data);
      const mechanism = this.wc2pk11(algorithm, key.algorithm as RsaHashedKeyAlgorithm);
      mechanism.name = RsaCrypto.getAlgorithm(this.crypto.session, this.name, mechanism.name);
      if (mechanism.name === "RSA_PKCS_PSS") {
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

  public async onVerify(algorithm: RsaPssParams, key: RsaCryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    return new Promise<boolean>((resolve, reject) => {
      Crypto.assertSession(this.crypto.session);

      let buf = Buffer.from(data);
      const mechanism = this.wc2pk11(algorithm, key.algorithm as RsaHashedKeyAlgorithm);
      mechanism.name = RsaCrypto.getAlgorithm(this.crypto.session, this.name, mechanism.name);
      if (mechanism.name === "RSA_PKCS_PSS") {
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
    Crypto.assertSession(this.crypto.session);

    return RsaCrypto.exportKey(this.crypto.session, format, key);
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: RsaHashedImportParams, extractable: boolean, keyUsages: KeyUsage[], attrs: Partial<Pkcs11KeyAttributes> = {}): Promise<CryptoKey> {
    Crypto.assertSession(this.crypto.session);

    const key = await RsaCrypto.importKey(this.crypto.session, format, keyData, { ...algorithm, name: this.name }, extractable, keyUsages, attrs);
    return key;
  }

  public checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    if (!(key instanceof RsaCryptoKey)) {
      throw new TypeError("key: Is not PKCS11 CryptoKey");
    }
  }

  protected wc2pk11(alg: RsaPssParams, keyAlg: RsaHashedKeyAlgorithm): IAlgorithm {
    let mech: string;
    let param: graphene.RsaPssParams;
    const saltLen = alg.saltLength;
    switch (keyAlg.hash.name.toUpperCase()) {
      case "SHA-1":
        mech = "SHA1_RSA_PKCS_PSS";
        param = new graphene.RsaPssParams(graphene.MechanismEnum.SHA1, graphene.RsaMgf.MGF1_SHA1, saltLen);
        break;
      case "SHA-224":
        mech = "SHA224_RSA_PKCS_PSS";
        param = new graphene.RsaPssParams(graphene.MechanismEnum.SHA224, graphene.RsaMgf.MGF1_SHA224, saltLen);
        break;
      case "SHA-256":
        mech = "SHA256_RSA_PKCS_PSS";
        param = new graphene.RsaPssParams(graphene.MechanismEnum.SHA256, graphene.RsaMgf.MGF1_SHA256, saltLen);
        break;
      case "SHA-384":
        mech = "SHA384_RSA_PKCS_PSS";
        param = new graphene.RsaPssParams(graphene.MechanismEnum.SHA384, graphene.RsaMgf.MGF1_SHA384, saltLen);
        break;
      case "SHA-512":
        mech = "SHA512_RSA_PKCS_PSS";
        param = new graphene.RsaPssParams(graphene.MechanismEnum.SHA512, graphene.RsaMgf.MGF1_SHA512, saltLen);
        break;
      default:
        throw new core.OperationError(`Cannot create PKCS11 mechanism from algorithm '${keyAlg.hash.name}'`);
    }
    return { name: mech, params: param };
  }

}
