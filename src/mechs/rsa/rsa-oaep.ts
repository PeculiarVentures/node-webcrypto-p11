import * as graphene from "graphene-pk11";
import * as core from "webcrypto-core";
import { Crypto } from "../../crypto";
import { CryptoKey } from "../../key";
import { RsaCrypto } from "./crypto";
import { RsaCryptoKey } from "./key";

export class RsaOaepProvider extends core.RsaOaepProvider {

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

  public async onEncrypt(algorithm: RsaOaepParams, key: RsaCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      Crypto.assertSession(this.crypto.session);

      const buf = Buffer.from(data);
      const mechanism = this.wc2pk11(algorithm, key.algorithm);
      const context = Buffer.alloc((key.algorithm).modulusLength >> 3);
      this.crypto.session.createCipher(mechanism, key.key)
        .once(buf, context, (err, data2) => {
          if (err) {
            reject(err);
          } else {
            resolve(new Uint8Array(data2).buffer);
          }
        });
    });
  }

  public async onDecrypt(algorithm: RsaOaepParams, key: RsaCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      Crypto.assertSession(this.crypto.session);

      const buf = Buffer.from(data);
      const mechanism = this.wc2pk11(algorithm, key.algorithm);
      const context = Buffer.alloc((key.algorithm).modulusLength >> 3);
      this.crypto.session.createDecipher(mechanism, key.key)
        .once(buf, context, (err, data2) => {
          if (err) {
            reject(err);
          } else {
            resolve(new Uint8Array(data2).buffer);
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

  protected wc2pk11(alg: RsaOaepParams, keyAlg: RsaHashedKeyAlgorithm): graphene.IAlgorithm {
    let params: graphene.RsaOaepParams;
    const sourceData = alg.label ? Buffer.from((alg as RsaOaepParams).label as Uint8Array) : undefined;
    switch (keyAlg.hash.name.toUpperCase()) {
      case "SHA-1":
        params = new graphene.RsaOaepParams(graphene.MechanismEnum.SHA1, graphene.RsaMgf.MGF1_SHA1, sourceData);
        break;
      case "SHA-224":
        params = new graphene.RsaOaepParams(graphene.MechanismEnum.SHA224, graphene.RsaMgf.MGF1_SHA224, sourceData);
        break;
      case "SHA-256":
        params = new graphene.RsaOaepParams(graphene.MechanismEnum.SHA256, graphene.RsaMgf.MGF1_SHA256, sourceData);
        break;
      case "SHA-384":
        params = new graphene.RsaOaepParams(graphene.MechanismEnum.SHA384, graphene.RsaMgf.MGF1_SHA384, sourceData);
        break;
      case "SHA-512":
        params = new graphene.RsaOaepParams(graphene.MechanismEnum.SHA512, graphene.RsaMgf.MGF1_SHA512, sourceData);
        break;
      default:
        throw new core.OperationError(`Cannot create PKCS11 mechanism from algorithm '${keyAlg.hash.name}'`);
    }
    const res = { name: "RSA_PKCS_OAEP", params };
    return res;
  }

}
