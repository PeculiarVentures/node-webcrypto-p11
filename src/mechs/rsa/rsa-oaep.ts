import * as graphene from "graphene-pk11";
import * as core from "webcrypto-core";

import { CryptoKey } from "../../key";
import * as types from "../../types";

import { RsaCrypto } from "./crypto";
import { RsaCryptoKey } from "./key";

export class RsaOaepProvider extends core.RsaOaepProvider implements types.IContainer {

  public override usages: core.ProviderKeyPairUsage = {
    privateKey: ["sign", "decrypt", "unwrapKey"],
    publicKey: ["verify", "encrypt", "wrapKey"],
  };
  public crypto: RsaCrypto;

  constructor(public container: types.ISessionContainer) {
    super();

    this.crypto = new RsaCrypto(container);
  }

  public async onGenerateKey(algorithm: Pkcs11RsaHashedKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    const key = await this.crypto.generateKey(
      { ...algorithm, name: this.name },
      extractable,
      keyUsages);

    return key;
  }

  public async onEncrypt(algorithm: RsaOaepParams, key: RsaCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      const buf = Buffer.from(data);
      const mechanism = this.wc2pk11(algorithm, key.algorithm);
      const context = Buffer.alloc((key.algorithm).modulusLength >> 3);
      this.container.session.createCipher(mechanism, key.key)
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
      const buf = Buffer.from(data);
      const mechanism = this.wc2pk11(algorithm, key.algorithm);
      const context = Buffer.alloc((key.algorithm).modulusLength >> 3);
      this.container.session.createDecipher(mechanism, key.key)
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
    return this.crypto.exportKey(format, key);
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: Pkcs11RsaHashedImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    const key = await this.crypto.importKey(format, keyData, { ...algorithm, name: this.name }, extractable, keyUsages);
    return key;
  }

  public override checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage): void {
    super.checkCryptoKey(key, keyUsage);
    if (!(key instanceof RsaCryptoKey)) {
      throw new TypeError("key: Is not PKCS11 CryptoKey");
    }
  }

  protected wc2pk11(alg: RsaOaepParams, keyAlg: Pkcs11RsaHashedKeyAlgorithm): graphene.IAlgorithm {
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
