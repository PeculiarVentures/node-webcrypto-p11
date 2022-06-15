import * as graphene from "graphene-pk11";
import * as core from "webcrypto-core";

import { CryptoKey } from "../../key";
import * as types from "../../types";

import { EcCrypto } from "./crypto";
import { EcCryptoKey } from "./key";

export class EcdhProvider extends core.EcdhProvider implements types.IContainer {

  public override namedCurves = core.EcCurves.names;

  public override usages: core.ProviderKeyPairUsage = {
    privateKey: ["sign", "deriveKey", "deriveBits"],
    publicKey: ["verify"],
  };

  public crypto: EcCrypto;

  constructor(public container: types.ISessionContainer) {
    super();

    this.crypto = new EcCrypto(container);
  }

  public async onGenerateKey(algorithm: types.Pkcs11EcKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    const key = await this.crypto.generateKey(
      { ...algorithm, name: this.name },
      extractable,
      keyUsages);

    return key;
  }

  public async onExportKey(format: KeyFormat, key: EcCryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    return this.crypto.exportKey(format, key);
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    const key = await this.crypto.importKey(format, keyData, { ...algorithm, name: this.name }, extractable, keyUsages);
    return key;
  }

  public override checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage): void {
    super.checkCryptoKey(key, keyUsage);
    if (!(key instanceof EcCryptoKey)) {
      throw new TypeError("key: Is not EC CryptoKey");
    }
  }

  public async onDeriveBits(algorithm: EcdhKeyDeriveParams, baseKey: EcCryptoKey, length: number): Promise<ArrayBuffer> {
    return new Promise<ArrayBuffer>((resolve, reject) => {
      let valueLen = 256;
      switch (baseKey.algorithm.namedCurve) {
        case "P-256":
        case "K-256":
          valueLen = 256;
          break;
        case "P-384":
          valueLen = 384;
          break;
        case "P-521":
          valueLen = 534;
          break;
      }

      // TODO Use template provider
      const template: graphene.ITemplate = {
        token: false,
        sensitive: false,
        class: graphene.ObjectClass.SECRET_KEY,
        keyType: graphene.KeyType.GENERIC_SECRET,
        extractable: true,
        encrypt: true,
        decrypt: true,
        valueLen: valueLen >> 3,
      };

      // derive key
      const ecPoint = (algorithm.public as EcCryptoKey).key.getAttribute({ pointEC: null }).pointEC!;
      this.container.session.deriveKey(
        {
          name: "ECDH1_DERIVE",
          params: new graphene.EcdhParams(
            graphene.EcKdf.NULL,
            null as any,
            ecPoint, // CKA_EC_POINT
          ),
        },
        baseKey.key,
        template,
        (err, key) => {
          if (err) {
            reject(err);
          } else {
            if (!key) {
              throw new Error("Cannot get key from callback function");
            }
            const secretKey = key.toType<graphene.SecretKey>();
            const value = secretKey.getAttribute({ value: null }).value as Buffer;
            resolve(new Uint8Array(value.slice(0, length >> 3)).buffer);
          }
        });
    });
  }

}
