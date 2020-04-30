import * as graphene from "graphene-pk11";
import * as core from "webcrypto-core";
import { Crypto } from "../../crypto";
import { CryptoKey } from "../../key";
import { EcCrypto } from "./crypto";
import { EcCryptoKey } from "./key";

export class EcdhProvider extends core.EcdhProvider {

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

  public async onExportKey(format: KeyFormat, key: EcCryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    Crypto.assertSession(this.crypto.session);

    return EcCrypto.exportKey(this.crypto.session, format, key);
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
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

  public async onDeriveBits(algorithm: EcdhKeyDeriveParams, baseKey: EcCryptoKey, length: number): Promise<ArrayBuffer> {
    return new Promise<ArrayBuffer>((resolve, reject) => {
      Crypto.assertSession(this.crypto.session);

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
      // const curve = EcCrypto.getNamedCurve(baseKey.algorithm.namedCurve);
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
      this.crypto.session.deriveKey(
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
            const secretKey = key.toType<graphene.SecretKey>();
            const value = secretKey.getAttribute({ value: null }).value as Buffer;
            resolve(new Uint8Array(value.slice(0, length >> 3)).buffer);
          }
        });
    });
  }

}
