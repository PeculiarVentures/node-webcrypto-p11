import { KeyType, NamedCurve, ObjectClass, SecretKey, SessionObject } from "graphene-pk11";
import * as core from "webcrypto-core";
import { Crypto } from "./crypto";
import { CryptoKey } from "./key";
import { EcCryptoKey, RsaCryptoKey } from "./mechs";
import * as utils from "./utils";

const OBJECT_TYPES = [ObjectClass.PRIVATE_KEY, ObjectClass.PUBLIC_KEY, ObjectClass.SECRET_KEY];

export class KeyStorage implements core.CryptoKeyStorage {

  protected crypto: Crypto;

  constructor(crypto: Crypto) {
    this.crypto = crypto;
  }

  public async keys() {
    const keys: string[] = [];
    OBJECT_TYPES.forEach((objectClass) => {
      this.crypto.session.find({ class: objectClass, token: true }, (obj) => {
        const item = obj.toType<any>();
        keys.push(CryptoKey.getID(item));
      });
    });
    return keys;
  }

  public async indexOf(item: CryptoKey) {
    if (item instanceof CryptoKey && item.key.token) {
      return CryptoKey.getID(item.key);
    }
    return null;
  }

  public async clear() {
    const keys: SessionObject[] = [];
    OBJECT_TYPES.forEach((objectClass) => {
      this.crypto.session.find({ class: objectClass, token: true }, (obj) => {
        keys.push(obj);
      });
    });
    keys.forEach((key) => {
      key.destroy();
    });
  }

  public async getItem(key: string): Promise<CryptoKey>;
  public async getItem(key: string, algorithm: Algorithm, usages: KeyUsage[]): Promise<CryptoKey>;
  public async getItem(key: string, algorithm?: Algorithm, usages?: KeyUsage[]) {
    const subjectObject = this.getItemById(key);
    if (subjectObject) {
      const p11Key = subjectObject.toType<SecretKey>();
      let alg: any;
      if (algorithm) {
        alg = utils.prepareAlgorithm(algorithm);
      } else {
        // name
        alg = {};
        switch (p11Key.type) {
          case KeyType.RSA: {
            if (p11Key.sign || p11Key.verify) {
              alg.name = "RSASSA-PKCS1-v1_5";
            } else {
              alg.name = "RSA-OAEP";
            }
            alg.hash = { name: "SHA-256" };
            break;
          }
          case KeyType.EC: {
            if (p11Key.sign || p11Key.verify) {
              alg.name = "ECDSA";
            } else {
              alg.name = "ECDH";
            }
            const attributes = p11Key.getAttribute({ paramsECDSA: null });
            const pointEC = NamedCurve.getByBuffer(attributes.paramsECDSA);
            let namedCurve: string;
            switch (pointEC.name) {
              case "secp192r1":
                namedCurve = "P-192";
                break;
              case "secp256r1":
                namedCurve = "P-256";
                break;
              case "secp384r1":
                namedCurve = "P-384";
                break;
              case "secp521r1":
                namedCurve = "P-521";
                break;
              default:
                throw new Error(`Unsupported named curve for EC key '${pointEC.name}'`);
            }
            alg.namedCurve = namedCurve;
            break;
          }
          case KeyType.AES: {
            if (p11Key.sign || p11Key.verify) {
              alg.name = "AES-HMAC";
            } else {
              alg.name = "AES-CBC";
            }
            break;
          }
          default:
            throw new Error(`Unsupported type of key '${KeyType[p11Key.type] || p11Key.type}'`);
        }
      }
      let CryptoKeyClass: typeof CryptoKey;
      switch (alg.name.toUpperCase()) {
        case "RSASSA-PKCS1-V1_5":
        case "RSA-PSS":
        case "RSA-OAEP":
          CryptoKeyClass = RsaCryptoKey as any;
          break;
        case "ECDSA":
        case "ECDH":
          CryptoKeyClass = EcCryptoKey as any;
          break;
        default:
          CryptoKeyClass = CryptoKey;
      }
      return new CryptoKeyClass(p11Key, alg);
    } else {
      return null;
    }
  }

  public async removeItem(key: string) {
    const sessionObject = this.getItemById(key);
    if (sessionObject) {
      sessionObject.destroy();
    }
  }

  public async setItem(data: core.NativeCryptoKey): Promise<string>;
  public async setItem(data: CryptoKey) {
    if (!(data instanceof CryptoKey)) {
      throw new core.CryptoError("Parameter 1 is not P11CryptoKey");
    }
    const p11Key = data as CryptoKey;

    // don't copy object from token
    if (!(this.hasItem(data) && p11Key.key.token)) {
      const obj = this.crypto.session.copy(p11Key.key, {
        token: true,
      });
      return CryptoKey.getID(obj.toType<any>());
    } else {
      return data.id;
    }

  }

  public async hasItem(key: CryptoKey) {
    const item = this.getItemById(key.id);
    return !!item;
  }

  protected getItemById(id: string) {
    let key: SessionObject = null;
    OBJECT_TYPES.forEach((objectClass) => {
      this.crypto.session.find({ class: objectClass, token: true }, (obj) => {
        const item = obj.toType<any>();
        if (id === CryptoKey.getID(item)) {
          key = item;
          return false;
        }
      });
    });
    return key;
  }

}
