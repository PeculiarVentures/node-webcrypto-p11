import * as graphene from "graphene-pk11";
import * as core from "webcrypto-core";

import { Crypto } from "./crypto";
import { CryptoKey } from "./key";
import { AesCryptoKey, EcCryptoKey, HmacCryptoKey, RsaCryptoKey } from "./mechs";
import { Pkcs11KeyAlgorithm } from "./types";
import * as utils from "./utils";

const OBJECT_TYPES = [graphene.ObjectClass.PRIVATE_KEY, graphene.ObjectClass.PUBLIC_KEY, graphene.ObjectClass.SECRET_KEY];

export class KeyStorage implements core.CryptoKeyStorage {

  protected crypto: Crypto;

  constructor(crypto: Crypto) {
    this.crypto = crypto;
  }

  public async keys(): Promise<string[]> {
    const keys: string[] = [];
    OBJECT_TYPES.forEach((objectClass) => {
      this.crypto.session!.find({ class: objectClass, token: true }, (obj) => {
        const item = obj.toType<graphene.Key>();
        keys.push(CryptoKey.getID(item));
      });
    });
    return keys;
  }

  public async indexOf(item: CryptoKey): Promise<string | null> {
    if (item instanceof CryptoKey && item.key.token) {
      return CryptoKey.getID(item.key);
    }
    return null;
  }

  public async clear(): Promise<void> {
    const keys: graphene.SessionObject[] = [];
    OBJECT_TYPES.forEach((objectClass) => {
      this.crypto.session!.find({ class: objectClass, token: true }, (obj) => {
        keys.push(obj);
      });
    });
    keys.forEach((key) => {
      key.destroy();
    });
  }

  public async getItem(key: string): Promise<CryptoKey>;
  /** @deprecated Use getItem(index, algorithm, extractable, keyUsages) */
  public async getItem(key: string, algorithm: Algorithm, usages: KeyUsage[]): Promise<CryptoKey>;
  public async getItem(index: string, algorithm: core.ImportAlgorithms, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  public async getItem(key: string, ...args: any[]): Promise<CryptoKey> {
    const subjectObject = this.getItemById(key);
    if (subjectObject) {
      const p11Key = subjectObject.toType<graphene.SecretKey>();
      let alg: Pkcs11KeyAlgorithm | undefined;
      let algorithm: Algorithm | undefined;
      let usages: KeyUsage[] | undefined;
      if (typeof args[0] === "object" && typeof args[1] === "boolean" && Array.isArray(args[2])) {
        algorithm = args[0];
        usages = args[2];
      } else if (typeof args[0] === "object" && Array.isArray(args[1])) {
        algorithm = args[0];
        usages = args[1];
      }
      if (algorithm) {
        alg = {
          ...utils.prepareAlgorithm(algorithm),
          token: false,
          sensitive: false,
          label: "",
        };
      } else {
        alg = {
          name: "",
          token: false,
          sensitive: false,
          label: "",
        };
        switch (p11Key.type) {
          case graphene.KeyType.RSA: {
            if (p11Key.sign || p11Key.verify) {
              alg.name = "RSASSA-PKCS1-v1_5";
            } else {
              alg.name = "RSA-OAEP";
            }
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            (alg as any).hash = { name: "SHA-256" };
            break;
          }
          case graphene.KeyType.EC: {
            if (p11Key.sign || p11Key.verify) {
              alg.name = "ECDSA";
            } else {
              alg.name = "ECDH";
            }

            break;
          }
          case graphene.KeyType.GENERIC_SECRET:
          case graphene.KeyType.AES: {
            if (p11Key.sign || p11Key.verify) {
              alg.name = "HMAC";
            } else {
              alg.name = "AES-CBC";
            }
            break;
          }
          default:
            throw new Error(`Unsupported type of key '${graphene.KeyType[p11Key.type] || p11Key.type}'`);
        }
      }
      let CryptoKeyClass: typeof CryptoKey;
      switch (alg.name.toUpperCase()) {
        case "RSASSA-PKCS1-V1_5":
        case "RSAES-PKCS1-V1_5":
        case "RSA-PSS":
        case "RSA-OAEP":
          CryptoKeyClass = RsaCryptoKey as typeof CryptoKey;
          break;
        case "ECDSA":
        case "ECDH":
          CryptoKeyClass = EcCryptoKey as typeof CryptoKey;
          break;
        case "HMAC":
          CryptoKeyClass = HmacCryptoKey as typeof CryptoKey;
          break;
        case "AES-CBC":
        case "AES-ECB":
        case "AES-GCM":
          CryptoKeyClass = AesCryptoKey as typeof CryptoKey;
          break;
        default:
          CryptoKeyClass = CryptoKey;
      }
      const key = new CryptoKeyClass(p11Key, alg, usages);

      if (typeof args[1] === "boolean") {
        key.extractable = args[1];
      }

      return key;
    } else {
      throw new Error(`Certificate storage item not found`);
    }
  }

  public async removeItem(key: string): Promise<void> {
    const sessionObject = this.getItemById(key);
    if (sessionObject) {
      sessionObject.destroy();
    }
  }

  public async setItem(data: core.NativeCryptoKey): Promise<string>;
  public async setItem(data: CryptoKey): Promise<string> {
    if (!(data instanceof CryptoKey)) {
      throw new core.CryptoError("Parameter 1 is not P11CryptoKey");
    }

    const p11Key = data as CryptoKey;

    // don't copy object from token
    const hasItem = await this.hasItem(data);
    if (!(hasItem && p11Key.key.token)) {
      const template = this.crypto.templateBuilder.build({
        action: "copy",
        type: p11Key.type,
        attributes: {
          token: true,
        }
      });
      const obj = this.crypto.session.copy(p11Key.key, template);
      return CryptoKey.getID(obj.toType<graphene.Key>());
    } else {
      return data.id;
    }

  }

  public async hasItem(key: CryptoKey): Promise<boolean> {
    const item = this.getItemById(key.id);
    return !!item;
  }

  protected getItemById(id: string): graphene.SessionObject | null {

    let key: graphene.SessionObject | null = null;
    OBJECT_TYPES.forEach((objectClass) => {
      this.crypto.session!.find({ class: objectClass, token: true }, (obj) => {
        const item = obj.toType<graphene.Key>();
        if (id === CryptoKey.getID(item)) {
          key = item;
          return false;
        }
      });
    });
    return key;
  }

}
