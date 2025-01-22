// Core
import * as core from "webcrypto-core";

import * as graphene from "graphene-pk11";
import { AlwaysAuthenticateParams, Pkcs11KeyAlgorithm } from "./types";

export interface ITemplatePair {
  privateKey: graphene.ITemplate;
  publicKey: graphene.ITemplate;
}

export interface CryptoKeyJson<T extends Pkcs11KeyAlgorithm = Pkcs11KeyAlgorithm> {
  algorithm: T;
  type: KeyType;
  usages: KeyUsage[];
  extractable: boolean;
}

export class CryptoKey<T extends Pkcs11KeyAlgorithm = Pkcs11KeyAlgorithm> extends core.CryptoKey implements AlwaysAuthenticateParams {

  public static defaultKeyAlgorithm(): Pkcs11KeyAlgorithm {
    const alg: Pkcs11KeyAlgorithm = {
      label: "",
      name: "",
      sensitive: false,
      token: false,
    };
    return alg;
  }

  public static getID(p11Key: graphene.Key): string {
    let name: string;
    switch (p11Key.class) {
      case graphene.ObjectClass.PRIVATE_KEY:
        name = "private";
        break;
      case graphene.ObjectClass.PUBLIC_KEY:
        name = "public";
        break;
      case graphene.ObjectClass.SECRET_KEY:
        name = "secret";
        break;
      default:
        throw new Error(`Unsupported Object type '${graphene.ObjectClass[p11Key.class]}'`);
    }
    return `${name}-${p11Key.handle.toString("hex")}-${p11Key.id.toString("hex")}`;
  }

  public id: string;
  public p11Object: graphene.Key | graphene.SecretKey | graphene.PublicKey | graphene.PrivateKey;

  /**
   * If `true`, the user has to supply the PIN for each use (sign or decrypt) with the key. Use `crypto.onAlwaysAuthenticate` handler to customize this behavior.
   * @since v2.6.0
   */
  public alwaysAuthenticate?: boolean | undefined;

  public override type: KeyType = "secret";
  public override extractable: boolean = false;
  public override algorithm: T;
  public override usages: KeyUsage[] = [];

  public get key(): graphene.Key {
    return this.p11Object.toType<graphene.Key>();
  }

  constructor(key: graphene.Key, alg: T | KeyAlgorithm, usages?: KeyUsage[]) {
    super();
    this.p11Object = key;
    switch (key.class) {
      case graphene.ObjectClass.PUBLIC_KEY:
        this.initPublicKey(key.toType<graphene.PublicKey>());
        break;
      case graphene.ObjectClass.PRIVATE_KEY:
        this.initPrivateKey(key.toType<graphene.PrivateKey>());
        break;
      case graphene.ObjectClass.SECRET_KEY:
        this.initSecretKey(key.toType<graphene.SecretKey>());
        break;
      default:
        throw new core.CryptoError(`Wrong incoming session object '${graphene.ObjectClass[key.class]}'`);
    }
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { name, ...defaultAlg } = CryptoKey.defaultKeyAlgorithm();
    this.algorithm = { ...alg, ...defaultAlg } as T;
    this.id = CryptoKey.getID(key);

    if (usages) {
      this.usages = usages;
    }

    try {
      this.algorithm.label = key.label;
    } catch { /*nothing*/ }
    try {
      this.algorithm.token = key.token;
    } catch { /*nothing*/ }
    try {
      if (key instanceof graphene.PrivateKey || key instanceof graphene.SecretKey) {
        this.algorithm.sensitive = key.get("sensitive");
      }
    } catch { /*nothing*/ }

    this.onAssign();
  }

  public toJSON(): CryptoKeyJson<T> {
    return {
      algorithm: this.algorithm,
      type: this.type,
      usages: this.usages,
      extractable: this.extractable,
    };
  }

  protected initPrivateKey(key: graphene.PrivateKey): void {
    this.p11Object = key;
    this.type = "private";
    this.alwaysAuthenticate = key.alwaysAuthenticate;
    try {
      // Yubico throws CKR_ATTRIBUTE_TYPE_INVALID
      this.extractable = key.extractable;
    } catch {
      this.extractable = false;
    }
    this.usages = [];
    if (key.decrypt) {
      this.usages.push("decrypt");
    }
    if (key.derive) {
      this.usages.push("deriveKey");
      this.usages.push("deriveBits");
    }
    if (key.sign) {
      this.usages.push("sign");
    }
    if (key.unwrap) {
      this.usages.push("unwrapKey");
    }
  }

  protected initPublicKey(key: graphene.PublicKey): void {
    this.p11Object = key;
    this.type = "public";
    this.extractable = true;
    if (key.encrypt) {
      this.usages.push("encrypt");
    }
    if (key.verify) {
      this.usages.push("verify");
    }
    if (key.wrap) {
      this.usages.push("wrapKey");
    }
  }

  protected initSecretKey(key: graphene.SecretKey): void {
    this.p11Object = key;
    this.type = "secret";
    try {
      // Yubico throws CKR_ATTRIBUTE_TYPE_INVALID
      this.extractable = key.extractable;
    } catch {
      this.extractable = false;
    }
    if (key.sign) {
      this.usages.push("sign");
    }
    if (key.verify) {
      this.usages.push("verify");
    }
    if (key.encrypt) {
      this.usages.push("encrypt");
    }
    if (key.decrypt) {
      this.usages.push("decrypt");
    }
    if (key.wrap) {
      this.usages.push("wrapKey");
    }
    if (key.unwrap) {
      this.usages.push("unwrapKey");
    }
    if (key.derive) {
      this.usages.push("deriveKey");
      this.usages.push("deriveBits");
    }
  }

  protected onAssign(): void {
    // nothing
  }

}
