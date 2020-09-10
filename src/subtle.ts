// Core
import * as core from "webcrypto-core";
import { ID_DIGEST } from "./const";
import { Crypto } from "./crypto";
import { CryptoKey as P11CryptoKey } from "./key";
import * as mechs from "./mechs";
import * as utils from "./utils";

export class SubtleCrypto extends core.SubtleCrypto {

  constructor(private crypto: Crypto) {
    super();

    //#region AES
    this.providers.set(new mechs.AesCbcProvider(this.crypto));
    this.providers.set(new mechs.AesEcbProvider(this.crypto));
    this.providers.set(new mechs.AesGcmProvider(this.crypto));
    //#endregion

    // //#region RSA
    this.providers.set(new mechs.RsaSsaProvider(this.crypto));
    this.providers.set(new mechs.RsaPssProvider(this.crypto));
    this.providers.set(new mechs.RsaOaepProvider(this.crypto));
    // //#endregion

    // //#region EC
    this.providers.set(new mechs.EcdsaProvider(this.crypto));
    this.providers.set(new mechs.EcdhProvider(this.crypto));
    // //#endregion

    //#region SHA
    this.providers.set(new mechs.Sha1Provider(this.crypto));
    this.providers.set(new mechs.Sha256Provider(this.crypto));
    this.providers.set(new mechs.Sha384Provider(this.crypto));
    this.providers.set(new mechs.Sha512Provider(this.crypto));
    //#endregion

    // //#region HMAC
    this.providers.set(new mechs.HmacProvider(this.crypto));
    // //#endregion
  }

  public async generateKey(algorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: KeyUsage[], attrs: Partial<Pkcs11KeyAttributes> = {}): Promise<CryptoKeyPair | CryptoKey> {
    const keys = await super.generateKey(algorithm, extractable, keyUsages, attrs);

    // Fix ID for generated key pair. It must be hash of public key raw
    if (utils.isCryptoKeyPair(keys)) {
      const { privateKey, publicKey } = keys;
      utils.assertPkcs11CryptoKey(privateKey);
      utils.assertPkcs11CryptoKey(publicKey);

      // compute hash from spki
      const raw = await this.exportKey("spki", publicKey);
      const digest = utils.digest(ID_DIGEST, raw).slice(0, 16);

      // update id's for CryptoKey
      publicKey.key.id = digest;
      publicKey.id = P11CryptoKey.getID(publicKey.key);

      privateKey.key.id = digest;
      privateKey.id = P11CryptoKey.getID(privateKey.key);
    }

    return keys;
  }

  public async importKey(format: KeyFormat, keyData: JsonWebKey | BufferSource, algorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: KeyUsage[], attrs: Partial<Pkcs11KeyAttributes> = {}): Promise<CryptoKey> {
    const key = await super.importKey(format, keyData, algorithm, extractable, keyUsages, attrs);

    // Fix ID for generated key pair. It must be hash of public key raw
    if (key.type === "public" && extractable) {
      utils.assertPkcs11CryptoKey(key);

      // compute hash from spki
      const raw = await this.exportKey("spki", key);
      const digest = utils.digest(ID_DIGEST, raw).slice(0, 16);

      // update id's for CryptoKey
      key.key.id = digest;
      key.id = P11CryptoKey.getID(key.key);
    }

    return key;
  }

  public async unwrapKey(format: KeyFormat, wrappedKey: BufferSource, unwrappingKey: CryptoKey, unwrapAlgorithm: AlgorithmIdentifier, unwrappedKeyAlgorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: KeyUsage[], attrs: Partial<Pkcs11KeyAttributes> = {}): Promise<globalThis.CryptoKey> {
    return await super.unwrapKey(format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages, attrs);
  }

  public async deriveKey(algorithm: AlgorithmIdentifier, baseKey: CryptoKey, derivedKeyType: AlgorithmIdentifier, extractable: boolean, keyUsages: KeyUsage[], attrs: Partial<Pkcs11KeyAttributes> = {}): Promise<globalThis.CryptoKey> {
    return await super.deriveKey(algorithm, baseKey, derivedKeyType, extractable, keyUsages, attrs);
  }

}
