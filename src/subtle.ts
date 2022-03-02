import * as core from "webcrypto-core";

import { ID_DIGEST } from "./const";
import { CryptoKey, CryptoKey as P11CryptoKey } from "./key";
import * as mechs from "./mechs";
import * as types from "./types";
import * as utils from "./utils";

export class SubtleCrypto extends core.SubtleCrypto implements types.IContainer {

  public constructor(public container: types.ISessionContainer) {
    super();

    //#region AES
    this.providers.set(new mechs.AesCbcProvider(this.container));
    this.providers.set(new mechs.AesEcbProvider(this.container));
    this.providers.set(new mechs.AesGcmProvider(this.container));
    //#endregion
    // #region RSA
    this.providers.set(new mechs.RsaSsaProvider(this.container));
    this.providers.set(new mechs.RsaPssProvider(this.container));
    this.providers.set(new mechs.RsaOaepProvider(this.container));
    // #endregion
    // #region EC
    this.providers.set(new mechs.EcdsaProvider(this.container));
    this.providers.set(new mechs.EcdhProvider(this.container));
    // #endregion
    //#region SHA
    this.providers.set(new mechs.Sha1Provider(this.container));
    this.providers.set(new mechs.Sha256Provider(this.container));
    this.providers.set(new mechs.Sha384Provider(this.container));
    this.providers.set(new mechs.Sha512Provider(this.container));
    //#endregion
    // #region HMAC
    this.providers.set(new mechs.HmacProvider(this.container));
    // #endregion
  }

  public async generateKey(algorithm: RsaHashedKeyGenParams | EcKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair>;
  public async generateKey(algorithm: AesKeyGenParams | HmacKeyGenParams | Pbkdf2Params, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey>;
  public async generateKey(algorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair | CryptoKey> {
    const keys = await super.generateKey(algorithm, extractable, keyUsages) as CryptoKey;

    // Fix ID for generated key pair. It must be hash of public key raw
    if (utils.isCryptoKeyPair(keys)) {
      const publicKey = keys.publicKey as P11CryptoKey;
      const privateKey = keys.privateKey as P11CryptoKey;

      const raw = await this.exportKey("spki", publicKey);
      const digest = utils.digest(ID_DIGEST, raw).slice(0, 16);
      publicKey.key.id = digest;
      publicKey.id = P11CryptoKey.getID(publicKey.key);
      privateKey.key.id = digest;
      privateKey.id = P11CryptoKey.getID(privateKey.key);
    }

    return keys;
  }

  public async importKey(format: KeyFormat, keyData: JsonWebKey | BufferSource, algorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    const key = await super.importKey(format, keyData, algorithm, extractable, keyUsages);

    // Fix ID for generated key pair. It must be hash of public key raw
    if (key.type === "public" && extractable) {
      const publicKey = key as P11CryptoKey;

      const raw = await this.exportKey("spki", publicKey);
      const digest = utils.digest(ID_DIGEST, raw).slice(0, 16);
      publicKey.key.id = digest;
      publicKey.id = P11CryptoKey.getID(publicKey.key);
    }

    return key as CryptoKey;
  }

}
