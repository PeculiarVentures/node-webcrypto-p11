// Core
import * as core from "webcrypto-core";
import { ID_DIGEST } from "./const";
import { Crypto } from "./crypto";
import { CryptoKey as P11CryptoKey } from "./key";
import {
  AesCbcProvider, AesEcbProvider, AesGcmProvider,
  EcdhProvider, EcdsaProvider,
  HmacProvider,
  RsaOaepProvider, RsaPssProvider, RsaSsaProvider,
  Sha1Provider, Sha256Provider, Sha384Provider, Sha512Provider,
} from "./mechs";
import * as utils from "./utils";

export class SubtleCrypto extends core.SubtleCrypto {

  constructor(private crypto: Crypto) {
    super();

    //#region AES
    this.providers.set(new AesCbcProvider(this.crypto));
    this.providers.set(new AesEcbProvider(this.crypto));
    this.providers.set(new AesGcmProvider(this.crypto));
    //#endregion

    // //#region RSA
    this.providers.set(new RsaSsaProvider(this.crypto));
    this.providers.set(new RsaPssProvider(this.crypto));
    this.providers.set(new RsaOaepProvider(this.crypto));
    // //#endregion

    // //#region EC
    this.providers.set(new EcdsaProvider(this.crypto));
    this.providers.set(new EcdhProvider(this.crypto));
    // //#endregion

    //#region SHA
    this.providers.set(new Sha1Provider(this.crypto));
    this.providers.set(new Sha256Provider(this.crypto));
    this.providers.set(new Sha384Provider(this.crypto));
    this.providers.set(new Sha512Provider(this.crypto));
    //#endregion

    // //#region HMAC
    this.providers.set(new HmacProvider(this.crypto));
    // //#endregion
  }

  public async generateKey(algorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair | CryptoKey> {
    const keys = await super.generateKey(algorithm, extractable, keyUsages);

    // Fix ID for generated key pair. It must be hash of public key raw
    if (utils.isCryptoKeyPair(keys)) {
      const publicKey = keys.publicKey as P11CryptoKey;
      const privateKey = keys.privateKey as P11CryptoKey;

      const raw = await this.exportKey("raw", publicKey);
      const digest = utils.digest(ID_DIGEST, raw);
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

      const raw = await this.exportKey("raw", publicKey);
      const digest = utils.digest(ID_DIGEST, raw);
      publicKey.key.id = digest;
      publicKey.id = P11CryptoKey.getID(publicKey.key);
    }

    return key;
  }

}
