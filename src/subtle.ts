// Core
import * as core from "webcrypto-core";
import { Crypto } from "./crypto";
import {
  AesCbcProvider, AesEcbProvider, AesGcmProvider,
  EcdhProvider, EcdsaProvider,
  HmacProvider,
  RsaOaepProvider, RsaPssProvider, RsaSsaProvider,
  Sha1Provider, Sha256Provider, Sha384Provider, Sha512Provider,
} from "./mechs";

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
}
