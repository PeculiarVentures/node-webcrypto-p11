// Core
import * as core from "webcrypto-core";
import {
  AesCbcProvider, AesEcbProvider, AesGcmProvider,
  EcdhProvider, EcdsaProvider,
  HmacProvider,
  RsaOaepProvider, RsaPssProvider, RsaSsaProvider,
  Sha1Provider, Sha256Provider, Sha384Provider, Sha512Provider,
} from "./mechs";
import { P11Session } from "./p11_session";

export class SubtleCrypto extends core.SubtleCrypto {

  constructor(private session: P11Session) {
    super();

    //#region AES
    this.providers.set(new AesCbcProvider(this.session));
    this.providers.set(new AesEcbProvider(this.session));
    this.providers.set(new AesGcmProvider(this.session));
    //#endregion

    // //#region RSA
    this.providers.set(new RsaSsaProvider(this.session));
    this.providers.set(new RsaPssProvider(this.session));
    this.providers.set(new RsaOaepProvider(this.session));
    // //#endregion

    // //#region EC
    this.providers.set(new EcdsaProvider(this.session));
    this.providers.set(new EcdhProvider(this.session));
    // //#endregion

    //#region SHA
    this.providers.set(new Sha1Provider(this.session));
    this.providers.set(new Sha256Provider(this.session));
    this.providers.set(new Sha384Provider(this.session));
    this.providers.set(new Sha512Provider(this.session));
    //#endregion

    // //#region HMAC
    this.providers.set(new HmacProvider(this.session));
    // //#endregion
  }
}
