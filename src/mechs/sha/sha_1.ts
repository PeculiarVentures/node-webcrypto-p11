import * as core from "webcrypto-core";
import { Crypto } from "../../crypto";
import { ShaCrypto } from "./crypto";

export class Sha1Provider extends core.ProviderCrypto {
  public name = "SHA-1";
  public usages: KeyUsage[] = [];

  constructor(public crypto: Crypto) {
    super();
  }

  public async onDigest(algorithm: Algorithm, data: ArrayBuffer): Promise<ArrayBuffer> {
    Crypto.assertSession(this.crypto.session);
    return ShaCrypto.digest(this.crypto.session, algorithm, data);
  }

}
