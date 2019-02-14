import * as core from "webcrypto-core";
import { P11Session } from "../../p11_session";
import { ShaCrypto } from "./crypto";

export class Sha1Provider extends core.ProviderCrypto {
  public name = "SHA-1";
  public usages: KeyUsage[] = [];

  constructor(public session: P11Session) {
    super();
  }

  public async onDigest(algorithm: Algorithm, data: ArrayBuffer): Promise<ArrayBuffer> {
    return ShaCrypto.digest(this.session.value, algorithm, data);
  }

}
