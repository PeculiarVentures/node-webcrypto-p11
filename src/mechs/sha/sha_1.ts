import * as core from "webcrypto-core";

import * as types from "../../types";

import { ShaCrypto } from "./crypto";

export class Sha1Provider extends core.ProviderCrypto implements types.IContainer {
  public name = "SHA-1";
  public usages: KeyUsage[] = [];
  public crypto: ShaCrypto;

  constructor(public container: types.ISessionContainer) {
    super();

    this.crypto = new ShaCrypto(container);
  }

  public override async onDigest(algorithm: Algorithm, data: ArrayBuffer): Promise<ArrayBuffer> {
    return this.crypto.digest(algorithm, data);
  }

}
