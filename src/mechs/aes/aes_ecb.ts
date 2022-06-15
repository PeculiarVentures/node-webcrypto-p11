import * as core from "webcrypto-core";

import { CryptoKey } from "../../key";
import * as types from "../../types";

import { AesCrypto } from "./crypto";
import { AesCryptoKey } from "./key";

export class AesEcbProvider extends core.ProviderCrypto implements types.IContainer {

  public name = "AES-ECB";
  public usages: KeyUsage[] = ["encrypt", "decrypt", "wrapKey", "unwrapKey"];
  public crypto: AesCrypto;

  constructor(public container: types.ISessionContainer) {
    super();

    this.crypto = new AesCrypto(container);
  }

  public override async onGenerateKey(algorithm: types.Pkcs11AesKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    const key = await this.crypto.generateKey(
      { ...algorithm, name: this.name },
      extractable,
      keyUsages);

    return key;
  }

  public override async onEncrypt(algorithm: Algorithm, key: AesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return this.crypto.encrypt(true, algorithm, key, new Uint8Array(data));
  }

  public override async onDecrypt(algorithm: Algorithm, key: AesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return this.crypto.decrypt(true, algorithm, key, new Uint8Array(data));
  }

  public override async onExportKey(format: KeyFormat, key: AesCryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    return this.crypto.exportKey(format, key);
  }

  public override async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: types.Pkcs11KeyImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    return this.crypto.importKey(format, keyData, { ...algorithm, name: this.name }, extractable, keyUsages);
  }

  public override checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage): void {
    super.checkCryptoKey(key, keyUsage);
    if (!(key instanceof CryptoKey)) {
      throw new TypeError("key: Is not a PKCS11 CryptoKey");
    }
  }
}
