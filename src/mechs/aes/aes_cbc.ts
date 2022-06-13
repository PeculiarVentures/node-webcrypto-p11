import * as core from "webcrypto-core";

import { Assert} from "../../assert";
import { CryptoKey } from "../../key";
import * as types from "../../types";

import { AesCrypto } from "./crypto";
import { AesCryptoKey } from "./key";

export class AesCbcProvider extends core.AesCbcProvider implements types.IContainer {

  public crypto: AesCrypto;

  constructor(public container: types.ISessionContainer) {
    super();

    this.crypto = new AesCrypto(container);
  }

  public async onGenerateKey(algorithm: Pkcs11AesKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    const key = await this.crypto.generateKey(
      { ...algorithm, name: this.name },
      extractable,
      keyUsages);

    return key;
  }

  public async onEncrypt(algorithm: Algorithm, key: AesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return this.crypto.encrypt(false, algorithm, key, new Uint8Array(data));
  }

  public async onDecrypt(algorithm: Algorithm, key: AesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return this.crypto.decrypt(false, algorithm, key, new Uint8Array(data));
  }

  public async onExportKey(format: KeyFormat, key: AesCryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    return this.crypto.exportKey(format, key);
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    return this.crypto.importKey(format, keyData, { ...algorithm, name: this.name }, extractable, keyUsages);
  }

  public override checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    Assert.isCryptoKey(key);
  }
}
