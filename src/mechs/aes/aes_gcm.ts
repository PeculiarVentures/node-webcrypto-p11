import * as core from "webcrypto-core";
import { AesCryptoKey } from ".";
import { Crypto } from "../../crypto";
import { CryptoKey } from "../../key";
import { AesCrypto } from "./crypto";

export class AesGcmProvider extends core.AesGcmProvider {

  constructor(public crypto: Crypto) {
    super();
  }

  public async onGenerateKey(algorithm: Pkcs11AesKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    Crypto.assertSession(this.crypto.session);

    const key = await AesCrypto.generateKey(
      this.crypto.session,
      { ...algorithm, name: this.name },
      extractable,
      keyUsages);

    return key;
  }

  public async onEncrypt(algorithm: Algorithm, key: AesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    Crypto.assertSession(this.crypto.session);

    return AesCrypto.encrypt(this.crypto.session, false, algorithm, key, new Uint8Array(data));
  }

  public async onDecrypt(algorithm: Algorithm, key: AesCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    Crypto.assertSession(this.crypto.session);

    return AesCrypto.decrypt(this.crypto.session, false, algorithm, key, new Uint8Array(data));
  }

  public async onExportKey(format: KeyFormat, key: AesCryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    Crypto.assertSession(this.crypto.session);

    return AesCrypto.exportKey(this.crypto.session, format, key);
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: Pkcs11KeyImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    Crypto.assertSession(this.crypto.session);

    return AesCrypto.importKey(this.crypto.session, format, keyData, { ...algorithm, name: this.name }, extractable, keyUsages);
  }

  public checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    if (!(key instanceof CryptoKey)) {
      throw new TypeError("key: Is not a PKCS11 CryptoKey");
    }
  }
}
