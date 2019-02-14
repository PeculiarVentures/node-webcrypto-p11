import * as core from "webcrypto-core";
import { CryptoKey } from "../../key";
import { P11Session } from "../../p11_session";
import { AesCrypto } from "./crypto";

export class AesGcmProvider extends core.AesGcmProvider {

  constructor(public session: P11Session) {
    super();
  }

  public async onGenerateKey(algorithm: AesKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    const key = await AesCrypto.generateKey(
      this.session,
      {
        name: this.name,
        length: algorithm.length,
      },
      extractable,
      keyUsages);

    return key;
  }

  public async onEncrypt(algorithm: Algorithm, key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return AesCrypto.encrypt(this.session, false, algorithm, key, new Uint8Array(data));
  }

  public async onDecrypt(algorithm: Algorithm, key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return AesCrypto.decrypt(this.session, false, algorithm, key, new Uint8Array(data));
  }

  public async onExportKey(format: KeyFormat, key: CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    return AesCrypto.exportKey(this.session, format, key);
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    return AesCrypto.importKey(this.session, format, keyData, { name: algorithm.name }, extractable, keyUsages);
  }

  public checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    if (!(key instanceof CryptoKey)) {
      throw new TypeError("key: Is not a PKCS11 CryptoKey");
    }
  }
}
