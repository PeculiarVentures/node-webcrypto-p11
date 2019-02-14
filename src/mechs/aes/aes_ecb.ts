import * as core from "webcrypto-core";
import { Crypto } from "../../crypto";
import { CryptoKey } from "../../key";
import { AesCrypto } from "./crypto";

export class AesEcbProvider extends core.ProviderCrypto {

  public name = "AES-ECB";
  public usages: KeyUsage[] = ["encrypt", "decrypt", "wrapKey", "unwrapKey"];

  constructor(public crypto: Crypto) {
    super();
  }

  public async onGenerateKey(algorithm: AesKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    const key = await AesCrypto.generateKey(
      this.crypto.session,
      {
        name: this.name,
        length: algorithm.length,
      },
      extractable,
      keyUsages);

    return key;
  }

  public async onEncrypt(algorithm: Algorithm, key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return AesCrypto.encrypt(this.crypto.session, true, algorithm, key, new Uint8Array(data));
  }

  public async onDecrypt(algorithm: Algorithm, key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return AesCrypto.decrypt(this.crypto.session, true, algorithm, key, new Uint8Array(data));
  }

  public async onExportKey(format: KeyFormat, key: CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    return AesCrypto.exportKey(this.crypto.session, format, key);
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    return AesCrypto.importKey(this.crypto.session, format, keyData, { name: algorithm.name }, extractable, keyUsages);
  }

  public checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    if (!(key instanceof CryptoKey)) {
      throw new TypeError("key: Is not a PKCS11 CryptoKey");
    }
  }
}
