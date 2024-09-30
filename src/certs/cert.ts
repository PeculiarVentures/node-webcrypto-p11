import * as graphene from "graphene-pk11";
import * as pvtsutils from "pvtsutils";
import * as core from "webcrypto-core";

import { Crypto } from "../crypto";
import { CryptoKey } from "../key";
import { Pkcs11Object } from "../p11_object";
import { Pkcs11Params } from "../types";

export interface Pkcs11CryptoCertificate extends core.CryptoCertificate {
  readonly id: string;
  readonly token: boolean;
  readonly sensitive: boolean;
  readonly label: string;
}

export type Pkcs11ImportAlgorithms = core.ImportAlgorithms & Pkcs11Params;

export abstract class CryptoCertificate extends Pkcs11Object implements Pkcs11CryptoCertificate {
  public crypto: Crypto;

  public static getID(p11Object: graphene.Storage): string {
    let type: string | undefined;
    let id: Buffer | undefined;
    if (p11Object instanceof graphene.Data) {
      type = "request";
      id = p11Object.objectId;
    } else if (p11Object instanceof graphene.X509Certificate) {
      type = "x509";
      id = p11Object.id;
    }
    if (!type || !id) {
      throw new Error("Unsupported PKCS#11 object");
    }
    return `${type}-${p11Object.handle.toString("hex")}-${id.toString("hex")}`;
  }

  public get id(): string {
    Pkcs11Object.assertStorage(this.p11Object);

    return CryptoCertificate.getID(this.p11Object);
  }

  public type: core.CryptoCertificateType = "x509";
  public publicKey!: CryptoKey;

  public get token(): boolean {
    try {
      Pkcs11Object.assertStorage(this.p11Object);
      return this.p11Object.token;
    } catch { /* nothing */ }
    return false;
  }

  public get sensitive(): boolean {
    return false;
  }

  public get label(): string {
    try {
      Pkcs11Object.assertStorage(this.p11Object);
      return this.p11Object.label;
    } catch { /* nothing */ }
    return "";
  }

  public constructor(crypto: Crypto) {
    super();
    this.crypto = crypto;
  }

  public abstract importCert(data: Buffer, algorithm: Pkcs11ImportAlgorithms, keyUsages: string[]): Promise<void>;
  public abstract exportCert(): Promise<ArrayBuffer>;
  public abstract exportKey(): Promise<CryptoKey>;
  public abstract exportKey(algorithm: Algorithm, usages: KeyUsage[]): Promise<CryptoKey>;

  /**
   * Computes and returns the ID of a public key using the WebCrypto API.
   * @returnsA Promise that resolves to a Buffer containing the ID of the public key.
   */
  protected async computeID(): Promise<Buffer> {
    // Retrieve the ID of the public key
    let id = this.publicKey.p11Object.id;

    // Check if the key exists in the key storage
    const indexes = await this.crypto.keyStorage.keys();
    if (!indexes.some(o => o.split("-")[2] === id.toString("hex"))) {
      // If the key is not found, look for it on the token
      let certKeyRaw: ArrayBuffer;
      try {
        certKeyRaw = await this.crypto.subtle.exportKey("spki", this.publicKey);
      } catch {
        return id;
      }

      for (const index of indexes) {
        const [type] = index.split("-");
        if (type !== "public") {
          continue;
        }

        // Export the key and compare it to the public key
        let keyRaw: ArrayBuffer;
        try {
          const key = await this.crypto.keyStorage.getItem(index);
          keyRaw = await this.crypto.subtle.exportKey("spki", key);

          if (pvtsutils.BufferSourceConverter.isEqual(keyRaw, certKeyRaw)) {
            // found
            id = key.p11Object.id;
            break;
          }
        } catch {
          // Skip the key if it cannot be exported
          continue;
        }

      }
    }

    return id;
  }

}
