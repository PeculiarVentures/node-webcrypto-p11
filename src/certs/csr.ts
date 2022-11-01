import * as x509 from "@peculiar/x509";
import * as graphene from "graphene-pk11";
import * as pvtsutils from "pvtsutils";
import * as core from "webcrypto-core";

import { CryptoKey, CryptoKeyJson } from "../key";
import { Pkcs11Object } from "../p11_object";
import { Pkcs11KeyAlgorithm } from "../types";

import { CryptoCertificate, Pkcs11ImportAlgorithms } from "./cert";
import { ParserError } from "./parser_error";

interface X509CertificateRequestJson {
  publicKey: CryptoKeyJson<Pkcs11KeyAlgorithm>;
  subjectName: string;
  type: "request";
  value: string;
}

export class X509CertificateRequest extends CryptoCertificate implements core.CryptoX509CertificateRequest {

  public get subjectName(): string {
    return this.getData()?.subject;
  }
  public override type: "request" = "request";
  declare public p11Object?: graphene.Data;
  public csr?: x509.Pkcs10CertificateRequest;

  public get value(): ArrayBuffer {
    Pkcs11Object.assertStorage(this.p11Object);

    return new Uint8Array(this.p11Object.value).buffer as ArrayBuffer;
  }

  /**
   * Creates new CertificateRequest in PKCS11 session
   * @param data
   * @param algorithm
   * @param keyUsages
   */
  public async importCert(data: Buffer, algorithm: Pkcs11ImportAlgorithms, keyUsages: KeyUsage[]): Promise<void> {
    const array = new Uint8Array(data).buffer as ArrayBuffer;
    this.parse(array);

    const { token, label, sensitive, ...keyAlg } = algorithm as any; // remove custom attrs for key
    this.publicKey = await this.getData().publicKey.export(keyAlg, keyUsages, this.crypto as globalThis.Crypto) as CryptoKey;

    const hashSPKI = this.publicKey.p11Object.id;

    const template = this.crypto.templateBuilder.build({
      action: "import",
      type: "request",
      attributes: {
        id: keyAlg.id || hashSPKI,
        label: algorithm.label || "X509 Request",
        token: !!(algorithm.token),
      },
    })

    // set data attributes
    template.value = Buffer.from(data);

    this.p11Object = this.crypto.session.create(template).toType<graphene.Data>();
  }

  public async exportCert(): Promise<ArrayBuffer> {
    return this.value;
  }

  public toJSON(): X509CertificateRequestJson {
    return {
      publicKey: this.publicKey.toJSON(),
      subjectName: this.subjectName,
      type: this.type,
      value: pvtsutils.Convert.ToBase64Url(this.value),
    };
  }

  public async exportKey(): Promise<CryptoKey>;
  public async exportKey(algorithm: Algorithm, usages: KeyUsage[]): Promise<CryptoKey>;
  public async exportKey(algorithm?: Algorithm, usages?: KeyUsage[]): Promise<CryptoKey> {
    if (!this.publicKey) {
      const publicKeyID = this.id.replace(/\w+-\w+-/i, "");
      const keyIndexes = await this.crypto.keyStorage.keys();
      for (const keyIndex of keyIndexes) {
        const parts = keyIndex.split("-");
        if (parts[0] === "public" && parts[2] === publicKeyID) {
          if (algorithm && usages) {
            this.publicKey = await this.crypto.keyStorage.getItem(keyIndex, algorithm, true, usages);
          } else {
            this.publicKey = await this.crypto.keyStorage.getItem(keyIndex);
          }
          break;
        }
      }
      if (!this.publicKey) {
        if (algorithm && usages) {
          this.publicKey = await this.getData().publicKey.export(algorithm, usages, this.crypto as globalThis.Crypto) as CryptoKey;
        } else {
          this.publicKey = await this.getData().publicKey.export(this.crypto as globalThis.Crypto) as CryptoKey;
        }
      }
    }
    return this.publicKey;
  }

  protected parse(data: ArrayBuffer): void {
    try {
      this.csr = new x509.Pkcs10CertificateRequest(data);
    } catch (e) {
      throw new ParserError("Cannot parse PKCS10 certificate request");
    }
  }

  /**
   * returns parsed ASN1 value
   */
  protected getData(): x509.Pkcs10CertificateRequest {
    if (!this.csr) {
      this.parse(this.value);
    }
    return this.csr!;
  }

}
