import * as asn1Schema from "@peculiar/asn1-schema";
import * as asnX509 from "@peculiar/asn1-x509";
import * as x509 from "@peculiar/x509";
import * as graphene from "graphene-pk11";
import * as pvtsutils from "pvtsutils";
import * as core from "webcrypto-core";

import { CryptoKey, CryptoKeyJson } from "../key";
import { Pkcs11Object } from "../p11_object";

import { CryptoCertificate, Pkcs11ImportAlgorithms } from "./cert";
import { ParserError } from "./parser_error";

interface X509CertificateJson {
  publicKey: CryptoKeyJson;
  notBefore: Date;
  notAfter: Date;
  subjectName: string;
  issuerName: string;
  serialNumber: string;
  type: "x509";
  value: string;
}

export class X509Certificate extends CryptoCertificate implements core.CryptoX509Certificate {

  public get serialNumber(): string {
    return this.getData().serialNumber;
  }
  public get notBefore(): Date {
    return this.getData().notBefore;
  }
  public get notAfter(): Date {
    return this.getData().notAfter;
  }
  public get issuerName(): string {
    return this.getData().issuer;
  }
  public get subjectName(): string {
    return this.getData().subject;
  }
  public override type = "x509" as const;

  public get value(): ArrayBuffer {
    Pkcs11Object.assertStorage(this.p11Object);
    return new Uint8Array(this.p11Object.value).buffer;
  }

  declare public p11Object?: graphene.X509Certificate;
  protected x509?: x509.X509Certificate;

  public async importCert(data: Buffer, algorithm: Pkcs11ImportAlgorithms, keyUsages: KeyUsage[]): Promise<void> {
    const array = new Uint8Array(data);
    this.parse(array.buffer as ArrayBuffer);

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { token, label, sensitive, ...keyAlg } = algorithm; // remove custom attrs for key
    this.publicKey = await this.getData().publicKey.export(keyAlg, keyUsages, this.crypto) as CryptoKey;

    const id = await this.computeID();
    const certLabel = this.getName();

    const template = this.crypto.templateBuilder.build({
      action: "import",
      type: "x509",
      attributes: {
        id,
        label: algorithm.label || certLabel,
        token: !!(algorithm.token),
      },
    });

    // set X509 attributes
    template.value = Buffer.from(data);
    const asn = asn1Schema.AsnConvert.parse(data, asnX509.Certificate);
    template.serial = Buffer.from(asn1Schema.AsnConvert.serialize(asn1Schema.AsnIntegerArrayBufferConverter.toASN(asn.tbsCertificate.serialNumber)));
    template.subject = Buffer.from(asn1Schema.AsnConvert.serialize(asn.tbsCertificate.subject));
    template.issuer = Buffer.from(asn1Schema.AsnConvert.serialize(asn.tbsCertificate.issuer));

    this.p11Object = this.crypto.session.create(template).toType<graphene.X509Certificate>();
  }

  public async exportCert(): Promise<ArrayBuffer> {
    return this.value;
  }

  public toJSON(): X509CertificateJson {
    return {
      publicKey: this.publicKey.toJSON(),
      notBefore: this.notBefore,
      notAfter: this.notAfter,
      subjectName: this.subjectName,
      issuerName: this.issuerName,
      serialNumber: this.serialNumber,
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
            this.publicKey = await this.crypto.keyStorage.getItem(keyIndex, algorithm, usages);
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
      this.x509 = new x509.X509Certificate(data);
    } catch {
      throw new ParserError("Cannot parse X509 certificate");
    }
  }

  /**
   * returns parsed ASN1 value
   */
  protected getData(): x509.X509Certificate {
    if (!this.x509) {
      this.parse(this.value);
    }
    return this.x509!;
  }

  /**
   * Returns name from subject of the certificate
   */
  protected getName(): string {
    const name = new x509.Name(this.subjectName).toJSON();
    for (const item of name) {
      const commonName = item.CN;
      if (commonName && commonName.length > 0) { // CN
        return commonName[0];
      }
    }
    return this.subjectName;
  }

}
