import * as Asn1Js from "asn1js";
import * as graphene from "graphene-pk11";
import * as core from "webcrypto-core";

import { Convert } from "pvtsutils";
import { Crypto } from "./crypto";
import { CryptoKey } from "./key";
import { Pkcs11Object } from "./p11_object";
import * as utils from "./utils";
import { Pkcs11CertificateAttributes } from '..';

const PkiJs = require("pkijs");

PkiJs.CertificationRequest.prototype.getPublicKey = PkiJs.Certificate.prototype.getPublicKey;


/**
 * List of OIDs
 * Source: https://msdn.microsoft.com/ru-ru/library/windows/desktop/aa386991(v=vs.85).aspx
 */
const OID: { [key: string]: { short?: string, long?: string } } = {
  "2.5.4.3": {
    short: "CN",
    long: "CommonName",
  },
  "2.5.4.6": {
    short: "C",
    long: "Country",
  },
  "2.5.4.5": {
    long: "DeviceSerialNumber",
  },
  "0.9.2342.19200300.100.1.25": {
    short: "DC",
    long: "DomainComponent",
  },
  "1.2.840.113549.1.9.1": {
    short: "E",
    long: "EMail",
  },
  "2.5.4.42": {
    short: "G",
    long: "GivenName",
  },
  "2.5.4.43": {
    short: "I",
    long: "Initials",
  },
  "2.5.4.7": {
    short: "L",
    long: "Locality",
  },
  "2.5.4.10": {
    short: "O",
    long: "Organization",
  },
  "2.5.4.11": {
    short: "OU",
    long: "OrganizationUnit",
  },
  "2.5.4.8": {
    short: "ST",
    long: "State",
  },
  "2.5.4.9": {
    short: "Street",
    long: "StreetAddress",
  },
  "2.5.4.4": {
    short: "SN",
    long: "SurName",
  },
  "2.5.4.12": {
    short: "T",
    long: "Title",
  },
  "1.2.840.113549.1.9.8": {
    long: "UnstructuredAddress",
  },
  "1.2.840.113549.1.9.2": {
    long: "UnstructuredName",
  },
};

/**
 * Converts X500Name to string
 * @param  {RDN} name X500Name
 * @param  {string} splitter Splitter char. Default ','
 * @returns string Formatted string
 * Example:
 * > C=Some name, O=Some organization name, C=RU
 */
export function nameToString(name: any, splitter: string = ","): string {
  const res: string[] = [];
  name.typesAndValues.forEach((typeValue: any) => {
    const type = typeValue.type;
    const oidValue = OID[type.toString()];
    const oidName = oidValue && oidValue.short ? oidValue.short : type.toString();
    res.push(oidName + "=" + typeValue.value.valueBlock.value);
  });
  return res.join(splitter + " ");
}

// CryptoX509Certificate

export abstract class CryptoCertificate extends Pkcs11Object implements Pkcs11CertificateAttributes {

  public static getID(p11Object: graphene.Storage) {
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

  public get id() {
    Pkcs11Object.assertStorage(this.p11Object);

    return CryptoCertificate.getID(this.p11Object);
  }

  public type: core.CryptoCertificateType = "x509";
  public publicKey!: CryptoKey;

  public get token() {
    try {
      Pkcs11Object.assertStorage(this.p11Object);
      return this.p11Object.token;
    } catch { /* nothing */ }
    return false;
  }

  public get label() {
    try {
      Pkcs11Object.assertStorage(this.p11Object);
      return this.p11Object.label;
    } catch { /* nothing */ }
    return "";
  }

  protected crypto: Crypto;

  public constructor(crypto: Crypto) {
    super();
    this.crypto = crypto;
  }

  public abstract importCert(data: Buffer, algorithm: core.ImportAlgorithms, keyUsages: string[], attrs?: Partial<Pkcs11CertificateAttributes>): Promise<void>;
  public abstract exportCert(): Promise<ArrayBuffer>;
  public abstract exportKey(): Promise<CryptoKey>;
  public abstract exportKey(algorithm: Algorithm, usages: string[]): Promise<CryptoKey>;

}

// X509Certificate

export class X509Certificate extends CryptoCertificate implements core.CryptoX509Certificate {

  public get serialNumber() {
    return Buffer.from(this.getData().serialNumber.valueBlock._valueHex).toString("hex");
  }
  public get notBefore() {
    return this.getData().notBefore.value;
  }
  public get notAfter() {
    return this.getData().notAfter.value;
  }
  public get issuerName() {
    return nameToString(this.getData().issuer);
  }
  public get subjectName() {
    return nameToString(this.getData().subject);
  }
  public type: "x509" = "x509";

  public get value(): ArrayBuffer {
    Pkcs11Object.assertStorage(this.p11Object);
    return new Uint8Array(this.p11Object.value).buffer;
  }

  public p11Object?: graphene.X509Certificate;
  protected schema: any;

  public async importCert(data: Buffer, algorithm: core.ImportAlgorithms, keyUsages: KeyUsage[], attrs: Partial<Pkcs11CertificateAttributes>) {
    Crypto.assertSession(this.crypto.session);

    const array = new Uint8Array(data);
    this.parse(array.buffer as ArrayBuffer);

    const publicKeyInfoSchema = this.schema.subjectPublicKeyInfo.toSchema();
    const publicKeyInfoBuffer = publicKeyInfoSchema.toBER(false);

    this.publicKey = await this.crypto.subtle.importKey("spki", publicKeyInfoBuffer, algorithm, true, keyUsages) as CryptoKey;

    const hashSPKI = this.publicKey.p11Object.id;

    const label = attrs.label || this.getName();
    const token = !!attrs.token;

    this.p11Object = this.crypto.session.create({
      id: hashSPKI,
      token,
      label,
      class: graphene.ObjectClass.CERTIFICATE,
      certType: graphene.CertificateType.X_509,
      serial: Buffer.from(this.schema.serialNumber.toBER(false)),
      subject: Buffer.from(this.schema.subject.toSchema(true).toBER(false)),
      issuer: Buffer.from(this.schema.issuer.toSchema(true).toBER(false)),
      private: false,
      value: Buffer.from(data),
    }).toType<graphene.X509Certificate>();
  }

  public async exportCert() {
    return this.value;
  }

  public toJSON() {
    return {
      publicKey: this.publicKey.toJSON(),
      notBefore: this.notBefore,
      notAfter: this.notAfter,
      subjectName: this.subjectName,
      issuerName: this.issuerName,
      serialNumber: this.serialNumber,
      type: this.type,
      value: Convert.ToBase64Url(this.value),
    };
  }

  public async exportKey(): Promise<CryptoKey>;
  public async exportKey(algorithm: Algorithm, usages: KeyUsage[]): Promise<CryptoKey>;
  public async exportKey(algorithm?: Algorithm, usages?: KeyUsage[]) {
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
        let params: { algorithm: { algorithm: any, usages: string[] } };
        PkiJs.setEngine("pkcs11", this.crypto, new PkiJs.CryptoEngine({ name: "pkcs11", crypto: this.crypto, subtle: this.crypto.subtle }));
        if (algorithm && usages) {
          params = {
            algorithm: {
              algorithm: utils.prepareAlgorithm(algorithm),
              usages,
            },
          };
          this.publicKey = await this.getData().getPublicKey(params);
        } else {
          this.publicKey = await this.getData().getPublicKey();
        }
      }
    }
    return this.publicKey;
  }

  protected parse(data: ArrayBuffer) {
    const asn1 = Asn1Js.fromBER(data);
    this.schema = new PkiJs.Certificate({ schema: asn1.result });
  }

  /**
   * returns parsed ASN1 value
   */
  protected getData() {
    if (!this.schema) {
      this.parse(this.value);
    }
    return this.schema;
  }

  /**
   * Returns name from subject of the certificate
   */
  protected getName() {
    const cert = this.getData();
    for (const typeAndValue of cert.subject.typesAndValues) {
      if (typeAndValue.type === "2.5.4.3") { // CN
        return typeAndValue.value.valueBlock.value;
      }
    }
    return this.subjectName;
  }

}

// X509CertificateRequest

export class X509CertificateRequest extends CryptoCertificate implements core.CryptoX509CertificateRequest {

  public get subjectName() {
    return nameToString(this.getData().subject);
  }
  public type: "request" = "request";
  public p11Object?: graphene.Data;

  public get value(): ArrayBuffer {
    Pkcs11Object.assertStorage(this.p11Object);

    return new Uint8Array(this.p11Object.value).buffer as ArrayBuffer;
  }

  protected schema: any;

  /**
   * Creates new CertificateRequest in PKCS11 session
   * @param data
   * @param algorithm
   * @param keyUsages
   */
  public async importCert(data: Buffer, algorithm: core.ImportAlgorithms, keyUsages: KeyUsage[], attrs: Partial<Pkcs11CertificateAttributes>) {
    Crypto.assertSession(this.crypto.session);

    const array = new Uint8Array(data).buffer as ArrayBuffer;
    this.parse(array);

    const publicKeyInfoSchema = this.schema.subjectPublicKeyInfo.toSchema();
    const publicKeyInfoBuffer = publicKeyInfoSchema.toBER(false);

    this.publicKey = await this.crypto.subtle.importKey("spki", publicKeyInfoBuffer, algorithm, true, keyUsages) as CryptoKey;

    const hashSPKI = this.publicKey.p11Object.id;
    const label = attrs.label || "X509 Request";
    const token = !!attrs.token;

    this.p11Object = this.crypto.session.create({
      objectId: hashSPKI,
      label,
      token,
      application: "webcrypto-p11",
      class: graphene.ObjectClass.DATA,
      private: false,
      value: Buffer.from(data),
    }).toType<graphene.Data>();
  }

  public async exportCert() {
    return this.value;
  }

  public toJSON() {
    return {
      publicKey: this.publicKey.toJSON(),
      subjectName: this.subjectName,
      type: this.type,
      value: Convert.ToBase64Url(this.value),
    };
  }

  public async exportKey(): Promise<CryptoKey>;
  public async exportKey(algorithm: Algorithm, usages: KeyUsage[]): Promise<CryptoKey>;
  public async exportKey(algorithm?: Algorithm, usages?: KeyUsage[]) {
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
        let params: { algorithm: { algorithm: any, usages: string[] } };
        PkiJs.setEngine("pkcs11", this.crypto, new PkiJs.CryptoEngine({ name: "pkcs11", crypto: this.crypto, subtle: this.crypto.subtle }));
        if (algorithm && usages) {
          params = {
            algorithm: {
              algorithm: utils.prepareAlgorithm(algorithm),
              usages,
            },
          };
          this.publicKey = await this.getData().getPublicKey(params);
        } else {
          this.publicKey = await this.getData().getPublicKey();
        }
      }
    }
    return this.publicKey;
  }

  protected parse(data: ArrayBuffer) {
    const asn1 = Asn1Js.fromBER(data);
    this.schema = new PkiJs.CertificationRequest({ schema: asn1.result });
  }

  /**
   * returns parsed ASN1 value
   */
  protected getData() {
    if (!this.schema) {
      this.parse(this.value);
    }
    return this.schema;
  }

}
