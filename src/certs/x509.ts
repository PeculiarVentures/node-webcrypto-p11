import * as graphene from "graphene-pk11";
import { Convert } from "pvtsutils";
import * as core from "webcrypto-core";
import { CryptoKey } from "../key";

import { Pkcs11Object } from "../p11_object";
import * as utils from "../utils";

import { CryptoCertificate, Pkcs11ImportAlgorithms } from "./cert";
import { nameToString } from "./utils";

// TODO Remove pkijs, asn1js
const asn1js = require("asn1js");
const pkijs = require("pkijs");

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

  public async importCert(data: Buffer, algorithm: Pkcs11ImportAlgorithms, keyUsages: KeyUsage[]) {
    const array = new Uint8Array(data);
    this.parse(array.buffer as ArrayBuffer);

    const publicKeyInfoSchema = this.schema.subjectPublicKeyInfo.toSchema();
    const publicKeyInfoBuffer = publicKeyInfoSchema.toBER(false);

    const { token, label, sensitive, ...keyAlg } = algorithm; // remove custom attrs for key
    this.publicKey = await this.crypto.subtle.importKey("spki", publicKeyInfoBuffer, keyAlg, true, keyUsages);

    const hashSPKI = this.publicKey.p11Object.id;

    const certLabel = this.getName();

    this.p11Object = this.crypto.session.create({
      id: hashSPKI,
      label: algorithm.label || certLabel,
      class: graphene.ObjectClass.CERTIFICATE,
      certType: graphene.CertificateType.X_509,
      serial: Buffer.from(this.schema.serialNumber.toBER(false)),
      subject: Buffer.from(this.schema.subject.toSchema(true).toBER(false)),
      issuer: Buffer.from(this.schema.issuer.toSchema(true).toBER(false)),
      token: !!(algorithm.token),
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
        pkijs.setEngine("pkcs11", this.crypto, new pkijs.CryptoEngine({ name: "pkcs11", crypto: this.crypto, subtle: this.crypto.subtle }));
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
    const asn1 = asn1js.fromBER(data);
    this.schema = new pkijs.Certificate({ schema: asn1.result });
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
