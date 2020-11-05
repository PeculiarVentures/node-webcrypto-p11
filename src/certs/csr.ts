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
  public async importCert(data: Buffer, algorithm: Pkcs11ImportAlgorithms, keyUsages: KeyUsage[]) {
    const array = new Uint8Array(data).buffer as ArrayBuffer;
    this.parse(array);

    const publicKeyInfoSchema = this.schema.subjectPublicKeyInfo.toSchema();
    const publicKeyInfoBuffer = publicKeyInfoSchema.toBER(false);

    const { token, label, sensitive, ...keyAlg } = algorithm; // remove custom attrs for key
    this.publicKey = await this.crypto.subtle.importKey("spki", publicKeyInfoBuffer, keyAlg, true, keyUsages) as CryptoKey;

    const hashSPKI = this.publicKey.p11Object.id;

    this.p11Object = this.crypto.session.create({
      objectId: hashSPKI,
      application: "webcrypto-p11",
      class: graphene.ObjectClass.DATA,
      label: algorithm.label || "X509 Request",
      token: !!(algorithm.token),
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
    this.schema = new pkijs.CertificationRequest({ schema: asn1.result });
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
