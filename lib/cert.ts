import { Certificate, CertificateType, ObjectClass, X509Certificate as P11X509Certificate } from "graphene-pk11";
import { Base64Url, PrepareAlgorithm } from "webcrypto-core";

import * as Asn1Js from "asn1js";
import { CryptoKey } from "./key";
import { digest } from "./utils";
import { WebCrypto } from "./webcrypto";

const PkiJs = require("pkijs");

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
 * @returns string Formated string
 * Example:
 * > C=Some name, O=Some organization name, C=RU
 */
export function nameToString(name: any, splitter: string = ","): string {
    const res: string[] = [];
    name.typesAndValues.forEach((typeValue: any) => {
        const type = typeValue.type;
        const value = OID[type.toString()].short;
        res.push(`${value ? value : type}=${typeValue.value.valueBlock.value}`);
    });
    return res.join(splitter + " ");
}

// CryptoX509Certificate

export interface Pkcs11CryptoX509Certificate extends CryptoCertificate {
    p11Object: Certificate;

    importCert(data: ArrayBuffer, algorithm: Algorithm, keyUsages: string[]): Promise<void>;
    exportCert<T extends Pkcs11CryptoX509Certificate>(this: { new: (crypto: WebCrypto) => T }): Promise<T>;
    exportKey(): Promise<CryptoKey>;
    exportKey(algorithm: Algorithm, usages: string[]): Promise<CryptoKey>;

}

// X509Certificate

export class X509Certificate implements CryptoX509Certificate, Pkcs11CryptoX509Certificate {

    public get serialNumber() {
        return this.p11Object.serialNumber;
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
    public get id() {
        return `x509-${this.p11Object.id.toString("hex")}`;
    }
    public type = "x509";

    public publicKey: CryptoKey;

    public get value(): ArrayBuffer {
        return new Uint8Array(this.p11Object.value).buffer;
    }

    public p11Object: P11X509Certificate;
    protected schema: any;
    protected crypto: WebCrypto;

    constructor(crypto: WebCrypto) {
        this.crypto = crypto;
    }

    public async importCert(data: ArrayBuffer, algorithm: Algorithm, keyUsages: string[]) {
        this.parse(data);

        const publicKeyInfoSchema = this.schema.subjectPublicKeyInfo.toSchema();
        const publicKeyInfoBuffer = publicKeyInfoSchema.toBER(false);

        this.publicKey = await this.crypto.subtle.importKey("spki", publicKeyInfoBuffer, algorithm, true, keyUsages);

        const hashSPKI = digest("SHA-1", publicKeyInfoBuffer);

        this.p11Object = this.crypto.session.create({
            id: hashSPKI,
            class: ObjectClass.CERTIFICATE,
            certType: CertificateType.X_509,
            serial: new Buffer(this.schema.serialNumber.toBER(false)),
            subject: new Buffer(this.schema.subject.toSchema(true).toBER(false)),
            issuer: new Buffer(this.schema.issuer.toSchema(true).toBER(false)),
            token: false,
            ski: hashSPKI,
            value: new Buffer(data),
        }).toType<P11X509Certificate>();
    }

    public async exportCert() {
        return this.value;
    }

    public toJSON() {
        return {
            publicKey: this.publicKey,
            notBefore: this.notBefore,
            notAfter: this.notAfter,
            subjectName: this.subjectName,
            issuerName: this.issuerName,
            serialNumber: this.serialNumber,
            type: this.type,
            value: Base64Url.encode(new Uint8Array(this.value)),
        };
    }

    public async exportKey(): Promise<CryptoKey>;
    public async exportKey(algorithm: Algorithm, usages: string[]): Promise<CryptoKey>;
    public async exportKey(algorithm?: Algorithm, usages?: string[]) {
        if (!this.publicKey) {
            let params: { algorithm: { algorithm: any, usages: string[] } };
            if (algorithm) {
                params = {
                    algorithm: {
                        algorithm: PrepareAlgorithm(algorithm),
                        usages,
                    },
                };
            }
            PkiJs.setEngine("pkcs11", this.crypto, this.crypto.subtle);
            return this.getData().getPublicKey(params);
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

}

// X509Certificate

export class X509CertificateRequest implements CryptoX509CertificateRequest, Pkcs11CryptoX509Certificate {

    public get subjectName() {
        return nameToString(this.getData().subject);
    }
    public get id() {
        return `request-${this.p11Object.id.toString("hex")}`;
    }
    public type = "request";

    public publicKey: CryptoKey;

    public get value(): ArrayBuffer {
        return new Uint8Array(this.p11Object.value).buffer;
    }

    public p11Object: P11X509Certificate;
    protected schema: any;
    protected crypto: WebCrypto;

    constructor(crypto: WebCrypto) {
        this.crypto = crypto;
    }

    /**
     * Creates new CertificateRequest in PKCS11 session
     * @param data
     * @param algorithm
     * @param keyUsages
     */
    public async importCert(data: ArrayBuffer, algorithm: Algorithm, keyUsages: string[]) {
        this.parse(data);

        const publicKeyInfoSchema = this.schema.subjectPublicKeyInfo.toSchema();
        const publicKeyInfoBuffer = publicKeyInfoSchema.toBER(false);

        this.publicKey = await this.crypto.subtle.importKey("spki", publicKeyInfoBuffer, algorithm, true, keyUsages);

        const hashSPKI = digest("SHA-1", publicKeyInfoBuffer);

        this.p11Object = this.crypto.session.create({
            objectId: hashSPKI,
            application: "webcrypto-p11",
            class: ObjectClass.DATA,
            label: "X509 Request",
            token: false,
            value: new Buffer(data),
        }).toType<P11X509Certificate>();
    }

    public async exportCert() {
        return this.value;
    }

    public toJSON() {
        return {
            publicKey: this.publicKey.toJSON(),
            subjectName: this.subjectName,
            type: this.type,
            value: Base64Url.encode(new Uint8Array(this.value)),
        };
    }

    public async exportKey(): Promise<CryptoKey>;
    public async exportKey(algorithm: Algorithm, usages: string[]): Promise<CryptoKey>;
    public async exportKey(algorithm?: Algorithm, usages?: string[]) {
        if (!this.publicKey) {
            let params: { algorithm: { algorithm: any, usages: string[] } };
            if (algorithm) {
                params = {
                    algorithm: {
                        algorithm: PrepareAlgorithm(algorithm),
                        usages,
                    },
                };
            }
            PkiJs.setEngine("pkcs11", this.crypto, this.crypto.subtle);
            return this.getData().getPublicKey(params);
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
