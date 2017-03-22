import * as Asn1Js from "asn1js";
import { X509Certificate as P11X509Certificate } from "graphene-pk11";
const { Certificate } = require("pkijs");

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


export class X509Certificate implements IX509Certificate {

    public get serialNumber() {
        return this.handle.serialNumber;
    }
    public get issuerName(){
        return nameToString(this.getData().issuer);
    }
    public get subjectName() {
        return nameToString(this.getData().subject);
    }
    public get id() {
        return this.handle.id.toString("hex");
    }
    public type = "x509";

    public publicKey: CryptoKey;

    public get value(): ArrayBuffer {
        return new Uint8Array(this.handle.value).buffer;
    }

    protected handle: P11X509Certificate;
    protected asn1: any;

    constructor(p11X509: P11X509Certificate) {
        this.handle = p11X509;
    }

    /**
     * returns parsed ASN1 value
     */
    protected getData() {
        if (!this.asn1) {
            const asn1 = Asn1Js.fromBER(this.value);
            this.asn1 = new Certificate({ schema: asn1.result });
        }
        return this.asn1;
    }

}
