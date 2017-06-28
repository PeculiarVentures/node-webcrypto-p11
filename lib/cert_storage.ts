import { CertificateType, Data as P11Data, ObjectClass, SessionObject, X509Certificate as P11X509Certificate } from "graphene-pk11";

import { Pkcs11CryptoCertificate, X509Certificate, X509CertificateRequest } from "./cert";
import * as utils from "./utils";
import { WebCrypto } from "./webcrypto";

const TEMPLATES = [
    { class: ObjectClass.CERTIFICATE, certType: CertificateType.X_509, token: true },
    { class: ObjectClass.DATA, token: true, label: "X509 Request" },
];

export class Pkcs11CertificateStorage implements CertificateStorage {

    protected crypto: WebCrypto;

    constructor(crypto: WebCrypto) {
        this.crypto = crypto;
    }

    public async indexOf(item: Pkcs11CryptoCertificate) {
        if (item instanceof Pkcs11CryptoCertificate && item.p11Object.token) {
            return Pkcs11CryptoCertificate.getID(item.p11Object);
        }
        return null;
    }

    public async keys() {
        const keys: string[] = [];
        TEMPLATES.forEach((template) => {
            this.crypto.session.find(template, (obj) => {
                const item = obj.toType<any>();
                const id = Pkcs11CryptoCertificate.getID(item);
                keys.push(id);
            });
        });
        return keys;
    }

    public async clear() {
        const objects: SessionObject[] = [];
        TEMPLATES.forEach((template) => {
            this.crypto.session.find(template, (obj) => {
                objects.push(obj);
            });
        });
        objects.forEach((obj) => {
            obj.destroy();
        });
    }

    public getItem(key: string): Promise<CryptoCertificate>;
    public getItem(key: string, algorithm: Algorithm, usages: string[]): Promise<CryptoCertificate>;
    public async getItem(key: string, algorithm?: Algorithm, usages?: string[]) {
        const storageObject = this.getItemById(key);
        if (storageObject instanceof P11X509Certificate) {
            const x509Object = storageObject.toType<P11X509Certificate>();
            const x509 = new X509Certificate(this.crypto);
            x509.p11Object = x509Object;
            await x509.exportKey(algorithm, usages);
            return x509;
        } else if (storageObject instanceof P11Data) {
            const x509Object = storageObject.toType<P11Data>();
            const x509request = new X509CertificateRequest(this.crypto);
            x509request.p11Object = x509Object;
            await x509request.exportKey(algorithm, usages);
            return x509request;
        } else {
            return null;
        }
    }

    public async removeItem(key: string) {
        const sessionObject = this.getItemById(key);
        if (sessionObject) {
            sessionObject.destroy();
        }
    }

    public async setItem(data: Pkcs11CryptoCertificate) {
        if (!(data instanceof Pkcs11CryptoCertificate)) {
            throw new Error("Incoming data is not PKCS#11 CryptoCertificate");
        }
        // don't copy object from token
        if (!data.p11Object.token) {
            const obj = this.crypto.session.copy(data.p11Object, {
                token: true,
            });
            return Pkcs11CryptoCertificate.getID(obj.toType<any>());
        } else {
            return data.id;
        }
    }

    public exportCert(type: "pem", item: CryptoCertificate): Promise<string>;
    public exportCert(type: "raw", item: CryptoCertificate): Promise<ArrayBuffer>;
    public async exportCert(format: CryptoCertificateFormat, cert: Pkcs11CryptoCertificate): Promise<ArrayBuffer | string> {
        switch (format) {
            case "pem": {
                throw Error("PEM format is not implemented");
            }
            case "raw": {
                return cert.exportCert();
            }
            default:
                throw new Error(`Unsupported format in use ${format}`);
        }
    }

    public importCert(type: "request", data: BufferSource, algorithm: Algorithm, keyUsages: string[]): Promise<CryptoX509CertificateRequest>;
    public importCert(type: "x509", data: BufferSource, algorithm: Algorithm, keyUsages: string[]): Promise<CryptoX509Certificate>;
    public async importCert(type: string, data: NodeBufferSource, algorithm: Algorithm, usages: string[]): Promise<CryptoCertificate> {
        const preparedData = utils.PrepareData(data);
        switch (type.toLowerCase()) {
            case "x509": {
                const x509 = new X509Certificate(this.crypto);
                await x509.importCert(preparedData, algorithm, usages);
                return x509;
            }
            case "request": {
                const request = new X509CertificateRequest(this.crypto);
                await request.importCert(preparedData, algorithm, usages);
                return request;
            }
            default:
                throw new Error(`Wrong value for parameter type. Must be x509 or request`);
        }
    }

    protected getItemById(id: string) {
        let object: SessionObject = null;
        TEMPLATES.forEach((template) => {
            this.crypto.session.find(template, (obj) => {
                const item = obj.toType<any>();
                if (id === Pkcs11CryptoCertificate.getID(item)) {
                    object = item;
                    return false;
                }
            });
        });
        return object;
    }

}
