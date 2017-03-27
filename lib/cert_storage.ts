import { CertificateType, Data as P11Data, ObjectClass, Session, SessionObject, X509Certificate as P11X509Certificate } from "graphene-pk11";

import { Pkcs11CryptoCertificate, X509Certificate, X509CertificateRequest } from "./cert";
import * as utils from "./utils";
import { WebCrypto } from "./webcrypto";

const TEMPLATES = [
    { class: ObjectClass.CERTIFICATE, certType: CertificateType.X_509, token: true },
    { class: ObjectClass.DATA, token: true, label: "X509 Request" },
];

export class Pkcs11CertificateStorage implements CertificateStorage {

    protected session: Session;
    protected crypto: WebCrypto;

    constructor(session: Session, crypto: WebCrypto) {
        this.session = session;
        this.crypto = crypto;
    }

    public async keys() {
        const keys: string[] = [];
        TEMPLATES.forEach((template) => {
            this.session.find(template, (obj) => {
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
            this.session.find(template, (obj) => {
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
            this.session.copy(data.p11Object, {
                token: true,
            });
        }
        return data.id;
    }

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
            this.session.find(template, (obj) => {
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
