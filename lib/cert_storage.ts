import { Certificate, ObjectClass, Session, SessionObject, X509Certificate as P11Certificate } from "graphene-pk11";

import { X509Certificate, X509CertificateRequest } from "./cert";
import { WebCrypto } from "./webcrypto";

export class Pkcs11CertificateStorage implements CertificateStorage {

    protected session: Session;
    protected crypto: WebCrypto;

    constructor(session: Session, crypto: WebCrypto) {
        this.session = session;
        this.crypto = crypto;
    }

    public async keys() {
        const keys: string[] = [];
        [ObjectClass.CERTIFICATE].forEach((objectClass) => {
            this.session.find({ class: objectClass, token: true }, (obj) => {
                const item = obj.toType<any>();
                keys.push(this.getName(objectClass, item.id));
            });
        });
        return keys;
    }

    public async clear() {
        const objects: SessionObject[] = [];
        [ObjectClass.CERTIFICATE].forEach((objectClass) => {
            this.session.find({ class: objectClass, token: true }, (obj) => {
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
        const sessionObject = this.getItemById(key);
        if (sessionObject) {
            const x509Object = sessionObject.toType<P11Certificate>();
            const x509 = new X509Certificate(this.crypto);
            x509.p11Object = x509Object;

            const publicKey = await this.crypto.keyStorage.getItem(`public-${x509Object.id.toString("hex")}`, algorithm, usages);
            if (!publicKey) {
                // export public key from certificate
                x509.publicKey = await x509.exportKey(algorithm, usages);
            } else {
                x509.publicKey  = publicKey;
            }
            return x509;
        } else {
            return null;
        }
    }

    public key(index: number): string {
        throw new Error("Not implemented yet");
    }

    public async removeItem(key: string) {
        const sessionObject = this.getItemById(key);
        if (sessionObject) {
            sessionObject.destroy();
        }
    }

    public async setItem(data: CryptoCertificate) {
        const p11Object = (data as any).handle as Certificate;
        // don't copy object from token
        if (!p11Object.token) {
            this.session.copy(p11Object, {
                token: true,
            });
        }
        return this.getName(p11Object.class, p11Object.toType<P11Certificate>().id);
    }

    public exportCert(cert: CryptoCertificate) {
        return (cert as any).value;
    }

    public async importCert(type: string, data: ArrayBuffer, algorithm: Algorithm, usages: string[]): Promise<CryptoCertificate> {
        switch (type.toLowerCase()) {
            case "x509": {
                const x509 = new X509Certificate(this.crypto);
                await x509.importCert(data, algorithm, usages);
                return x509;
            }
            case "request": {
                const request = new X509CertificateRequest(this.crypto);
                await request.importCert(data, algorithm, usages);
                return request;
            }
            default:
                throw new Error(`Wrong value for parameter type. Must be x509 or request`);
        }
    }

    protected getItemById(id: string) {
        let object: SessionObject = null;
        [ObjectClass.CERTIFICATE].forEach((objectClass) => {
            this.session.find({ class: objectClass }, (obj) => {
                const item = obj.toType<any>();
                if (id === this.getName(objectClass, item.id)) {
                    object = item;
                    return false;
                }
            });
        });
        return object;
    }

    /**
     * Returns name for item by it's type and id
     * Template: <type>-<hex(id)>
     *
     * @protected
     * @param {ObjectClass} type
     * @param {Buffer} id
     * @returns
     *
     * @memberOf KeyStorage
     */
    protected getName(type: ObjectClass, id: Buffer) {
        let name: string;
        switch (type) {
            case ObjectClass.CERTIFICATE:
                name = "x509";
                break;
            default:
                throw new Error(`Unsupported Object type '${type}'`);
        }
        return `${name}-${id.toString("hex")}`;
    }

}
