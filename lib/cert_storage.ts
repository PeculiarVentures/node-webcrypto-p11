import * as webcrypto from "webcrypto-core";
const WebCryptoError = webcrypto.WebCryptoError;

import { KeyType, ObjectClass, PublicKey, Session, SessionObject, X509Certificate } from "graphene-pk11";
import { CryptoKey } from "./key";

export class CertificateStorage implements ICertificateStorage {

    protected session: Session;

    constructor(session: Session) {
        this.session = session;
    }

    public async keys() {
        const keys: string[] = [];
        [ObjectClass.CERTIFICATE].forEach((objectClass) => {
            this.session.find({ class: objectClass }, (obj) => {
                const item = obj.toType<any>();
                keys.push(this.getName(objectClass, item.id));
            });
        });
        return keys;
    }

    public async clear() {
        this.session.clear();
    }

    public async getItem(key: string) {
        const subjectObject = this.getItemById(key);
        if (subjectObject) {
            const x509 = subjectObject.toType<X509Certificate>();
            const keys = this.session.find({
                class: ObjectClass.PUBLIC_KEY,
                id: x509.id,
            });
            if (!keys.length) {
                throw new Error("Cannot find public key for Certificate");
            }
            const p11Key = keys.items(0).toType<PublicKey>();
            const alg: any = {};
            // name
            switch (p11Key.type) {
                case KeyType.RSA: {
                    if (p11Key.verify) {
                        alg.name = "RSASSA-PKCS1-v1_5";
                    } else {
                        alg.name = "RSA-OAEP";
                    }
                    alg.hash = { name: "SHA-256" };
                    break;
                }
                case KeyType.EC: {
                    throw new Error(`Not implemented yet`);
                }
                default:
                    throw new Error(`Unsupported type of key '${KeyType[p11Key.type] || p11Key.type}'`);
            }
            // const alg = JSON.parse(p11Key.label);
            return {
                id: x509.id.toString("hex"),
                type: "x509",
                publicKey: new CryptoKey(p11Key, alg),
                value: new Uint8Array(x509.value).buffer,
            } as IX509Certificate;
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

    public async setItem(key: string, data: ICertificateStorageItem) {
        if (!(data instanceof CryptoKey)) {
            throw new WebCryptoError("Parameter 2 is not P11CryptoKey");
        }
        const p11Key = data as CryptoKey;
        // don't copy object from token
        if (!p11Key.key.token) {
            this.session.copy(p11Key.key, {
                token: true,
                id: new Buffer(key),
                label: JSON.stringify(data.algorithm),
            });
        }
    }

    public async importCert(type: string, data: ArrayBuffer, algorithm: Algorithm, keyUsages: string[]): Promise<ICertificateStorageItem> {
        throw new Error("Method not implemented.");
    }

    protected getItemById(id: string) {
        let key: SessionObject = null;
        [ObjectClass.CERTIFICATE].forEach((objectClass) => {
            this.session.find({ class: objectClass }, (obj) => {
                const item = obj.toType<any>();
                if (id === this.getName(objectClass, item.id)) {
                    key = item;
                    return false;
                }
            });
        });
        return key;
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
