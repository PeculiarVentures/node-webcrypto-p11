import * as crypto from "crypto";

import { KeyType, ObjectClass, PublicKey, Session, SessionObject, X509Certificate as P11Certificate, CertificateType, Certificate } from "graphene-pk11";
import { CryptoKey } from "./key";

import * as Asn1Js from "asn1js";
import { WebCrypto } from "./webcrypto";
import { X509Certificate } from "./cert";
const pkijs = require("pkijs");

export class CertificateStorage implements ICertificateStorage {

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
        this.session.clear();
    }

    public async getItem(key: string) {
        const subjectObject = this.getItemById(key);
        if (subjectObject) {
            const x509Object = subjectObject.toType<P11Certificate>();
            const keys = this.session.find({
                class: ObjectClass.PUBLIC_KEY,
                id: x509Object.id,
            });
            if (!keys.length) {
                // TODO: export key from certificate
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
            const cert = new X509Certificate(x509Object);
            cert.publicKey = new CryptoKey(p11Key, alg);
            return cert;
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
        const p11Object = (data as any).handle as Certificate;
        // don't copy object from token
        if (!p11Object.token) {
            this.session.copy(p11Object, {
                token: true,
            });
        }
    }

    public async importCert(type: string, data: ArrayBuffer, algorithm: Algorithm, usages: string[]): Promise<ICertificateStorageItem> {
        const asn1 = Asn1Js.fromBER(data);
        switch (type.toLowerCase()) {
            case "x509": {
                const x509 = new pkijs.Certificate({ schema: asn1.result });

                const publicKeyInfoSchema = x509.subjectPublicKeyInfo.toSchema();
                const publicKeyInfoBuffer = publicKeyInfoSchema.toBER(false);

                const publicKey = await this.crypto.subtle.importKey("spki", publicKeyInfoBuffer, algorithm, true, usages);

                const hash = crypto.createHash("SHA1");
                hash.update(new Buffer(publicKeyInfoBuffer));
                const hashSPKI = hash.digest();

                const x509Object = this.session.create({
                    id: hashSPKI,
                    class: ObjectClass.CERTIFICATE,
                    certType: CertificateType.X_509,
                    serial: new Buffer(x509.serialNumber.toBER(false)),
                    subject: new Buffer(x509.subject.toSchema(true).toBER(false)),
                    issuer: new Buffer(x509.issuer.toSchema(true).toBER(false)),
                    token: false,
                    ski: hashSPKI,
                    value: new Buffer(data),
                });

                const cert = new X509Certificate(x509Object.toType<P11Certificate>());
                cert.publicKey = publicKey;
                return cert
            }
            case "request": {
                const request = new pkijs.CertificationRequest({ schema: asn1.result });

                const publicKeyInfoSchema = request.subjectPublicKeyInfo.toSchema();
                const publicKeyInfoBuffer = publicKeyInfoSchema.toBER(false);

                const publicKey = await this.crypto.subtle.importKey("spki", publicKeyInfoBuffer, algorithm, true, usages);

                return {
                    id: "",
                    publicKey,
                    type: "request",
                    value: data,
                };
            }
            default:
                throw new Error(`Wrong value for parameter type. Must be x509 or request`);
        }
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
