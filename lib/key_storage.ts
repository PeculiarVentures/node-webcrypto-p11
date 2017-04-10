import * as webcrypto from "webcrypto-core";
const WebCryptoError = webcrypto.WebCryptoError;

import { KeyType, NamedCurve, ObjectClass, SecretKey, Session, SessionObject } from "graphene-pk11";
import { PrepareAlgorithm } from "webcrypto-core";
import { CryptoKey } from "./key";

const OBJECT_TYPES = [ObjectClass.PRIVATE_KEY, ObjectClass.PUBLIC_KEY, ObjectClass.SECRET_KEY];

export class KeyStorage implements IKeyStorage {

    protected session: Session;

    constructor(session: Session) {
        this.session = session;
    }

    public async keys() {
        const keys: string[] = [];
        OBJECT_TYPES.forEach((objectClass) => {
            this.session.find({ class: objectClass, token: true }, (obj) => {
                const item = obj.toType<any>();
                keys.push(CryptoKey.getID(item));
            });
        });
        return keys;
    }

    public async indexOf(item: CryptoKey) {
        if (item instanceof CryptoKey && item.key.token) {
            return CryptoKey.getID(item.key);
        }
        return null;
    }

    public async clear() {
        const keys: SessionObject[] = [];
        OBJECT_TYPES.forEach((objectClass) => {
            this.session.find({ class: objectClass, token: true }, (obj) => {
                keys.push(obj);
            });
        });
        keys.forEach((key) => {
            key.destroy();
        });
    }

    public async getItem(key: string): Promise<CryptoKey>;
    public async getItem(key: string, algorithm: Algorithm, usages: string[]): Promise<CryptoKey>;
    public async getItem(key: string, algorithm?: Algorithm, usages?: string[]) {
        const subjectObject = this.getItemById(key);
        if (subjectObject) {
            const p11Key = subjectObject.toType<SecretKey>();
            let alg: any;
            if (algorithm) {
                alg = PrepareAlgorithm(algorithm);
            } else {
                // name
                alg = {};
                switch (p11Key.type) {
                    case KeyType.RSA: {
                        if (p11Key.sign || p11Key.verify) {
                            alg.name = "RSASSA-PKCS1-v1_5";
                        } else {
                            alg.name = "RSA-OAEP";
                        }
                        alg.hash = { name: "SHA-256" };
                        break;
                    }
                    case KeyType.EC: {
                        if (p11Key.sign || p11Key.verify) {
                            alg.name = "ECDSA";
                        } else {
                            alg.name = "ECDH";
                        }
                        const attributes = p11Key.getAttribute({ paramsECDSA: null });
                        const pointEC = NamedCurve.getByBuffer(attributes.paramsECDSA);
                        let namedCurve: string;
                        switch (pointEC.name) {
                            case "secp192r1":
                                namedCurve = "P-192";
                                break;
                            case "secp256r1":
                                namedCurve = "P-256";
                                break;
                            case "secp384r1":
                                namedCurve = "P-384";
                                break;
                            case "secp521r1":
                                namedCurve = "P-521";
                                break;
                            default:
                                throw new Error(`Unsupported named curve for EC key '${pointEC.name}'`);
                        }
                        alg.namedCurve = namedCurve;
                        break;
                    }
                    case KeyType.AES: {
                        if (p11Key.sign || p11Key.verify) {
                            alg.name = "AES-HMAC";
                        } else {
                            alg.name = "AES-CBC";
                        }
                        break;
                    }
                    default:
                        throw new Error(`Unsupported type of key '${KeyType[p11Key.type] || p11Key.type}'`);
                }
            }
            return new CryptoKey(p11Key, alg);
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

    public async setItem(data: CryptoKey) {
        if (!(data instanceof CryptoKey)) {
            throw new WebCryptoError("Parameter 1 is not P11CryptoKey");
        }
        const p11Key = data as CryptoKey;

        // don't copy object from token
        if (!(this.hasItem(data) && p11Key.key.token)) {
            const obj = this.session.copy(p11Key.key, {
                token: true,
            });
            return CryptoKey.getID(obj.toType<any>());
        } else {
            return data.id;
        }

    }

    public hasItem(key: CryptoKey) {
        const item = this.getItemById(key.id);
        return !!item;
    }

    protected getItemById(id: string) {
        let key: SessionObject = null;
        OBJECT_TYPES.forEach((objectClass) => {
            this.session.find({ class: objectClass, token: true }, (obj) => {
                const item = obj.toType<any>();
                if (id === CryptoKey.getID(item)) {
                    key = item;
                    return false;
                }
            });
        });
        return key;
    }

}
