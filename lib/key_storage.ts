import * as webcrypto from "webcrypto-core";
const WebCryptoError = webcrypto.WebCryptoError;

import { KeyType, NamedCurve, ObjectClass, SecretKey, Session, SessionObject } from "graphene-pk11";
import { PrepareAlgorithm } from "webcrypto-core";
import { CryptoKey } from "./key";

export class KeyStorage implements IKeyStorage {

    protected session: Session;

    constructor(session: Session) {
        this.session = session;
    }

    public async keys() {
        const keys: string[] = [];
        [ObjectClass.PRIVATE_KEY, ObjectClass.PUBLIC_KEY].forEach((objectClass) => {
            this.session.find({ class: objectClass, token: true }, (obj) => {
                const item = obj.toType<any>();
                keys.push(this.getName(objectClass, item.id));
            });
        });
        return keys;
    }

    public async clear() {
        const keys: SessionObject[] = [];
        [ObjectClass.PRIVATE_KEY, ObjectClass.PUBLIC_KEY].forEach((objectClass) => {
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
            throw new WebCryptoError("Parameter 2 is not P11CryptoKey");
        }
        const p11Key = data as CryptoKey;
        // don't copy object from token
        if (!p11Key.key.token) {
            this.session.copy(p11Key.key, {
                token: true,
            });
        }

        return this.getName(p11Key.key.class, new Buffer(data.id, "binary"));
    }

    protected getItemById(id: string) {
        let key: SessionObject = null;
        [ObjectClass.PRIVATE_KEY, ObjectClass.PUBLIC_KEY].forEach((objectClass) => {
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
            case ObjectClass.PRIVATE_KEY:
                name = "private";
                break;
            case ObjectClass.PUBLIC_KEY:
                name = "public";
                break;
            case ObjectClass.SECRET_KEY:
                name = "secret";
                break;
            default:
                throw new Error(`Unsupported Object type '${type}'`);
        }
        return `${name}-${id.toString("hex")}`;
    }

}
