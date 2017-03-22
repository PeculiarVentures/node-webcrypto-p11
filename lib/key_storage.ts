import * as webcrypto from "webcrypto-core";
const WebCryptoError = webcrypto.WebCryptoError;

import { KeyType, ObjectClass, SecretKey, Session, SessionObject } from "graphene-pk11";
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
        this.session.clear();
    }

    public async getItem(key: string) {
        const subjectObject = this.getItemById(key);
        if (subjectObject) {
            const p11Key = subjectObject.toType<SecretKey>();
            const alg: any = {};
            // name
            switch (p11Key.type) {
                case KeyType.RSA: {
                    if (p11Key.sign || p11Key.verify) {
                        alg.name = "RSASSA-PKCS1-v1_5";
                    } else {
                        alg.name = "RSA-OAEP";
                    }
                    alg.hash = "SHA-256";
                    break;
                }
                case KeyType.EC: {
                    throw new Error(`Not implemented yet`);
                }
                default:
                    throw new Error(`Unsupported type of key '${KeyType[p11Key.type] || p11Key.type}'`);
            }
            // const alg = JSON.parse(p11Key.label);
            return new CryptoKey(p11Key, alg);
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

    public async setItem(key: string, data: CryptoKey) {
        if (!(data instanceof CryptoKey)) {
            throw new WebCryptoError("Parameter 2 is not P11CryptoKey");
        }
        const p11Key = data as CryptoKey;
        // don't copy object from token
        if (!p11Key.key.token) {
            this.session.copy(p11Key.key, {
                token: true,
                id: new Buffer(p11Key.id),
                label: JSON.stringify(data.algorithm),
            });
        }
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
