import {SessionObject, Session, Key, KeyType} from "graphene-pk11";
import {WebCryptoError} from "./error";
import {P11CryptoKey} from "./key";

export class P11KeyStorage implements NodeKeyStorage {

    protected session: Session;

    constructor(session: Session) {
        this.session = session;
    }

    get length(): number {
        throw new Error("Not implemented yet");
    }
    clear(): void {
        this.session.clear();
    }

    protected getItemById(id: string): SessionObject {
        let keys = this.session.find({ id: new Buffer(id) });
        if (!keys.length) {
            // console.log(`WebCrypto:PKCS11: Key by ID '${id}' is not found`);
            return null;
        }
        if (keys.length > 1)
            console.log(`WebCrypto:PKCS11: ${keys.length} keys matches ID '${id}'`);
        return keys.items(0);
    }

    getItem(key: string): CryptoKey {
        let sobj = this.getItemById(key);
        if (sobj) {
            let _key = sobj.toType<Key>();
            let alg = JSON.parse(_key.label);
            return new P11CryptoKey(_key, alg);
        }
        else
            return null;
    }

    key(index: number): string {
        throw new Error("Not implemented yet");
    }

    removeItem(key: string): void {
        let sobj = this.getItemById(key);
        if (sobj) {
            sobj.destroy();
        }
    }

    setItem(key: string, data: CryptoKey): void {
        if (!(data instanceof P11CryptoKey))
            throw new WebCryptoError("Parameter 2 is not P11CryptoKey");
        let _key = data as P11CryptoKey;
        // don't copy object from token
        if (!_key.key.token) {
            this.session.copy(_key.key, {
                token: true,
                id: new Buffer(key),
                label: JSON.stringify(data.algorithm)
            });
        }
    }

}