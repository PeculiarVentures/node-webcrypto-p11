import * as webcrypto from "webcrypto-core";
const WebCryptoError = webcrypto.WebCryptoError;

import { Key, Session } from "graphene-pk11";
import { CryptoKey } from "./key";

export class KeyStorage {

    protected session: Session;

    constructor(session: Session) {
        this.session = session;
    }

    public get length(): number {
        throw new Error("Not implemented yet");
    }

    public clear(): void {
        this.session.clear();
    }

    public getItem(key: string) {
        const subjectObject = this.getItemById(key);
        if (subjectObject) {
            const p11Key = subjectObject.toType<Key>();
            const alg = JSON.parse(p11Key.label);
            return new CryptoKey(p11Key, alg);
        } else {
            return null;
        }
    }

    public key(index: number): string {
        throw new Error("Not implemented yet");
    }

    public removeItem(key: string): void {
        const sessionObject = this.getItemById(key);
        if (sessionObject) {
            sessionObject.destroy();
        }
    }

    public setItem(key: string, data: CryptoKey): void {
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

    protected getItemById(id: string) {
        const keys = this.session.find({ id: new Buffer(id) });
        if (!keys.length) {
            // console.log(`WebCrypto:PKCS11: Key by ID '${id}' is not found`);
            return null;
        }
        if (keys.length > 1) {
            console.log(`WebCrypto:PKCS11: ${keys.length} keys matches ID '${id}'`);
        }
        return keys.items(0);
    }

}
