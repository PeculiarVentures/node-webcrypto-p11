import {Key, PrivateKey, PublicKey, SecretKey, ObjectClass, ITemplate} from "graphene-pk11";

import * as error from "./error";

export const KT_PRIVATE = "private";
export const KT_PUBLIC = "public";
export const KT_SECRET = "secret";

export const KU_ENCRYPT = "encrypt";
export const KU_DECRYPT = "decrypt";
export const KU_SIGN = "sign";
export const KU_VERIFY = "verify";
export const KU_WRAP = "wrapKey";
export const KU_UNWRAP = "unwrapKey";
export const KU_DERIVE = "deriveKey";

export interface ITemplatePair {
    privateKey: ITemplate;
    publicKey: ITemplate;
}

export class P11CryptoKey implements CryptoKey {
    type: string;
    extractable: boolean;
    algorithm: any;
    id: string;
    usages: string[] = [];

    private _key: Key | PrivateKey | PublicKey | SecretKey;
    get key(): Key {
        return this._key;
    }

    constructor(key: Key, alg: Algorithm) {

        switch (key.class) {
            case ObjectClass.PUBLIC_KEY:
                this.initPublicKey(key.toType<PublicKey>());
                break;
            case ObjectClass.PRIVATE_KEY:
                this.initPrivateKey(key.toType<PrivateKey>());
                break;
            case ObjectClass.SECRET_KEY:
                this.initSecretKey(key.toType<SecretKey>());
                break;
            default:
                throw new error.WebCryptoError(`Wrong incoming session object '${ObjectClass[key.class]}'`);
        }
        this.algorithm = alg;
        this.id = this._key.getAttribute({id: null}).id.toString();
    }

    protected initPrivateKey(key: PrivateKey) {
        this._key = key;
        this.type = KT_PRIVATE;
        this.extractable = key.extractable;
        this.usages = [];
        if (key.decrypt) this.usages.push(KU_DECRYPT);
        if (key.derive) this.usages.push(KU_DERIVE);
        if (key.sign) this.usages.push(KU_SIGN);
        if (key.unwrap) this.usages.push(KU_UNWRAP);
    }

    protected initPublicKey(key: PublicKey) {
        this._key = key;
        this.type = KT_PUBLIC;
        this.extractable = true;
        if (key.encrypt) this.usages.push(KU_ENCRYPT);
        if (key.verify) this.usages.push(KU_VERIFY);
        if (key.wrap) this.usages.push(KU_WRAP);
    }

    protected initSecretKey(key: SecretKey) {
        this._key = key;
        this.type = KT_SECRET;
        this.extractable = key.extractable;
        if (key.encrypt) this.usages.push(KU_ENCRYPT);
        if (key.verify) this.usages.push(KU_VERIFY);
        if (key.wrap) this.usages.push(KU_WRAP);
        if (key.decrypt) this.usages.push(KU_DECRYPT);
        if (key.derive) this.usages.push(KU_DERIVE);
        if (key.sign) this.usages.push(KU_SIGN);
        if (key.unwrap) this.usages.push(KU_UNWRAP);
    }


}

