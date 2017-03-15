// Core
import { WebCryptoError } from "webcrypto-core";

import { ITemplate, Key, ObjectClass, PrivateKey, PublicKey, SecretKey } from "graphene-pk11";

export interface ITemplatePair {
    privateKey: ITemplate;
    publicKey: ITemplate;
}

export interface CryptoKeyPair extends NativeCryptoKey {
    privateKey: CryptoKey;
    publicKey: CryptoKey;
}

export class CryptoKey implements NativeCryptoKey {

    public type: string;
    public extractable: boolean;
    public algorithm: KeyAlgorithm;
    public id: string;
    public usages: string[] = [];

    private _key: Key | PrivateKey | PublicKey | SecretKey;

    public get key(): Key {
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
                throw new WebCryptoError(`Wrong incoming session object '${ObjectClass[key.class]}'`);
        }
        this.algorithm = alg;
        this.id = this._key.getAttribute({ id: null }).id!.toString();
    }

    protected initPrivateKey(key: PrivateKey) {
        this._key = key;
        this.type = "private";
        try {
            // Yubico throws CKR_ATTRIBUTE_TYPE_INVALID
            this.extractable = key.extractable;
        } catch (e) {
            this.extractable = false;
        }
        this.usages = [];
        if (key.decrypt) {
            this.usages.push("decrypt");
        }
        if (key.derive) {
            this.usages.push("deriveKey");
            this.usages.push("deriveBits");
        }
        if (key.sign) {
            this.usages.push("sign");
        }
        if (key.unwrap) {
            this.usages.push("unwrapKey");
        }
    }

    protected initPublicKey(key: PublicKey) {
        this._key = key;
        this.type = "public";
        this.extractable = true;
        if (key.encrypt) {
            this.usages.push("encrypt");
        }
        if (key.verify) {
            this.usages.push("verify");
        }
        if (key.wrap) {
            this.usages.push("wrapKey");
        }
    }

    protected initSecretKey(key: SecretKey) {
        this._key = key;
        this.type = "secret";
        try {
            // Yubico throws CKR_ATTRIBUTE_TYPE_INVALID
            this.extractable = key.extractable;
        } catch (e) {
            this.extractable = false;
        }
        if (key.encrypt) {
            this.usages.push("encrypt");
        }
        if (key.verify) {
            this.usages.push("verify");
        }
        if (key.wrap) {
            this.usages.push("wrapKey");
        }
        if (key.decrypt) {
            this.usages.push("decrypt");
        }
        if (key.derive) {
            this.usages.push("deriveKey");
            this.usages.push("deriveBits");
        }
        if (key.sign) {
            this.usages.push("sign");
        }
        if (key.unwrap) {
            this.usages.push("unwrapKey");
        }
    }

}

