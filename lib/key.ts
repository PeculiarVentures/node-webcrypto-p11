import * as iwc from "./iwebcrypto"
import * as graphene from "graphene-pk11"

export class CryptoKey implements iwc.ICryptoKey {
    type: string;
    extractable: boolean;
    algorithm: any;
    usages: string[] = [];

    private _key;
    get key(): graphene.Key {
        return this._key;
    }

    constructor(key, alg: iwc.IAlgorithmIdentifier) {
        key = key.toType();
        this._key = key;
        this.extractable = !key.isExractable || key.isExractable();
        this.algorithm = alg;
        // set key type
        switch (key.getClass()) {
            case graphene.Enums.ObjectClass.PrivateKey:
                this.type = "private";
                break;
            case graphene.Enums.ObjectClass.PublicKey:
                this.type = "public";
                break;
            case graphene.Enums.ObjectClass.SecretKey:
                this.type = "secret";
                break;
        }
        // set key usages
        if (this.type === "private" || this.type === "secret") {
            if (key.isDecrypt())
                this.usages.push("decrypt");
            if (key.isSign())
                this.usages.push("sign");
            if (key.isUnwrap())
                this.usages.push("unwrap");
        }
        if (this.type === "public" || this.type === "secret") {
            if (key.isEncrypt())
                this.usages.push("encrypt");
            if (key.isVerify())
                this.usages.push("verify");
            if (key.isWrap())
                this.usages.push("wrap");
        }
    }
}

