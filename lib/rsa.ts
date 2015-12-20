import * as graphene from "graphene-pk11";
let RSA = graphene.RSA;
let Enums = graphene.Enums;

import * as alg from "./alg";
import * as iwc from "./iwebcrypto";
import {CryptoKey} from "./key";
import * as aes from "./aes";

let ALG_NAME_RSA_PKCS1 = "RSASSA-PKCS1-v1_5";
let ALG_NAME_RSA_PSS = "RSA-PSS";
let ALG_NAME_RSA_OAEP = "RSA-OAEP";

let HASH_ALGS = ["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"];

export class Rsa extends alg.AlgorithmBase {
    static generateKey(session: graphene.Session, alg: any, extractable: boolean, keyUsages: string[], label?: string): iwc.ICryptoKeyPair {
        let size = alg.modulusLength;
        let exp = new Buffer(alg.publicExponent);
        let _key = session.generate("RSA", null, {
            "label": label,
            "token": true,
            "extractable": extractable,
            "keyUsages": keyUsages,
            "modulusLength": size,
            "publicExponent": exp
        });

        return {
            privateKey: new RsaKey(_key.privateKey, alg),
            publicKey: new RsaKey(_key.publicKey, alg)
        };
    }

    static checkRsaGenParams(alg: IRsaKeyGenParams) {
        if (!alg.modulusLength)
            throw new TypeError("RsaKeyGenParams: modulusLength: Missing required property");
        if (alg.modulusLength < 256 || alg.modulusLength > 16384)
            throw new TypeError("RsaKeyGenParams: The modulus length must be a multiple of 8 bits and >= 256 and <= 16384");
        if (!(alg.publicExponent && alg.publicExponent instanceof Uint8Array))
            throw new TypeError("RsaKeyGenParams: publicExponent: Missing or not a Uint8Array");
    }

    static checkAlgorithmHashedParams(alg: iwc.IAlgorithmIdentifier) {
        super.checkAlgorithmHashedParams(alg);
        let _alg = alg.hash;
        _alg.name = _alg.name.toUpperCase();
        if (HASH_ALGS.indexOf(_alg.name) === -1)
            throw new Error("AlgorithmHashedParams: Unknow hash algorithm in use");
    }

    static wc2pk11(alg) {
        RsaPKCS1.checkAlgorithmHashedParams(alg);
        let _alg = null;
        switch (alg.hash.name.toUpperCase()) {
            case "SHA-1":
                _alg = "SHA1_RSA_PKCS";
                break;
            case "SHA-224":
                _alg = "SHA224_RSA_PKCS";
                break;
            case "SHA-256":
                _alg = "SHA256_RSA_PKCS";
                break;
            case "SHA-384":
                _alg = "SHA384_RSA_PKCS";
                break;
            case "SHA-512":
                _alg = "SHA512_RSA_PKCS";
                break;
            default:
                throw new TypeError("Unknown Hash agorithm name in use");
        }
        return _alg;
    }
}

export interface IRsaKeyGenParams extends iwc.IAlgorithmIdentifier {
    modulusLength: number;
    publicExponent: Uint8Array;
}

export class RsaKey extends CryptoKey {
    modulusLength: number;
    publicExponent: Uint8Array;

    constructor(key, alg: IRsaKeyGenParams) {
        super(key, alg);
        this.modulusLength = alg.modulusLength;
        this.publicExponent = alg.publicExponent;
        // TODO: get params from key if alg params is empty
    }
}

export class RsaPKCS1 extends Rsa {
    static ALGORITHM_NAME: string = ALG_NAME_RSA_PKCS1;

    static generateKey(session: graphene.Session, alg: IRsaKeyGenParams, extractable: boolean, keyUsages: string[], label?: string): iwc.ICryptoKeyPair {
        this.checkAlgorithmIdentifier(alg);
        this.checkRsaGenParams(alg);
        this.checkAlgorithmHashedParams(alg);

        let keyPair: iwc.ICryptoKeyPair = super.generateKey.apply(this, arguments);
        return keyPair;
    }

    static sign(session: graphene.Session, alg: iwc.IAlgorithmIdentifier, key: CryptoKey, data: Buffer) {
        this.checkAlgorithmIdentifier(alg);
        this.checkPrivateKey(key);
        let _alg = this.wc2pk11(key.algorithm);

        let signer = session.createSign(_alg, key.key);
        signer.update(data);
        let signature = signer.final();

        return signature;
    }

    static verify(session: graphene.Session, alg: iwc.IAlgorithmIdentifier, key: CryptoKey, signature: Buffer, data: Buffer): boolean {
        this.checkAlgorithmIdentifier(alg);
        this.checkPublicKey(key);
        let _alg = this.wc2pk11(key.algorithm);

        let signer = session.createVerify(_alg, key.key);
        signer.update(data);
        let res = signer.final(signature);

        return res;
    }

}

export class RsaPSS extends Rsa {
    static ALGORITHM_NAME: string = ALG_NAME_RSA_PSS;

    static generateKey(session: graphene.Session, alg: IRsaKeyGenParams, extractable: boolean, keyUsages: string[], label?: string): iwc.ICryptoKeyPair {
        throw new Error("not realized in this implementation");
    }
}

export class RsaOAEP extends Rsa {
    static ALGORITHM_NAME: string = ALG_NAME_RSA_OAEP;

    static generateKey(session: graphene.Session, alg: IRsaKeyGenParams, extractable: boolean, keyUsages: string[], label?: string): iwc.ICryptoKeyPair {
        this.checkAlgorithmIdentifier(alg);
        this.checkRsaGenParams(alg);
        this.checkAlgorithmHashedParams(alg);

        let keyPair: iwc.ICryptoKeyPair = super.generateKey.apply(this, arguments);
        return keyPair;
    }

    static wc2pk11(alg) {
        let params = null;
        switch (alg.hash.name.toUpperCase()) {
            case "SHA-1":
                params = new RSA.RsaOAEPParams(Enums.Mechanism.SHA1, Enums.MGF1.SHA1);
                break;
            case "SHA-224":
                params = new RSA.RsaOAEPParams(Enums.Mechanism.SHA224, Enums.MGF1.SHA224);
                break;
            case "SHA-256":
                params = new RSA.RsaOAEPParams(Enums.Mechanism.SHA256, Enums.MGF1.SHA256);
                break;
            case "SHA-384":
                params = new RSA.RsaOAEPParams(Enums.Mechanism.SHA384, Enums.MGF1.SHA384);
                break;
            case "SHA-512":
                params = new RSA.RsaOAEPParams(Enums.Mechanism.SHA512, Enums.MGF1.SHA512);
                break;
            default:
                throw new Error("Unknown hash name in use");
        }
        let res = { name: "RSA_PKCS_OAEP", params: params };
        return res;
    }

    static encrypt(session: graphene.Session, alg: iwc.IAlgorithmIdentifier, key: CryptoKey, data: Buffer): Buffer {
        this.checkAlgorithmIdentifier(alg);
        this.checkPublicKey(key);
        let _alg = this.wc2pk11(key.algorithm);

        // TODO: Remove <any>
        let enc = session.createEncrypt(<any>_alg, key.key);
        let msg = new Buffer(0);
        msg = Buffer.concat([msg, enc.update(data)]);
        msg = Buffer.concat([msg, enc.final()]);
        return msg;
    }

    static decrypt(session: graphene.Session, alg: iwc.IAlgorithmIdentifier, key: CryptoKey, data: Buffer): Buffer {
        this.checkAlgorithmIdentifier(alg);
        this.checkPrivateKey(key);
        let _alg = this.wc2pk11(key.algorithm);

        // TODO: Remove <any>
        let dec = session.createDecrypt(<any>_alg, key.key);
        let msg = new Buffer(0);
        msg = Buffer.concat([msg, dec.update(data)]);
        msg = Buffer.concat([msg, dec.final()]);
        return msg;
    }

    static wrapKey(session: graphene.Session, key: CryptoKey, wrappingKey: CryptoKey, alg: iwc.IAlgorithmIdentifier): Buffer {
        this.checkAlgorithmIdentifier(alg);
        this.checkAlgorithmHashedParams(alg);
        this.checkSecretKey(key);
        this.checkPublicKey(wrappingKey);
        let _alg = this.wc2pk11(alg);

        let wrappedKey: Buffer = session.wrapKey(wrappingKey.key, _alg, key.key);
        return wrappedKey;
    }

    static unwrapKey(session: graphene.Session, wrappedKey: Buffer, unwrappingKey: CryptoKey, unwrapAlgorithm: iwc.IAlgorithmIdentifier, unwrappedAlgorithm: aes.IAesKeyGenParams, extractable: boolean, keyUsages: string[]): iwc.ICryptoKey {
        this.checkAlgorithmIdentifier(unwrapAlgorithm);
        this.checkAlgorithmHashedParams(unwrapAlgorithm);
        this.checkPrivateKey(unwrappingKey);
        let _alg = this.wc2pk11(alg);

        // convert unwrappedAlgorithm to PKCS11 Algorithm
        let AlgClass = null;
        switch (unwrappedAlgorithm.name) {
            // case aes.ALG_NAME_AES_CTR:
            // case aes.ALG_NAME_AES_CMAC:
            // case aes.ALG_NAME_AES_CFB:
            // case aes.ALG_NAME_AES_KW:
            case aes.ALG_NAME_AES_CBC:
                aes.Aes.checkKeyGenParams(<any>unwrappedAlgorithm);
                AlgClass = aes.AesCBC;
                break;
            case aes.ALG_NAME_AES_GCM:
                aes.Aes.checkKeyGenParams(<any>unwrappedAlgorithm);
                AlgClass = aes.AesGCM;
                break;
            default:
                throw new Error("Unsupported algorithm in use");
        }


        let unwrappedKey: graphene.Key = session.unwrapKey(
            unwrappingKey.key,
            _alg,
            {
                "class": Enums.ObjectClass.SecretKey,
                "sensitive": true,
                "private": true,
                "token": false,
                "keyType": Enums.KeyType.AES,
                "valueLen": unwrappedAlgorithm.length / 8,
                "encrypt": keyUsages.indexOf["encrypt"] > -1,
                "decrypt": keyUsages.indexOf["decrypt"] > -1,
                "sign": keyUsages.indexOf["sign"] > -1,
                "verify": keyUsages.indexOf["verify"] > -1,
                "wrap": keyUsages.indexOf["wrapKey"] > -1,
                "unwrap": keyUsages.indexOf["unwrapKey"] > -1,
                "derive": keyUsages.indexOf["deriveKey"] > -1
            },
            wrappedKey
        );
        return new AlgClass(unwrappedKey, unwrappedAlgorithm);
    }
}