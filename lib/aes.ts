import * as graphene from "graphene-pk11"
var AES = graphene.AES;
var Enums = graphene.Enums;

import * as alg from "./alg"
import * as iwc from "./iwebcrypto"
import {CryptoKey} from "./key"

export var ALG_NAME_AES_CTR = "AES-CTR";
export var ALG_NAME_AES_CBC = "AES-CBC";
export var ALG_NAME_AES_CMAC = "AES-CMAC";
export var ALG_NAME_AES_GCM = "AES-GCM";
export var ALG_NAME_AES_CFB = "AES-CFB";
export var ALG_NAME_AES_KW = "AES-KW";

let HASH_ALGS = ["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"];

export class Aes extends alg.AlgorithmBase {
    static generateKey(session: graphene.Session, alg: IAesKeyGenParams, extractable: boolean, keyUsages: string[], label?: string): iwc.ICryptoKey {
        this.checkAlgorithmIdentifier(alg);
        this.checkKeyGenParams(alg);

        let _key = AES.Aes.generate(session, null, {
            "label": label,
            "length": alg.length,
            "token": true,
            "extractable": extractable,
            "keyUsages": keyUsages,
        });

        return new AesKey(_key.key, alg);
    }

    static checkKeyGenParams(alg: IAesKeyGenParams) {
        if (!alg.length)
            throw new TypeError("AesKeyGenParams: length: Missing required property");
        switch (alg.length) {
            case 128:
            case 192:
            case 256:
                break;
            default:
                throw new TypeError("AesKeyGenParams: length: Wrong value. Can be 128, 192, or 256");
        }
    }

    static checkAlgorithmHashedParams(alg: iwc.IAlgorithmIdentifier) {
        super.checkAlgorithmHashedParams(alg);
        let _alg = alg.hash;
        _alg.name = _alg.name.toUpperCase();
        if (HASH_ALGS.indexOf(_alg.name) === -1)
            throw new Error("AlgorithmHashedParams: Unknow hash algorithm in use");
    }

    static checkAlgorithmParams(alg: IAesAlgorithmParams) {
        this.checkAlgorithmIdentifier(alg);
        if (!alg.iv)
            throw new TypeError("AlgorithmParams: iv: Missing required property");
        if (!alg.tagLength)
            alg.tagLength = 128;
    }

    static wc2pk11(alg: IAesAlgorithmParams) {
        throw new Error("Not realized");
    }
}

export interface IAesKeyGenParams extends iwc.IAlgorithmIdentifier {
    length: number;
}

export interface IAesAlgorithmParams extends iwc.IAlgorithmIdentifier {
    iv: Buffer;
    additionalData?: Buffer;
    tagLength?: number;
}

export class AesKey extends CryptoKey {
    length: number;

    constructor(key, alg: IAesKeyGenParams) {
        super(key, alg);
        this.length = alg.length;
        // TODO: get params from key if alg params is empty
    }
}

export class AesGCM extends Aes {
    static ALGORITHM_NAME: string = ALG_NAME_AES_GCM;

    static wc2pk11(alg: IAesAlgorithmParams) {
        let params = new graphene.AES.AesGCMParams(alg.iv, alg.additionalData, alg.tagLength);
        return { name: "AES_GCM", params: params };
    }

    static encrypt(session: graphene.Session, alg: IAesAlgorithmParams, key: CryptoKey, data: Buffer): Buffer {
        this.checkAlgorithmParams(alg);
        this.checkSecretKey(key);
        let _alg = this.wc2pk11(alg);

        // TODO: Remove <any>
        let enc = session.createEncrypt(<any>_alg, key.key);
        let msg = new Buffer(0);
        msg = Buffer.concat([msg, enc.update(data)]);
        msg = Buffer.concat([msg, enc.final()]);
        return msg;
    }

    static decrypt(session: graphene.Session, alg: IAesAlgorithmParams, key: CryptoKey, data: Buffer): Buffer {
        this.checkAlgorithmParams(alg);
        this.checkSecretKey(key);
        let _alg = this.wc2pk11(alg);

        // TODO: Remove <any>
        let dec = session.createDecrypt(<any>_alg, key.key);
        let msg = new Buffer(0);
        msg = Buffer.concat([msg, dec.update(data)]);
        msg = Buffer.concat([msg, dec.final()]);
        return msg;
    }

    static wrapKey(session: graphene.Session, key: CryptoKey, wrappingKey: CryptoKey, alg: IAesAlgorithmParams): Buffer {
        this.checkAlgorithmIdentifier(alg);
        this.checkAlgorithmHashedParams(alg);
        this.checkSecretKey(key);
        this.checkPublicKey(wrappingKey);
        let _alg = this.wc2pk11(alg);

        let wrappedKey: Buffer = session.wrapKey(wrappingKey.key, <any>_alg, key.key);
        return wrappedKey;
    }

    static unwrapKey(session: graphene.Session, wrappedKey: Buffer, unwrappingKey: CryptoKey, unwrapAlgorithm: IAesAlgorithmParams, unwrappedAlgorithm: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[]): iwc.ICryptoKey {
        this.checkAlgorithmIdentifier(unwrapAlgorithm);
        this.checkAlgorithmHashedParams(unwrapAlgorithm);
        this.checkPrivateKey(unwrappingKey);
        let _alg = this.wc2pk11(unwrapAlgorithm);

        // TODO: convert unwrappedAlgorithm to PKCS11 Algorithm 

        let unwrappedKey: graphene.Key = session.unwrapKey(unwrappingKey.key, <any>_alg, { name: "" }, wrappedKey);
        // TODO: WrapKey with known AlgKey 
        return new CryptoKey(unwrappedKey, { name: "" });
    }
}

export class AesCBC extends AesGCM {
    static ALGORITHM_NAME: string = ALG_NAME_AES_CBC;

    static wc2pk11(alg: IAesAlgorithmParams) {
        let params = new graphene.AES.AesGCMParams(alg.iv, alg.additionalData, alg.tagLength);
        return { name: "AES_CBC_PAD", params: params };
    }
}