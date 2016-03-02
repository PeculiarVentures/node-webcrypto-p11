import {Session, IAlgorithm, AesGcmParams, SecretKey, KeyGenMechanism, MechanismEnum, Key, ITemplate, ObjectClass, KeyType} from "graphene-pk11";
import * as error from "../error";
import * as base64url from "base64url";

import {IAlgorithmHashed, AlgorithmBase, IJwk, IJwkSecret, RSA_HASH_ALGS} from "./alg";
import {P11CryptoKey, KU_DECRYPT, KU_ENCRYPT, KU_SIGN, KU_VERIFY, KU_WRAP, KU_UNWRAP} from "../key";

export var ALG_NAME_AES_CTR = "AES-CTR";
export var ALG_NAME_AES_CBC = "AES-CBC";
export var ALG_NAME_AES_CMAC = "AES-CMAC";
export var ALG_NAME_AES_GCM = "AES-GCM";
export var ALG_NAME_AES_CFB = "AES-CFB";
export var ALG_NAME_AES_KW = "AES-KW";

class AesError extends error.WebCryptoError { }

function create_template(alg: IAesKeyGenAlgorithm, keyUsages: string[]) {
    return {
        token: false,
        class: ObjectClass.SECRET_KEY,
        keyType: KeyType.AES,
        label: `AES-${alg.length}`,
        id: new Buffer(new Date().getTime().toString()),
        extractable: true,
        derive: false,
        sign: keyUsages.indexOf(KU_SIGN) !== -1,
        verify: keyUsages.indexOf(KU_VERIFY) !== -1,
        encrypt: keyUsages.indexOf(KU_ENCRYPT) !== -1,
        decrypt: keyUsages.indexOf(KU_DECRYPT) !== -1,
        wrap: keyUsages.indexOf(KU_WRAP) !== -1,
        unwrap: keyUsages.indexOf(KU_UNWRAP) !== -1,
        valueLen: alg.length / 8
    };
}

abstract class Aes extends AlgorithmBase {

    static generateKey(session: Session, alg: Algorithm, extractable: boolean, keyUsages: string[], callback: (err: Error, key: CryptoKey | CryptoKeyPair) => void): void {
        try {
            let _alg: IAesKeyGenAlgorithm = <any>alg;
            this.checkAlgorithmIdentifier(alg);
            this.checkKeyGenAlgorithm(_alg);

            // PKCS11 generation
            session.generateKey(KeyGenMechanism.AES, create_template(_alg, keyUsages), (err, key) => {
                try {
                    if (err)
                        callback(err, null);
                    else {
                        let wcKey = new P11CryptoKey(key, _alg);
                        callback(null, wcKey);
                    }
                }
                catch (e) {
                    callback(e, null);
                }
            });
        }
        catch (e) {
            callback(e, null);
        }
    }

    static onCheck(method: string, paramName: string, paramValue: any): void {
        switch (method) {
            case "encrypt":
                switch (paramName) {
                    case "alg":
                        this.checkAlgorithmParams(paramValue);
                        break;
                    case "key":
                        this.checkSecretKey(paramValue);
                        break;
                    case "data":
                        break;
                }
                break;
            case "decrypt":
                switch (paramName) {
                    case "alg":
                        this.checkAlgorithmParams(paramValue);
                        break;
                    case "key":
                        this.checkSecretKey(paramValue);
                        break;
                    case "data":
                        break;
                }
                break;
        }
    }

    static wrapKey(session: Session, format: string, key: CryptoKey, wrappingKey: CryptoKey, alg: Algorithm, callback: (err: Error, wkey: Buffer) => void): void {
        let that = this;
        try {
            this.exportKey(session, format, key, (err: Error, data: any) => {
                if (err) {
                    callback(err, null);
                }
                else {
                    if (!Buffer.isBuffer(data)) {
                        // JWK to Buffer
                        data = new Buffer(JSON.stringify(data));
                    }
                }
                that.encrypt(session, alg, wrappingKey, data, callback);
            });
        }
        catch (e) {
            callback(e, null);
        }
    }

    static unwrapKey(session: Session, format: string, wrappedKey: Buffer, unwrappingKey: CryptoKey, unwrapAlgorithm: Algorithm, unwrappedAlgorithm: Algorithm, extractable: boolean, keyUsages: string[], callback: (err: Error, key: CryptoKey) => void): void {
        let that = this;
        try {
            this.decrypt(session, unwrapAlgorithm, unwrappingKey, wrappedKey, (err: Error, dec: Buffer) => {
                if (err) {
                    callback(err, null);
                }
                else {
                    try {
                        let ikey: IJwk | Buffer = <Buffer>dec;
                        if (format === "jwk") {
                            ikey = JSON.parse(dec.toString());
                        }
                        that.importKey(session, format, ikey, unwrappedAlgorithm, extractable, keyUsages, callback);
                    }
                    catch (e) {
                        callback(e, null);
                    }
                }
            });
        }
        catch (e) {
            callback(e, null);
        }
    }

    static exportKey(session: Session, format: string, key: CryptoKey, callback: (err: Error, data: Buffer | IJwk) => void): void {
        try {
            let vals = (<P11CryptoKey>key).key.getAttribute({ value: null, valueLen: null });
            switch (format.toLowerCase()) {
                case "jwk":
                    let aes: string = /AES-(\w+)/.exec((<IAesKeyGenAlgorithm>key.algorithm).name)[1];
                    let jwk: IJwkSecret = {
                        kty: "oct",
                        k: base64url.encode(vals.value),
                        alg: `A${vals.valueLen * 8}${aes}`,
                        ext: true
                    };
                    callback(null, jwk);
                    break;
                case "raw":
                    callback(null, vals.value);
            }
        }
        catch (e) {
            callback(e, null);
        }
    }
    static importKey(session: Session, format: string, keyData: IJwk | Buffer, algorithm: Algorithm, extractable: boolean, keyUsages: string[], callback: (err: Error, key: CryptoKey) => void): void {
        try {
            // get key value
            let value: Buffer;
            if (format === "jwk")
                value = base64url.toBuffer((<IJwkSecret>keyData).k);
            else
                value = <Buffer>keyData;

            // prepare key algorithm
            let _alg: IAesKeyGenAlgorithm = {
                name: algorithm.name,
                length: value.length * 8
            };
            let template: ITemplate = create_template(_alg, keyUsages);
            template.value = value;
            delete template.valueLen;

            // create session object
            let sobj = session.create(template);
            // return value as CryptoKey
            callback(null, new P11CryptoKey(sobj.toType<SecretKey>(), _alg));
        }
        catch (e) {
            callback(e, null);
        }
    }
    static checkAlgorithmParams(alg: Algorithm) { }

    static checkKeyGenAlgorithm(alg: IAesKeyGenAlgorithm) {
        this.checkAlgorithmIdentifier(alg);
        if (!alg.length)
            throw new AesError(`length: Missing required property`);
        switch (alg.length) {
            case 128:
            case 192:
            case 256:
                break;
            default:
                throw new AesError(`length: Wrong value. Can be 128, 192, or 256`);
        }
    }

    static checkAlgorithmHashedParams(alg: IAlgorithmHashed) {
        super.checkAlgorithmHashedParams(alg);
        let _alg = alg.hash;
        _alg.name = _alg.name.toUpperCase();
        if (RSA_HASH_ALGS.indexOf(_alg.name) === -1)
            throw new error.AlgorithmError(error.ERROR_WRONG_ALGORITHM, _alg.name);
    }

    static wc2pk11(alg: Algorithm): IAlgorithm {
        throw new Error("Not realized");
    }
}

export interface IAesKeyGenAlgorithm extends Algorithm {
    length: number;
}

export interface IAesCbcAlgorithmParams extends Algorithm {
    iv: Buffer;
}

export interface IAesGcmAlgorithmParams extends IAesCbcAlgorithmParams {
    additionalData?: ArrayBuffer;
    tagLength?: number;
}

export class AesGCM extends Aes {
    static ALGORITHM_NAME: string = ALG_NAME_AES_GCM;

    static wc2pk11(alg: IAesGcmAlgorithmParams): IAlgorithm {
        let aad = new Buffer(new Uint8Array(alg.additionalData));
        let params = new AesGcmParams(alg.iv, aad, alg.tagLength);
        return { name: "AES_GCM", params: params };
    }

    static checkAlgorithmParams(alg: IAesGcmAlgorithmParams): void {
        this.checkAlgorithmIdentifier(alg);
        // Recommended to use 12 bytes length
        if (!alg.iv)
            throw new error.AlgorithmError("iv: Missing required property");

        // can be 32, 64, 96, 104, 112, 120 or 128 (default)
        if (!alg.tagLength)
            alg.tagLength = 128;
        switch (alg.tagLength) {
            case 32:
            case 64:
            case 96:
            case 104:
            case 112:
            case 120:
            case 128:
                break;
            default:
                throw new error.AlgorithmError(`tagLength: Wrong value, can be 32, 64, 96, 104, 112, 120 or 128 (default)`);
        }
    }
}

export class AesCBC extends Aes {
    static ALGORITHM_NAME: string = ALG_NAME_AES_CBC;

    static wc2pk11(alg: IAesGcmAlgorithmParams): IAlgorithm {
        return { name: "AES_CBC_PAD", params: alg.iv };
    }

    static checkAlgorithmParams(alg: IAesCbcAlgorithmParams) {
        this.checkAlgorithmIdentifier(alg);
        if (!alg.iv)
            throw new error.AlgorithmError(`iv: Missing required property`);
    }
}