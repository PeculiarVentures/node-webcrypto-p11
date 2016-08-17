import {Session, IAlgorithm, AesGcmParams, SecretKey, KeyGenMechanism, MechanismEnum, Key, ITemplate, ObjectClass, KeyType} from "graphene-pk11";
import * as error from "../error";
import {Base64Url} from "../utils";

import * as utils from "../utils";
import {IAlgorithmHashed, AlgorithmBase, IJwk, IJwkSecret, RSA_HASH_ALGS} from "./alg";
import {P11CryptoKey, KU_DECRYPT, KU_ENCRYPT, KU_SIGN, KU_VERIFY, KU_WRAP, KU_UNWRAP} from "../key";

export var ALG_NAME_AES_CTR = "AES-CTR";
export var ALG_NAME_AES_CBC = "AES-CBC";
export var ALG_NAME_AES_CMAC = "AES-CMAC";
export var ALG_NAME_AES_GCM = "AES-GCM";
export var ALG_NAME_AES_CFB = "AES-CFB";
export var ALG_NAME_AES_KW = "AES-KW";

class AesError extends error.WebCryptoError { }

export function create_template(session: Session, alg: IAesKeyGenAlgorithm, extractable: boolean, keyUsages: string[]): ITemplate {

    let id = utils.GUID(session);
    return {
        token: !!process.env["WEBCRYPTO_PKCS11_TOKEN"],
        sensitive: !!process.env["WEBCRYPTO_PKCS11_SENSITIVE"],
        class: ObjectClass.SECRET_KEY,
        keyType: KeyType.AES,
        label: `AES-${alg.length}`,
        id: new Buffer(id),
        extractable: extractable,
        derive: false,
        sign: keyUsages.indexOf(KU_SIGN) !== -1,
        verify: keyUsages.indexOf(KU_VERIFY) !== -1,
        encrypt: keyUsages.indexOf(KU_ENCRYPT) !== -1,
        decrypt: keyUsages.indexOf(KU_DECRYPT) !== -1,
        wrap: keyUsages.indexOf(KU_WRAP) !== -1,
        unwrap: keyUsages.indexOf(KU_UNWRAP) !== -1,
    };
}

abstract class Aes extends AlgorithmBase {

    static generateKey(session: Session, alg: Algorithm, extractable: boolean, keyUsages: string[], callback: (err: Error, key: CryptoKey | CryptoKeyPair) => void): void {
        try {
            let _alg: IAesKeyGenAlgorithm = <any>alg;
            this.checkAlgorithmIdentifier(alg);
            this.checkKeyGenAlgorithm(_alg);

            // PKCS11 generation
            let template: ITemplate = create_template(session, _alg, extractable, keyUsages);
            template.valueLen = (<IAesKeyGenAlgorithm>alg).length / 8;
            session.generateKey(KeyGenMechanism.AES, template, (err, key) => {
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

    static exportKey(session: Session, format: string, key: CryptoKey, callback: (err: Error, data: Buffer | IJwk) => void): void {
        try {
            let vals = (<P11CryptoKey>key).key.getAttribute({ value: null, valueLen: null });
            switch (format.toLowerCase()) {
                case "jwk":
                    let aes: string = /AES-(\w+)/.exec((<IAesKeyGenAlgorithm>key.algorithm).name)[1];
                    let jwk: IJwkSecret = {
                        kty: "oct",
                        k: Base64Url.encode(vals.value),
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
                value = Base64Url.decode((<IJwkSecret>keyData).k);
            else
                value = <Buffer>keyData;

            // prepare key algorithm
            let _alg: IAesKeyGenAlgorithm = {
                name: algorithm.name,
                length: value.length * 8
            };
            let template: ITemplate = create_template(session, _alg, extractable, keyUsages);
            template.value = value;

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

    static wc2pk11(alg: Algorithm, key: CryptoKey): IAlgorithm {
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
        let aad = alg.additionalData ? new Buffer(new Uint8Array(alg.additionalData)) : null;
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

    static wc2pk11(alg: IAesGcmAlgorithmParams, key: CryptoKey): IAlgorithm {
        return { name: "AES_CBC_PAD", params: alg.iv };
    }

    static checkAlgorithmParams(alg: IAesCbcAlgorithmParams) {
        this.checkAlgorithmIdentifier(alg);
        if (!alg.iv)
            throw new error.AlgorithmError(`iv: Missing required property`);
    }
}