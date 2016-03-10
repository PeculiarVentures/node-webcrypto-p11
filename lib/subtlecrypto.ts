/// <reference path="./promise.d.ts" />

import * as graphene from "graphene-pk11";
import {P11CryptoKey} from "./key";

import * as error from "./error";

import * as alg from "./algs/alg";
import * as aes from "./algs/aes";
import * as rsa from "./algs/rsa";
import * as ec from "./algs/ec";

/**
 * converts alg to Algorithm
 */
function prepare_algorithm(alg: string | Algorithm): Algorithm {
    let _alg: Algorithm = (alg instanceof String) ? { name: alg } : alg;
    if (typeof _alg !== "object")
        throw new error.AlgorithmError(`Algorithm must be an Object`);
    if (!(_alg.name && typeof (_alg.name) === "string"))
        throw new error.AlgorithmError(`Missing required property name`);
    return _alg;
}

/**
 * Converts ArrayBuffer to Buffer
 * @param ab ArrayBuffer value wich must be converted to Buffer
 */
function ab2b(data: ArrayBufferView) {
    return new Buffer(new Uint8Array(data.buffer));
}

function b2ab(data: Buffer): ArrayBufferView {
    let ab = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++)
        ab[i] = data[i];
    return ab;
}

export class P11SubtleCrypto implements SubtleCrypto {
    protected session: graphene.Session;

    constructor(session: graphene.Session) {
        this.session = session;
    }

    generateKey(algorithm: string | Algorithm, extractable: boolean, keyUsages: string[]): any {
        let that = this;
        return new Promise(function(resolve, reject) {
            let _alg = prepare_algorithm(algorithm);

            let AlgClass: alg.IAlgorithmBase = null;
            switch (_alg.name.toLowerCase()) {
                case rsa.RsaPKCS1.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaPKCS1;
                    break;
                case rsa.RsaPSS.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaPSS;
                    break;
                case rsa.RsaOAEP.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaOAEP;
                    break;
                case aes.AesGCM.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesGCM;
                    break;
                case aes.AesCBC.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesCBC;
                    break;
                case ec.Ecdsa.ALGORITHM_NAME.toLowerCase():
                    AlgClass = ec.Ecdsa;
                    break;
                case ec.Ecdh.ALGORITHM_NAME.toLowerCase():
                    AlgClass = ec.Ecdh;
                    break;
                default:
                    throw new error.AlgorithmError(error.ERROR_WRONG_ALGORITHM, _alg.name);
            }
            AlgClass.generateKey(that.session, _alg, extractable, keyUsages, (err: Error, key: CryptoKey | CryptoKeyPair) => {
                if (err)
                    reject(err);
                else
                    resolve(key);
            });
        });
    }

    sign(algorithm: string | Algorithm, key: CryptoKey, data: ArrayBufferView): any {
        let that = this;

        return new Promise(function(resolve, reject) {

            let _data: Buffer = ab2b(data);
            let _alg = prepare_algorithm(algorithm);

            let AlgClass: alg.IAlgorithmBase = null;
            switch (_alg.name.toLowerCase()) {
                case rsa.RsaPKCS1.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaPKCS1;
                    break;
                case rsa.RsaPSS.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaPSS;
                    break;
                case ec.Ecdsa.ALGORITHM_NAME.toLowerCase():
                    AlgClass = ec.Ecdsa;
                    break;
                default:
                    throw new error.AlgorithmError(error.ERROR_WRONG_ALGORITHM, _alg.name);
            }
            AlgClass.sign(that.session, _alg, key, _data, (err, signature) => {
                if (err)
                    reject(err);
                else
                    resolve(b2ab(signature));
            });

        });
    }

    verify(algorithm: string | Algorithm, key: CryptoKey, signature: ArrayBufferView, data: ArrayBufferView): any {
        let that = this;

        return new Promise(function(resolve, reject) {
            let _signature = ab2b(signature);
            let _data = ab2b(data);
            let _alg = prepare_algorithm(algorithm);

            let AlgClass: alg.IAlgorithmBase = null;
            switch (_alg.name.toLowerCase()) {
                case rsa.RsaPKCS1.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaPKCS1;
                    break;
                case rsa.RsaPSS.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaPSS;
                    break;
                case ec.Ecdsa.ALGORITHM_NAME.toLowerCase():
                    AlgClass = ec.Ecdsa;
                    break;
                default:
                    throw new error.AlgorithmError(error.ERROR_WRONG_ALGORITHM, _alg.name);
            }
            AlgClass.verify(that.session, _alg, key, _signature, _data, (err, verify) => {
                if (err)
                    reject(err);
                else
                    resolve(verify);
            });
        });
    }

    encrypt(algorithm: string | Algorithm, key: CryptoKey, data: ArrayBufferView): any {
        let that = this;

        return new Promise(function(resolve, reject) {
            let _data = ab2b(data);
            let _alg = prepare_algorithm(algorithm);

            let AlgClass: alg.IAlgorithmBase = null;
            switch (_alg.name.toLowerCase()) {
                case rsa.RsaOAEP.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaOAEP;
                    break;
                case aes.AesGCM.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesGCM;
                    break;
                case aes.AesCBC.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesCBC;
                    break;
                default:
                    throw new error.AlgorithmError(error.ERROR_WRONG_ALGORITHM, _alg.name);
            }
            AlgClass.encrypt(that.session, _alg, key, _data, (err, enc) => {
                if (err)
                    reject(err);
                else
                    resolve(b2ab(enc));
            });
        });
    }

    decrypt(algorithm: string | Algorithm, key: CryptoKey, data: ArrayBufferView): any {
        let that = this;

        return new Promise(function(resolve, reject) {
            let _data = ab2b(data);
            let _alg = prepare_algorithm(algorithm);

            let AlgClass: alg.IAlgorithmBase = null;
            switch (_alg.name.toLowerCase()) {
                case rsa.RsaOAEP.ALGORITHM_NAME.toLowerCase():
                    AlgClass = rsa.RsaOAEP;
                    break;
                case aes.AesGCM.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesGCM;
                    break;
                case aes.AesCBC.ALGORITHM_NAME.toLowerCase():
                    AlgClass = aes.AesCBC;
                    break;
                default:
                    throw new error.AlgorithmError(error.ERROR_WRONG_ALGORITHM, _alg.name);
            }
            AlgClass.decrypt(that.session, _alg, key, _data, (err, enc) => {
                if (err)
                    reject(err);
                else
                    resolve(b2ab(enc));
            });
        });
    }

    wrapKey(format: string, key: CryptoKey, wrappingKey: CryptoKey, wrapAlgorithm: string | Algorithm): any {
        let that = this;

        return new Promise(function(resolve, reject) {
            let _alg = prepare_algorithm(wrapAlgorithm);
            let KeyClass: alg.IAlgorithmBase;
            switch (_alg.name) {
                case aes.ALG_NAME_AES_CBC:
                    KeyClass = aes.AesCBC;
                    break;
                case aes.ALG_NAME_AES_GCM:
                    KeyClass = aes.AesGCM;
                    break;
                default:
                    throw new error.AlgorithmError(error.ERROR_WRONG_ALGORITHM, _alg.name);
            }

            KeyClass.wrapKey(that.session, format, key, wrappingKey, _alg, (err: Error, wkey: Buffer) => {
                if (err)
                    reject(err);
                else
                    resolve(b2ab(wkey));
            });
        });
    }

    unwrapKey(format: string, wrappedKey: ArrayBufferView, unwrappingKey: CryptoKey, unwrapAlgorithm: string | Algorithm, unwrappedKeyAlgorithm: string | Algorithm, extractable: boolean, keyUsages: string[]): any {
        let that = this;

        return new Promise(function(resolve, reject) {
            let KeyClass: alg.IAlgorithmBase;
            switch (unwrappingKey.algorithm.name) {
                case aes.ALG_NAME_AES_CBC:
                    KeyClass = aes.AesCBC;
                    break;
                case aes.ALG_NAME_AES_GCM:
                    KeyClass = aes.AesGCM;
                    break;
                default:
                    throw new error.AlgorithmError(error.ERROR_WRONG_ALGORITHM, unwrappingKey.algorithm.name);
            }
            let wrappedKeyBuffer = ab2b(wrappedKey);
            KeyClass.unwrapKey(that.session, format, wrappedKeyBuffer, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages, (err: Error, uwkey: CryptoKey) => {
                if (err)
                    reject(err);
                else
                    resolve(uwkey);
            });
        });
    }

    deriveKey(algorithm: string | Algorithm, baseKey: CryptoKey, derivedKeyType: string | Algorithm, extractable: boolean, keyUsages: string[]): any {
        let that = this;

        return new Promise(function(resolve, reject) {
            let _alg1 = prepare_algorithm(algorithm);
            let _alg2 = prepare_algorithm(derivedKeyType);

            let AlgClass: alg.IAlgorithmBase = null;
            switch (_alg1.name.toLowerCase()) {
                case ec.Ecdh.ALGORITHM_NAME.toLowerCase():
                    AlgClass = ec.Ecdh;
                    break;
                default:
                    throw new error.AlgorithmError(error.ERROR_WRONG_ALGORITHM, _alg1.name);
            }
            AlgClass.deriveKey(that.session, algorithm, baseKey, derivedKeyType, extractable, keyUsages, (err, key) => {
                if (err)
                    reject(err);
                else
                    resolve(key);
            });
        });
    }

    exportKey(format: string, key: CryptoKey): any {
        let that = this;

        return new Promise(function(resolve, reject) {
            let KeyClass: alg.IAlgorithmBase;
            switch (key.algorithm.name) {
                case aes.ALG_NAME_AES_CBC:
                    KeyClass = aes.AesCBC;
                    break;
                case aes.ALG_NAME_AES_GCM:
                    KeyClass = aes.AesGCM;
                    break;
                case rsa.ALG_NAME_RSA_PKCS1:
                    KeyClass = rsa.RsaPKCS1;
                    break;
                case rsa.ALG_NAME_RSA_OAEP:
                    KeyClass = rsa.RsaOAEP;
                    break;
                default:
                    throw new error.AlgorithmError(error.ERROR_WRONG_ALGORITHM, key.algorithm.name);
            }
            KeyClass.exportKey(that.session, format, key, (err: Error, data: any) => {
                if (err)
                    reject(err)
                else {
                    if (Buffer.isBuffer(data)) {
                        // raw | spki | pkcs8
                        let ubuf = new Uint8Array(data);
                        resolve(ubuf);
                    }
                    else
                        // jwk
                        resolve(data);
                }
            });
        });
    }

    importKey(format: string, keyData: any, algorithm: string | Algorithm, extractable: boolean, keyUsages: string[]): any {
        let that = this;

        return new Promise(function(resolve, reject) {
            let _alg = prepare_algorithm(algorithm);
            let KeyClass: alg.IAlgorithmBase;
            switch (_alg.name) {
                case aes.ALG_NAME_AES_CBC:
                    KeyClass = aes.AesCBC;
                    break;
                case aes.ALG_NAME_AES_GCM:
                    KeyClass = aes.AesGCM;
                    break;
                default:
                    throw new error.AlgorithmError(error.ERROR_WRONG_ALGORITHM, _alg.name);
            }

            let data: any;
            if (ArrayBuffer.isView(keyData)) {
                // raw | pkcs8 | spki
                data = ab2b(keyData);
            }
            else
                // jwk
                data = keyData;

            KeyClass.importKey(that.session, format, data, _alg, extractable, keyUsages, (err: Error, key: CryptoKey) => {
                if (err)
                    reject(err);
                else
                    resolve(key);
            });
        });
    }

    deriveBits(algorithm: string | Algorithm, baseKey: CryptoKey, length: number): any {
        let that = this;
        return new Promise(function(resolve, reject) {
            reject(new Error("Method is not implemented"));
        });
    }

    digest(algorithm: string | Algorithm, data: ArrayBufferView): any {
        let that = this;
        return new Promise(function(resolve, reject) {
            reject(new Error("Method is not implemented"));
        });
    }

}