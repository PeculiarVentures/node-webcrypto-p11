/// <reference path="./promise.ts" />

import * as graphene from "graphene-pk11";
import {CryptoKey} from "./key";

import * as alg from "./alg";
import * as rsa from "./rsa";
import * as aes from "./aes";
import * as ec from "./ec";

import * as iwc from "./iwebcrypto";

function prepare_algorithm(alg: iwc.AlgorithmType): iwc.IAlgorithmIdentifier {
    let _alg: iwc.IAlgorithmIdentifier = { name: "" };
    if (alg instanceof String) {
        _alg = { name: alg };
    }
    else {
        _alg = <iwc.IAlgorithmIdentifier>alg;
    }
    return _alg;
}

export class P11SubtleCrypto implements iwc.ISubtleCrypto {
    protected session: graphene.Session;

    constructor(session: graphene.Session) {
        this.session = session;
    }

    generateKey(algorithm: iwc.AlgorithmType, extractable: boolean, keyUsages: string[]): Promise {
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
                    throw new TypeError("Unsupported algorithm in use");
            }
            let key = AlgClass.generateKey(that.session, _alg, extractable, keyUsages);
            resolve(key);
        });
    }

    sign(algorithm: iwc.AlgorithmType, key: CryptoKey, data: Buffer): Promise {
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
                case ec.Ecdsa.ALGORITHM_NAME.toLowerCase():
                    AlgClass = ec.Ecdsa;
                    break;
                default:
                    throw new TypeError("Unsupported algorithm in use");
            }
            let signature = AlgClass.sign(that.session, _alg, key, data);
            resolve(signature);
        });
    }

    verify(algorithm: iwc.AlgorithmType, key: CryptoKey, signature: Buffer, data: Buffer): Promise {
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
                case ec.Ecdsa.ALGORITHM_NAME.toLowerCase():
                    AlgClass = ec.Ecdsa;
                    break;
                default:
                    throw new TypeError("Unsupported algorithm in use");
            }
            let valid = AlgClass.verify(that.session, _alg, key, signature, data);
            resolve(valid);
        });
    }

    encrypt(algorithm: iwc.AlgorithmType, key: CryptoKey, data: Buffer): Promise {
        let that = this;
        return new Promise(function(resolve, reject) {
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
                    throw new TypeError("Unsupported algorithm in use");
            }
            let msg = AlgClass.encrypt(that.session, _alg, key, data);
            resolve(msg);
        });
    }

    decrypt(algorithm: iwc.AlgorithmType, key: CryptoKey, data: Buffer): Promise {
        let that = this;
        return new Promise(function(resolve, reject) {
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
                    throw new TypeError("Unsupported algorithm in use");
            }
            let msg = AlgClass.decrypt(that.session, _alg, key, data);
            resolve(msg);
        });
    }

    wrapKey(format: string, key: CryptoKey, wrappingKey: CryptoKey, algorithm: iwc.IAlgorithmIdentifier): Promise {
        let that = this;
        return new Promise(function(resolve, reject) {
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
                    throw new TypeError("Unsupported algorithm in use");
            }
            let wrappedKey = AlgClass.wrapKey(that.session, key, wrappingKey, _alg);
            resolve(wrappedKey);
        });
    }

    unwrapKey(format: string, wrappedKey: Buffer, unwrappingKey: CryptoKey, unwrapAlgorithm: iwc.IAlgorithmIdentifier, unwrappedAlgorithm: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[]): Promise {
        let that = this;
        return new Promise(function(resolve, reject) {
            let _alg1 = prepare_algorithm(unwrapAlgorithm);
            let _alg2 = prepare_algorithm(unwrappedAlgorithm);

            let AlgClass: alg.IAlgorithmBase = null;
            switch (_alg1.name.toLowerCase()) {
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
                    throw new TypeError("Unsupported algorithm in use");
            }
            let unwrappedKey = AlgClass.unwrapKey(that.session, wrappedKey, unwrappingKey, _alg1, _alg2, extractable, keyUsages);
            resolve(unwrappedKey);
        });
    }

    deriveKey(algorithm: iwc.IAlgorithmIdentifier, baseKey: CryptoKey, derivedKeyType: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[]): Promise {
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
                    throw new TypeError("Unsupported algorithm in use");
            }
            let key: CryptoKey = AlgClass.deriveKey(that.session, algorithm, baseKey, derivedKeyType, extractable, keyUsages);
            resolve(key);
        });
    }

}