import {
    Session,
    IAlgorithm,
    AesGcmParams,
    SecretKey,
    KeyGenMechanism,
    MechanismEnum,
    Key,
    ITemplate,
    ObjectClass,
    KeyType,
    EcdhParams,
    NamedCurve,
    EcKdf} from "graphene-pk11";
import * as error from "../error";
import * as aes from "./aes";
import * as base64url from "base64url";

import {IAlgorithmHashed, AlgorithmBase, IJwk, IJwkSecret, RSA_HASH_ALGS} from "./alg";
import {P11CryptoKey, KU_DECRYPT, KU_ENCRYPT, KU_SIGN, KU_VERIFY, KU_WRAP, KU_UNWRAP, KU_DERIVE, ITemplatePair} from "../key";

let ALG_NAME_ECDH = "ECDH";
let ALG_NAME_ECDSA = "ECDSA";

function create_template(alg: IEcKeyGenAlgorithm, extractable: boolean, keyUsages: string[]): ITemplatePair {
    const label = `EC-${alg.namedCurve}`;
    const id = new Buffer(new Date().getTime().toString());
    const keyType = KeyType.ECDSA;
    return {
        privateKey: {
            token: false,
            class: ObjectClass.PRIVATE_KEY,
            keyType: keyType,
            private: true,
            label: label,
            id: id,
            extractable: extractable,
            derive: keyUsages.indexOf(KU_DERIVE) !== -1,
            sign: keyUsages.indexOf(KU_SIGN) !== -1,
            decrypt: keyUsages.indexOf(KU_DECRYPT) !== -1,
            unwrap: keyUsages.indexOf(KU_UNWRAP) !== -1
        },
        publicKey: {
            token: false,
            class: ObjectClass.PUBLIC_KEY,
            keyType: keyType,
            label: label,
            id: id,
            derive: keyUsages.indexOf(KU_DERIVE) !== -1,
            verify: keyUsages.indexOf(KU_VERIFY) !== -1,
            encrypt: keyUsages.indexOf(KU_ENCRYPT) !== -1,
            wrap: keyUsages.indexOf(KU_WRAP) !== -1,
        }
    };
}

export interface IEcKeyGenAlgorithm extends Algorithm {
    namedCurve: string;
}

export interface IEcAlgorithmParams extends Algorithm {
    namedCurve: string;
    public?: CryptoKey;
}

export interface IEcdsaAlgorithmParams extends IEcAlgorithmParams {
    hash: {
        name: string;
    };
}

export class Ec extends AlgorithmBase {

    static generateKey(session: Session, alg: Algorithm, extractable: boolean, keyUsages: string[], callback: (err: Error, key: CryptoKey | CryptoKeyPair) => void): void {
        try {
            let _alg: IEcKeyGenAlgorithm = <any>alg;
            this.checkAlgorithmIdentifier(alg);
            this.checkAlgorithmHashedParams(<IAlgorithmHashed>alg);
            this.checkKeyGenAlgorithm(_alg);

            let template = create_template(_alg, extractable, keyUsages);

            // EC params
            let _namedCurve = "";
            switch (_alg.namedCurve) {
                case "P-192":
                    _namedCurve = "secp192r1";
                    break;
                case "P-256":
                    _namedCurve = "secp256r1";
                    break;
                case "P-384":
                    _namedCurve = "secp384r1";
                    break;
                case "P-521":
                    _namedCurve = "secp521r1";
                    break;
                default:
                    throw new Error("Unsupported namedCurve in use");
            }
            template.publicKey.paramsEC = NamedCurve.getByName(_namedCurve).value;
            // PKCS11 generation
            session.generateKeyPair(KeyGenMechanism.EC, template.publicKey, template.privateKey, (err, keys) => {
                try {
                    if (err)
                        callback(err, null);
                    else {
                        let wcKeyPair: CryptoKeyPair = {
                            privateKey: new P11CryptoKey(keys.privateKey, _alg),
                            publicKey: new P11CryptoKey(keys.publicKey, _alg)
                        };
                        callback(null, wcKeyPair);
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

    static checkKeyGenAlgorithm(alg: IEcKeyGenAlgorithm) {
        this.checkAlgorithmParams(alg);
    }

    static checkAlgorithmParams(alg: IEcAlgorithmParams) {
        this.checkAlgorithmIdentifier(alg);
        if (!alg.namedCurve)
            throw new TypeError("EcParams: namedCurve: Missing required property");
        switch (alg.namedCurve.toUpperCase()) {
            case "P-192":
            case "P-256":
            case "P-384":
            case "P-521":
                break;
            default:
                throw new TypeError("EcParams: namedCurve: Wrong value. Can be P-256, P-384, or P-521");
        }
        alg.namedCurve = alg.namedCurve.toUpperCase();
    }

    static checkAlgorithmHashedParams(alg: IAlgorithmHashed) {
        super.checkAlgorithmHashedParams(alg);
        let _alg = alg.hash;
        _alg.name = _alg.name.toUpperCase();
        if (RSA_HASH_ALGS.indexOf(_alg.name) === -1)
            throw new error.AlgorithmError(error.ERROR_WRONG_ALGORITHM, _alg.name);
    }

}

export class Ecdsa extends Ec {
    static ALGORITHM_NAME: string = ALG_NAME_ECDSA;

    static wc2pk11(alg: IEcdsaAlgorithmParams, key: CryptoKey): IAlgorithm {
        let _alg: string = null;
        switch (alg.hash.name.toUpperCase()) {
            case "SHA-1":
                _alg = "ECDSA_SHA1";
                break;
            case "SHA-224":
                _alg = "ECDSA_SHA224";
                break;
            case "SHA-256":
                _alg = "ECDSA_SHA256";
                break;
            case "SHA-384":
                _alg = "ECDSA_SHA384";
                break;
            case "SHA-512":
                _alg = "ECDSA_SHA512";
                break;
            default:
                throw new error.AlgorithmError(error.ERROR_WRONG_ALGORITHM, (<IAlgorithmHashed>key.algorithm).hash.name);
        }
        return { name: _alg, params: null };
    }

    static onCheck(method: string, paramName: string, paramValue: any): void {
        switch (method) {
            case "sign":
                switch (paramName) {
                    case "alg":
                        this.checkAlgorithmHashedParams(paramValue);
                        break;
                    case "key":
                        this.checkPrivateKey(paramValue);
                        break;
                    case "data":
                        break;
                }
                break;
            case "verify":
                switch (paramName) {
                    case "alg":
                        break;
                    case "key":
                        this.checkAlgorithmHashedParams(paramValue);
                        this.checkPublicKey(paramValue);
                        break;
                    case "data":
                        break;
                }
                break;
        }
    }

}

export class Ecdh extends Ec {
    static ALGORITHM_NAME: string = ALG_NAME_ECDH;

    static deriveKey(session: Session, algorithm: Algorithm, baseKey: CryptoKey, derivedKeyType: Algorithm, extractable: boolean, keyUsages: string[], callback: (err: Error, key: CryptoKey) => void): void;
    static deriveKey(session: Session, algorithm: IEcdsaAlgorithmParams, baseKey: CryptoKey, derivedKeyType: Algorithm, extractable: boolean, keyUsages: string[], callback: (err: Error, key: CryptoKey) => void): void;
    static deriveKey(session: Session, algorithm: IEcdsaAlgorithmParams, baseKey: CryptoKey, derivedKeyType: Algorithm, extractable: boolean, keyUsages: string[], callback: (err: Error, key: CryptoKey) => void): void {
        try {
            // check algorithm
            this.checkAlgorithmParams(algorithm);
            if (!algorithm.public)
                throw new TypeError("EcParams: public: Missing required property");
            this.checkPublicKey(algorithm.public);

            // check baseKey
            this.checkPrivateKey(baseKey);

            // check derivedKeyType
            if (typeof derivedKeyType !== "object")
                throw TypeError("derivedKeyType: AlgorithmIdentifier: Algorithm must be an Object");
            if (!(derivedKeyType.name && typeof (derivedKeyType.name) === "string"))
                throw TypeError("derivedKeyType: AlgorithmIdentifier: Missing required property name");
            let AesClass: any = null;
            switch (derivedKeyType.name.toLowerCase()) {
                case aes.AesGCM.ALGORITHM_NAME.toLowerCase():
                    AesClass = aes.AesGCM;
                    break;
                case aes.AesCBC.ALGORITHM_NAME.toLowerCase():
                    AesClass = aes.AesCBC;
                    break;
                default:
                    throw new Error("derivedKeyType: Unknown Algorithm name in use");
            }
            AesClass.checkKeyGenAlgorithm(<aes.IAesKeyGenAlgorithm>derivedKeyType);

            let template: ITemplate = aes.create_template(<aes.IAesKeyGenAlgorithm>derivedKeyType, extractable, keyUsages);
            // template.valueLen = (<aes.IAesKeyGenAlgorithm>derivedKeyType).length / 8;
            // derive key
            let dKey: Key = session.deriveKey(
                {
                    name: "ECDH1_DERIVE",
                    params: new EcdhParams(
                        EcKdf.NULL,
                        null,
                        (<P11CryptoKey>algorithm.public).key.getAttribute({ pointEC: null }).pointEC // CKA_EC_POINT
                    )
                },
                (<P11CryptoKey>baseKey).key,
                template
            );

            callback(null, new P11CryptoKey(dKey, derivedKeyType));
        } catch (e) {
            callback(e, null);
        }
    }
}