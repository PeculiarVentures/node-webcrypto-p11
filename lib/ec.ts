import * as graphene from "graphene-pk11";
let ECDSA = graphene.ECDSA;
let Enums = graphene.Enums;

import * as Aes from "./aes";

import * as alg from "./alg";
import * as iwc from "./iwebcrypto";
import {CryptoKey} from "./key";

let ALG_NAME_ECDH = "ECDH";
let ALG_NAME_ECDSA = "ECDSA";

let HASH_ALGS = ["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"];

export class Ec extends alg.AlgorithmBase {
    static generateKey(session: graphene.Session, alg: IEcKeyGenParams, extractable: boolean, keyUsages: string[], label?: string): iwc.ICryptoKeyPair {
        this.checkAlgorithmIdentifier(alg);
        this.checkKeyGenParams(alg);

        let _namedCurve = "";
        switch (alg.namedCurve) {
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

        let _key = ECDSA.Ecdsa.generate(session, null, {
            "label": label,
            "namedCurve": _namedCurve,
            "token": true,
            "extractable": extractable,
            "keyUsages": keyUsages,
        });

        return {
            "privateKey": new EcKey(_key.privateKey, alg),
            "publicKey": new EcKey(_key.publicKey, alg)
        };
    }

    static checkKeyGenParams(alg: IEcKeyGenParams) {
        this.checkAlgorithmParams(alg);
    }

    static checkAlgorithmHashedParams(alg: iwc.IAlgorithmIdentifier) {
        super.checkAlgorithmHashedParams(alg);
        let _alg = alg.hash;
        _alg.name = _alg.name.toUpperCase();
        if (HASH_ALGS.indexOf(_alg.name) === -1)
            throw new Error("AlgorithmHashedParams: Unknow hash algorithm in use");
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

    static wc2pk11(alg: IEcAlgorithmParams) {
        throw new Error("Not realized");
    }
}

export interface IEcKeyGenParams extends iwc.IAlgorithmIdentifier {
    namedCurve: string;
}

export interface IEcAlgorithmParams extends iwc.IAlgorithmIdentifier {
    namedCurve: string;
    public?: CryptoKey;
}

export interface IEcdsaAlgorithmParams extends IEcAlgorithmParams {
    hash: {
        name: string;
    };
}

export class EcKey extends CryptoKey {
    namedCurve: string;

    constructor(key, alg: IEcKeyGenParams) {
        super(key, alg);
        this.namedCurve = alg.namedCurve;
        // TODO: get params from key if alg params is empty
    }
}

export class Ecdsa extends Ec {
    static ALGORITHM_NAME: string = ALG_NAME_ECDSA;

    static wc2pk11(alg: IEcdsaAlgorithmParams) {
        let _alg = null;
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
                throw new TypeError("Unknown Hash agorithm name in use");
        }
        return _alg;
    }

    static sign(session: graphene.Session, alg: IEcdsaAlgorithmParams, key: CryptoKey, data: Buffer) {
        this.checkAlgorithmIdentifier(alg);
        this.checkAlgorithmHashedParams(alg);
        this.checkPrivateKey(key);
        let _alg = this.wc2pk11(alg);

        let signer = session.createSign(_alg, key.key);
        signer.update(data);
        let signature = signer.final();

        return signature;
    }

    static verify(session: graphene.Session, alg: IEcdsaAlgorithmParams, key: CryptoKey, signature: Buffer, data: Buffer): boolean {
        this.checkAlgorithmIdentifier(alg);
        this.checkAlgorithmHashedParams(alg);
        this.checkPublicKey(key);
        let _alg = this.wc2pk11(alg);

        let signer = session.createVerify(_alg, key.key);
        signer.update(data);
        let res = signer.final(signature);

        return res;
    }
}

export class Ecdh extends Ec {
    static ALGORITHM_NAME: string = ALG_NAME_ECDH;

    static deriveKey(session: graphene.Session, alg: IEcdsaAlgorithmParams, baseKey: CryptoKey, derivedKeyType: Aes.IAesKeyGenParams, extractable: boolean, keyUsages: string[]): CryptoKey {
        // check algorithm
        this.checkAlgorithmParams(alg);
        if (!alg.public)
            throw new TypeError("EcParams: public: Missing required property");
        this.checkPublicKey(alg.public);

        // check baseKey
        this.checkPrivateKey(baseKey);

        // check derivedKeyType
        if (typeof derivedKeyType !== "object")
            throw TypeError("derivedKeyType: AlgorithmIdentifier: Algorithm must be an Object");
        if (!(derivedKeyType.name && typeof (derivedKeyType.name) === "string"))
            throw TypeError("derivedKeyType: AlgorithmIdentifier: Missing required property name");
        let AesClass = null;
        switch (derivedKeyType.name.toLowerCase()) {
            case Aes.AesGCM.ALGORITHM_NAME.toLowerCase():
                Aes.AesGCM.checkKeyGenParams(<Aes.IAesKeyGenParams>derivedKeyType);
                AesClass = Aes.AesGCM;
                break;
            default:
                throw new Error("derivedKeyType: Unknown Algorithm name in use");
        }

        // derive key
        let dKey: graphene.Key = session.deriveKey(
            {
                name: "ECDH1_DERIVE",
                params: new graphene.ECDSA.EcdhParams(
                    0x00000001, // CKD_NULL
                    null,
                    alg.public.key.getBinaryAttribute(0x00000181) // CKA_EC_POINT
                )
            },
            baseKey.key,
            {
                "class": Enums.ObjectClass.SecretKey,
                "sensitive": true,
                "private": true,
                "token": false,
                "keyType": Enums.KeyType.AES,
                "valueLen": derivedKeyType.length / 8,
                "encrypt": keyUsages.indexOf["encrypt"] > -1,
                "decrypt": keyUsages.indexOf["decrypt"] > -1,
                "sign": keyUsages.indexOf["sign"] > -1,
                "verify": keyUsages.indexOf["verify"] > -1,
                "wrapKey": keyUsages.indexOf["unwrapKey"] > -1,
                "derive": keyUsages.indexOf["deriveKey"] > -1
            }
        );

        return new CryptoKey(AesClass(dKey), derivedKeyType);
    }
}