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
RsaOaepParams,
RsaMgf} from "graphene-pk11";
import * as error from "../error";
import * as base64url from "base64url";

import {IAlgorithmHashed, AlgorithmBase, IJwk, IJwkSecret, RSA_HASH_ALGS} from "./alg";
import {P11CryptoKey, KU_DECRYPT, KU_ENCRYPT, KU_SIGN, KU_VERIFY, KU_WRAP, KU_UNWRAP, ITemplatePair} from "../key";

let ALG_NAME_RSA_PKCS1 = "RSASSA-PKCS1-v1_5";
let ALG_NAME_RSA_PSS = "RSA-PSS";
let ALG_NAME_RSA_OAEP = "RSA-OAEP";


function create_template(alg: IRsaKeyGenAlgorithm, keyUsages: string[]): ITemplatePair {
    const label = `RSA-${alg.modulusLength}`;
    const id = new Buffer(new Date().getTime().toString());
    return {
        privateKey: {
            token: false,
            class: ObjectClass.PRIVATE_KEY,
            keyType: KeyType.RSA,
            private: true,
            label: label,
            id: id,
            extractable: true,
            derive: false,
            sign: keyUsages.indexOf(KU_SIGN) !== -1,
            decrypt: keyUsages.indexOf(KU_DECRYPT) !== -1,
            unwrap: keyUsages.indexOf(KU_UNWRAP) !== -1
        },
        publicKey: {
            token: false,
            class: ObjectClass.PUBLIC_KEY,
            keyType: KeyType.RSA,
            label: label,
            id: id,
            verify: keyUsages.indexOf(KU_VERIFY) !== -1,
            encrypt: keyUsages.indexOf(KU_ENCRYPT) !== -1,
            wrap: keyUsages.indexOf(KU_WRAP) !== -1,
        }
    };
}

export interface IRsaKeyGenAlgorithm extends Algorithm {
    modulusLength: number;
    publicExponent: Uint8Array;
}

abstract class Rsa extends AlgorithmBase {

    static generateKey(session: Session, alg: Algorithm, extractable: boolean, keyUsages: string[], callback: (err: Error, key: CryptoKey | CryptoKeyPair) => void): void {
        try {
            let _alg: IRsaKeyGenAlgorithm = <any>alg;
            this.checkAlgorithmIdentifier(alg);
            this.checkAlgorithmHashedParams(<IAlgorithmHashed>alg);
            this.checkKeyGenAlgorithm(_alg);

            let template = create_template(_alg, keyUsages);

            // RSA params
            template.publicKey.publicExponent = new Buffer(_alg.publicExponent),
                template.publicKey.modulusBits = _alg.modulusLength;

            // PKCS11 generation
            session.generateKeyPair(KeyGenMechanism.RSA, template.publicKey, template.privateKey, (err, keys) => {
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

    static checkKeyGenAlgorithm(alg: IRsaKeyGenAlgorithm) {
        if (!alg.modulusLength)
            throw new TypeError("RsaKeyGenParams: modulusLength: Missing required property");
        if (alg.modulusLength < 256 || alg.modulusLength > 16384)
            throw new TypeError("RsaKeyGenParams: The modulus length must be a multiple of 8 bits and >= 256 and <= 16384");
        if (!(alg.publicExponent && alg.publicExponent instanceof Uint8Array))
            throw new TypeError("RsaKeyGenParams: publicExponent: Missing or not a Uint8Array");
    }

    static wc2pk11(alg: Algorithm): IAlgorithm {
        let _alg: IAlgorithmHashed = <any>alg;
        this.checkAlgorithmHashedParams(_alg);
        let res: string = null;
        switch (_alg.hash.name.toUpperCase()) {
            case "SHA-1":
                res = "SHA1_RSA_PKCS";
                break;
            case "SHA-224":
                res = "SHA224_RSA_PKCS";
                break;
            case "SHA-256":
                res = "SHA256_RSA_PKCS";
                break;
            case "SHA-384":
                res = "SHA384_RSA_PKCS";
                break;
            case "SHA-512":
                res = "SHA512_RSA_PKCS";
                break;
            default:
                throw new error.AlgorithmError(error.ERROR_WRONG_ALGORITHM, _alg.hash.name);
        }
        return { name: res, params: null };
    }

    static checkAlgorithmHashedParams(alg: IAlgorithmHashed) {
        super.checkAlgorithmHashedParams(alg);
        let _alg = alg.hash;
        _alg.name = _alg.name.toUpperCase();
        if (RSA_HASH_ALGS.indexOf(_alg.name) === -1)
            throw new error.AlgorithmError(error.ERROR_WRONG_ALGORITHM, _alg.name);
    }

    static sign(session: Session, alg: Algorithm, key: CryptoKey, data: Buffer, callback: (err: Error, signature: Buffer) => void): void {
        try {
            this.checkAlgorithmIdentifier(alg);
            this.checkPrivateKey(key);
            let _alg = this.wc2pk11(key.algorithm);

            let signer = session.createSign(<IAlgorithm>_alg, (<P11CryptoKey>key).key);
            signer.update(data, (err: Error) => {
                if (err)
                    callback(err, null);
                else
                    signer.final(callback);
            });

        } catch (e) {
            callback(e, null);
        }
    }

    static verify(session: Session, alg: Algorithm, key: CryptoKey, signature: Buffer, data: Buffer, callback: (err: Error, verify: boolean) => void): void {
        try {
            this.checkAlgorithmIdentifier(alg);
            this.checkPublicKey(key);
            let _alg = this.wc2pk11(key.algorithm);

            let signer = session.createVerify(<IAlgorithm>_alg, (<P11CryptoKey>key).key);
            signer.update(data, (err: Error) => {
                if (err)
                    callback(err, null);
                else
                    signer.final(signature, callback);
            });

        } catch (e) {
            callback(e, null);
        }
    }

}
//     exportKey(session: graphene.Session, format: string, key: CryptoKey): Buffer | Object {
//         throw new Error("Method is not supported");
//     }

//     static checkAlgorithmHashedParams(alg: iwc.IAlgorithmIdentifier) {
//         super.checkAlgorithmHashedParams(alg);
//         let _alg = alg.hash;
//         _alg.name = _alg.name.toUpperCase();
//         if (HASH_ALGS.indexOf(_alg.name) === -1)
//             throw new Error("AlgorithmHashedParams: Unknow hash algorithm in use");
//     }

// }

export class RsaPKCS1 extends Rsa {
    static ALGORITHM_NAME: string = ALG_NAME_RSA_PKCS1;
}

export class RsaOAEP extends Rsa {
    static ALGORITHM_NAME: string = ALG_NAME_RSA_OAEP;

    static onCheck(method: string, paramName: string, paramValue: any): void {
        switch (method) {
            case "encrypt":
                switch (paramName) {
                    case "alg":
                        this.checkAlgorithmIdentifier(paramValue);
                        this.checkAlgorithmHashedParams(paramValue);
                        break;
                    case "key":
                        this.checkPublicKey(paramValue);
                        break;
                    case "data":
                        break;
                }
                break;
            case "decrypt":
                switch (paramName) {
                    case "alg":
                        this.checkAlgorithmIdentifier(paramValue);
                        this.checkAlgorithmHashedParams(paramValue);
                        break;
                    case "key":
                        this.checkPrivateKey(paramValue);
                        break;
                    case "data":
                        break;
                }
                break;
        }
    }

    static wc2pk11(alg: IAlgorithmHashed): IAlgorithm {
        let params: RsaOaepParams = null;
        switch (alg.hash.name.toUpperCase()) {
            case "SHA-1":
                params = new RsaOaepParams(MechanismEnum.SHA1, RsaMgf.MGF1_SHA1);
                break;
            case "SHA-224":
                params = new RsaOaepParams(MechanismEnum.SHA224, RsaMgf.MGF1_SHA224);
                break;
            case "SHA-256":
                params = new RsaOaepParams(MechanismEnum.SHA256, RsaMgf.MGF1_SHA256);
                break;
            case "SHA-384":
                params = new RsaOaepParams(MechanismEnum.SHA384, RsaMgf.MGF1_SHA384);
                break;
            case "SHA-512":
                params = new RsaOaepParams(MechanismEnum.SHA512, RsaMgf.MGF1_SHA512);
                break;
            default:
                throw new error.AlgorithmError(error.ERROR_WRONG_ALGORITHM, alg.hash.name);
        }
        let res = { name: "RSA_PKCS_OAEP", params: params };
        return res;
    }
}

export class RsaPSS extends Rsa {
    static ALGORITHM_NAME: string = ALG_NAME_RSA_PSS;
}

//     static generateKey(session: graphene.Session, alg: IRsaKeyGenParams, extractable: boolean, keyUsages: string[], label?: string): iwc.ICryptoKeyPair {
//         this.checkAlgorithmIdentifier(alg);
//         this.checkRsaGenParams(alg);
//         this.checkAlgorithmHashedParams(alg);

//         let keyPair: iwc.ICryptoKeyPair = super.generateKey.apply(this, arguments);
//         return keyPair;
//     }

//     static sign(session: graphene.Session, alg: iwc.IAlgorithmIdentifier, key: CryptoKey, data: Buffer) {
//         this.checkAlgorithmIdentifier(alg);
//         this.checkPrivateKey(key);
//         let _alg = this.wc2pk11(key.algorithm);

//         let signer = session.createSign(_alg, key.key);
//         signer.update(data);
//         let signature = signer.final();

//         return signature;
//     }

//     static verify(session: graphene.Session, alg: iwc.IAlgorithmIdentifier, key: CryptoKey, signature: Buffer, data: Buffer): boolean {
//         this.checkAlgorithmIdentifier(alg);
//         this.checkPublicKey(key);
//         let _alg = this.wc2pk11(key.algorithm);

//         let signer = session.createVerify(_alg, key.key);
//         signer.update(data);
//         let res = signer.final(signature);

//         return res;
//     }

// }

// export class RsaPSS extends Rsa {
//     static ALGORITHM_NAME: string = ALG_NAME_RSA_PSS;

//     static generateKey(session: graphene.Session, alg: IRsaKeyGenParams, extractable: boolean, keyUsages: string[], label?: string): iwc.ICryptoKeyPair {
//         throw new Error("not realized in this implementation");
//     }
// }

// export class RsaOAEP extends Rsa {
//     static ALGORITHM_NAME: string = ALG_NAME_RSA_OAEP;

//     static generateKey(session: graphene.Session, alg: IRsaKeyGenParams, extractable: boolean, keyUsages: string[], label?: string): iwc.ICryptoKeyPair {
//         this.checkAlgorithmIdentifier(alg);
//         this.checkRsaGenParams(alg);
//         this.checkAlgorithmHashedParams(alg);

//         let keyPair: iwc.ICryptoKeyPair = super.generateKey.apply(this, arguments);
//         return keyPair;
//     }

//     static wc2pk11(alg) {
//         let params = null;
//         switch (alg.hash.name.toUpperCase()) {
//             case "SHA-1":
//                 params = new RSA.RsaOAEPParams(Enums.Mechanism.SHA1, Enums.MGF1.SHA1);
//                 break;
//             case "SHA-224":
//                 params = new RSA.RsaOAEPParams(Enums.Mechanism.SHA224, Enums.MGF1.SHA224);
//                 break;
//             case "SHA-256":
//                 params = new RSA.RsaOAEPParams(Enums.Mechanism.SHA256, Enums.MGF1.SHA256);
//                 break;
//             case "SHA-384":
//                 params = new RSA.RsaOAEPParams(Enums.Mechanism.SHA384, Enums.MGF1.SHA384);
//                 break;
//             case "SHA-512":
//                 params = new RSA.RsaOAEPParams(Enums.Mechanism.SHA512, Enums.MGF1.SHA512);
//                 break;
//             default:
//                 throw new Error("Unknown hash name in use");
//         }
//         let res = { name: "RSA_PKCS_OAEP", params: params };
//         return res;
//     }

//     static encrypt(session: graphene.Session, alg: iwc.IAlgorithmIdentifier, key: CryptoKey, data: Buffer): Buffer {
//         this.checkAlgorithmIdentifier(alg);
//         this.checkPublicKey(key);
//         let _alg = this.wc2pk11(key.algorithm);

//         // TODO: Remove <any>
//         let enc = session.createEncrypt(<any>_alg, key.key);
//         let msg = new Buffer(0);
//         msg = Buffer.concat([msg, enc.update(data)]);
//         msg = Buffer.concat([msg, enc.final()]);
//         return msg;
//     }

//     static decrypt(session: graphene.Session, alg: iwc.IAlgorithmIdentifier, key: CryptoKey, data: Buffer): Buffer {
//         this.checkAlgorithmIdentifier(alg);
//         this.checkPrivateKey(key);
//         let _alg = this.wc2pk11(key.algorithm);

//         // TODO: Remove <any>
//         let dec = session.createDecrypt(<any>_alg, key.key);
//         let msg = new Buffer(0);
//         msg = Buffer.concat([msg, dec.update(data)]);
//         msg = Buffer.concat([msg, dec.final()]);
//         return msg;
//     }

//     static wrapKey(session: graphene.Session, key: CryptoKey, wrappingKey: CryptoKey, alg: iwc.IAlgorithmIdentifier): Buffer {
//         this.checkAlgorithmIdentifier(alg);
//         this.checkAlgorithmHashedParams(alg);
//         this.checkSecretKey(key);
//         this.checkPublicKey(wrappingKey);
//         let _alg = this.wc2pk11(alg);

//         let wrappedKey: Buffer = session.wrapKey(wrappingKey.key, _alg, key.key);
//         return wrappedKey;
//     }

//     static unwrapKey(session: graphene.Session, wrappedKey: Buffer, unwrappingKey: CryptoKey, unwrapAlgorithm: iwc.IAlgorithmIdentifier, unwrappedAlgorithm: aes.IAesKeyGenAlgorithm, extractable: boolean, keyUsages: string[]): iwc.ICryptoKey {
//         this.checkAlgorithmIdentifier(unwrapAlgorithm);
//         this.checkAlgorithmHashedParams(unwrapAlgorithm);
//         this.checkPrivateKey(unwrappingKey);
//         let _alg = this.wc2pk11(unwrapAlgorithm);

//         // convert unwrappedAlgorithm to PKCS11 Algorithm
//         let AlgClass = null;
//         switch (unwrappedAlgorithm.name) {
//             // case aes.ALG_NAME_AES_CTR:
//             // case aes.ALG_NAME_AES_CMAC:
//             // case aes.ALG_NAME_AES_CFB:
//             // case aes.ALG_NAME_AES_KW:
//             case aes.ALG_NAME_AES_CBC:
//                 aes.Aes.checkKeyGenParams(<any>unwrappedAlgorithm);
//                 AlgClass = aes.AesCBC;
//                 break;
//             case aes.ALG_NAME_AES_GCM:
//                 aes.Aes.checkKeyGenParams(<any>unwrappedAlgorithm);
//                 AlgClass = aes.AesGCM;
//                 break;
//             default:
//                 throw new Error("Unsupported algorithm in use");
//         }


//         let unwrappedKey: graphene.Key = session.unwrapKey(
//             unwrappingKey.key,
//             _alg,
//             {
//                 "class": Enums.ObjectClass.SecretKey,
//                 "sensitive": true,
//                 "private": true,
//                 "token": false,
//                 "keyType": Enums.KeyType.AES,
//                 "valueLen": unwrappedAlgorithm.length / 8,
//                 "encrypt": keyUsages.indexOf["encrypt"] > -1,
//                 "decrypt": keyUsages.indexOf["decrypt"] > -1,
//                 "sign": keyUsages.indexOf["sign"] > -1,
//                 "verify": keyUsages.indexOf["verify"] > -1,
//                 "wrap": keyUsages.indexOf["wrapKey"] > -1,
//                 "unwrap": keyUsages.indexOf["unwrapKey"] > -1,
//                 "derive": keyUsages.indexOf["deriveKey"] > -1
//             },
//             wrappedKey
//         );
//         return new AlgClass(unwrappedKey, unwrappedAlgorithm);
//     }
// }