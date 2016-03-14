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
import * as aes from "./aes";

export let ALG_NAME_RSA_PKCS1 = "RSASSA-PKCS1-v1_5";
let ALG_NAME_RSA_PSS = "RSA-PSS";
export let ALG_NAME_RSA_OAEP = "RSA-OAEP";

interface IJwkRsaKey extends IJwk {
    alg: string;
}

interface IJwkRsaPublicKey extends IJwkRsaKey {
    e: string;
    n: string;
}

interface IJwkRsaPrivateKey extends IJwkRsaKey {
    e: string;
    n: string;
    d: string;
    q: string;
    p: string;
    dq: string;
    dp: string;
    qi: string;
}

function create_template(alg: IRsaKeyGenAlgorithm, extractable: boolean, keyUsages: string[]): ITemplatePair {
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
            extractable: extractable,
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

            let template = create_template(_alg, extractable, keyUsages);

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

    static checkAlgorithmHashedParams(alg: IAlgorithmHashed) {
        super.checkAlgorithmHashedParams(alg);
        let _alg = alg.hash;
        _alg.name = _alg.name.toUpperCase();
        if (RSA_HASH_ALGS.indexOf(_alg.name) === -1)
            throw new error.AlgorithmError(error.ERROR_WRONG_ALGORITHM, _alg.name);
    }

    protected static jwkAlgName(alg: IAlgorithmHashed): string {
        throw new Error("Not implemented");
    }

    protected static exportJwkPublicKey(session: Session, key: CryptoKey, callback: (err: Error, data: IJwk) => void) {
        try {
            this.checkPublicKey(key);
            let pkey: ITemplate = (<P11CryptoKey>key).key.getAttribute({
                publicExponent: null,
                modulus: null
            });
            let alg: string = this.jwkAlgName(<IAlgorithmHashed>key.algorithm);
            let jwk: IJwkRsaPublicKey = {
                kty: "RSA",
                alg: alg,
                ext: true,
                key_ops: key.usages,
                e: base64url(pkey.publicExponent),
                n: base64url(pkey.modulus)
            };
            callback(null, jwk);
        }
        catch (e) {
            callback(e, null);
        }
    }

    protected static exportJwkPrivateKey(session: Session, key: CryptoKey, callback: (err: Error, data: IJwk) => void) {
        try {
            this.checkPrivateKey(key);
            let pkey: ITemplate = (<P11CryptoKey>key).key.getAttribute({
                publicExponent: null,
                modulus: null,
                privateExponent: null,
                prime1: null,
                prime2: null,
                exp1: null,
                exp2: null,
                coefficient: null
            });
            let alg: string = this.jwkAlgName(<IAlgorithmHashed>key.algorithm);
            let jwk: IJwkRsaPrivateKey = {
                kty: "RSA",
                alg: alg,
                ext: true,
                key_ops: key.usages,
                e: base64url(pkey.publicExponent),
                n: base64url(pkey.modulus),
                d: base64url(pkey.privateExponent),
                p: base64url(pkey.prime1),
                q: base64url(pkey.prime2),
                dp: base64url(pkey.exp1),
                dq: base64url(pkey.exp2),
                qi: base64url(pkey.coefficient)
            };
            callback(null, jwk);
        }
        catch (e) {
            callback(e, null);
        }
    }

    static exportKey(session: Session, format: string, key: CryptoKey, callback: (err: Error, data: Buffer | IJwk) => void): void {
        try {
            switch (format.toLowerCase()) {
                case "jwk":
                    if (key.type === "private")
                        this.exportJwkPrivateKey(session, key, callback);
                    else
                        this.exportJwkPublicKey(session, key, callback);
                default:
                    throw new Error(`Not supported format '${format}'`);
            }
        }
        catch (e) {
            callback(e, null);
        }
    }

    static importJwkPrivateKey(session: Session, jwk: IJwkRsaPrivateKey, algorithm: IRsaKeyGenAlgorithm, extractable: boolean, keyUsages: string[], callback: (err: Error, key: CryptoKey) => void) {
        try {
            let template = create_template(algorithm, extractable, keyUsages).privateKey;
            template.publicExponent = base64url.toBuffer(jwk.e);
            template.modulus = base64url.toBuffer(jwk.n);
            template.privateExponent = base64url.toBuffer(jwk.d);
            template.prime1 = base64url.toBuffer(jwk.p);
            template.prime2 = base64url.toBuffer(jwk.q);
            template.exp1 = base64url.toBuffer(jwk.dp);
            template.exp2 = base64url.toBuffer(jwk.dq);
            template.coefficient = base64url.toBuffer(jwk.qi);
            let p11key = session.create(template);
            callback(null, new P11CryptoKey(<any>p11key, algorithm));
        }
        catch (e) {
            callback(e, null);
        }
    }

    static importJwkPublicKey(session: Session, jwk: IJwkRsaPublicKey, algorithm: IRsaKeyGenAlgorithm, extractable: boolean, keyUsages: string[], callback: (err: Error, key: CryptoKey) => void) {
        try {
            let template = create_template(algorithm, extractable, keyUsages).publicKey;
            template.publicExponent = base64url.toBuffer(jwk.e);
            template.modulus = base64url.toBuffer(jwk.n);
            let p11key = session.create(template);
            callback(null, new P11CryptoKey(<any>p11key, algorithm));
        }
        catch (e) {
            callback(e, null);
        }
    }

    static importKey(session: Session, format: string, keyData: IJwk | Buffer, algorithm: Algorithm, extractable: boolean, keyUsages: string[], callback: (err: Error, key: CryptoKey) => void): void;
    static importKey(session: Session, format: string, keyData: IJwk | Buffer, algorithm: IRsaKeyGenAlgorithm, extractable: boolean, keyUsages: string[], callback: (err: Error, key: CryptoKey) => void): void;
    static importKey(session: Session, format: string, keyData: IJwk | Buffer, algorithm: IRsaKeyGenAlgorithm, extractable: boolean, keyUsages: string[], callback: (err: Error, key: CryptoKey) => void): void {
        try {
            switch (format.toLowerCase()) {
                case "jwk":
                    let jwk: any = keyData;
                    if (jwk.d)
                        this.importJwkPrivateKey(session, jwk, algorithm, extractable, keyUsages, callback);
                    else
                        this.importJwkPublicKey(session, jwk, algorithm, extractable, keyUsages, callback);
                default:
                    throw new Error(`Not supported format '${format}'`);
            }
        }
        catch (e) {
            callback(e, null);
        }
    }

}

export class RsaPKCS1 extends Rsa {
    static ALGORITHM_NAME: string = ALG_NAME_RSA_PKCS1;

    static wc2pk11(alg: Algorithm, key: CryptoKey): IAlgorithm {
        let res: string = null;
        switch ((<IAlgorithmHashed>key.algorithm).hash.name.toUpperCase()) {
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
                throw new error.AlgorithmError(error.ERROR_WRONG_ALGORITHM, (<IAlgorithmHashed>alg).hash.name);
        }
        return { name: res, params: null };
    }

    protected static jwkAlgName(alg: IAlgorithmHashed): string {
        let algName = /(\d+)$/.exec(alg.hash.name)[1];
        return `RS${algName === "1" ? "" : algName}`;
    }

    static onCheck(method: string, paramName: string, paramValue: any): void {
        switch (method) {
            case "sign":
                switch (paramName) {
                    case "alg":
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
                        this.checkPublicKey(paramValue);
                        break;
                    case "data":
                        break;
                }
                break;
        }
    }
}

export class RsaOAEP extends Rsa {
    static ALGORITHM_NAME: string = ALG_NAME_RSA_OAEP;

    protected static jwkAlgName(alg: IAlgorithmHashed): string {
        let algName = /(\d+)$/.exec(alg.hash.name)[1];
        return `RSA-OAEP${algName === "1" ? "" : ("-" + algName)}`;
    }

    static onCheck(method: string, paramName: string, paramValue: any): void {
        switch (method) {
            case "encrypt":
                switch (paramName) {
                    case "alg":
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

    static wrapKey(session: Session, format: string, key: CryptoKey, wrappingKey: CryptoKey, alg: Algorithm, callback: (err: Error, wkey: Buffer) => void): void {
        try {
            if (format === "raw") {
                let _alg = this.wc2pk11(alg, wrappingKey);
                session.wrapKey(_alg, (<P11CryptoKey>wrappingKey).key, (<P11CryptoKey>key).key, callback);
            }
            else
                super.wrapKey.apply(this, arguments);
        }
        catch (e) {
            callback(e, null);
        }
    }

    static unwrapKey(session: Session, format: string, wrappedKey: Buffer, unwrappingKey: CryptoKey, unwrapAlgorithm: Algorithm, unwrappedAlgorithm: Algorithm, extractable: boolean, keyUsages: string[], callback: (err: Error, key: CryptoKey) => void): void {
        try {
            if (format === "raw") {
                let _alg = this.wc2pk11(unwrapAlgorithm, unwrappingKey);
                let template = aes.create_template(<aes.IAesKeyGenAlgorithm>unwrappedAlgorithm, extractable, keyUsages);
                session.unwrapKey(_alg, (<P11CryptoKey>unwrappingKey).key, wrappedKey, template, (err, p11key) => {
                    if (err)
                        callback(err, null);
                    else
                        callback(null, new P11CryptoKey(p11key, unwrappedAlgorithm));
                });
            }
            else
                super.unwrapKey.apply(this, arguments);
        }
        catch (e) {
            callback(e, null);
        }
    }

    static wc2pk11(alg: Algorithm, key: CryptoKey): IAlgorithm {
        let params: RsaOaepParams = null;
        switch ((<IAlgorithmHashed>key.algorithm).hash.name.toUpperCase()) {
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
                throw new error.AlgorithmError(error.ERROR_WRONG_ALGORITHM, (<IAlgorithmHashed>key.algorithm).hash.name);
        }
        let res = { name: "RSA_PKCS_OAEP", params: params };
        return res;
    }
}

export class RsaPSS extends Rsa {
    static ALGORITHM_NAME: string = ALG_NAME_RSA_PSS;
}