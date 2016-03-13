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
    INamedCurve,
    EcKdf} from "graphene-pk11";
import * as error from "../error";
import * as aes from "./aes";
import * as base64url from "base64url";

import {IAlgorithmHashed, AlgorithmBase, IJwk, IJwkSecret, RSA_HASH_ALGS} from "./alg";
import {P11CryptoKey, KU_DECRYPT, KU_ENCRYPT, KU_SIGN, KU_VERIFY, KU_WRAP, KU_UNWRAP, KU_DERIVE, ITemplatePair} from "../key";

export let ALG_NAME_ECDH = "ECDH";
export let ALG_NAME_ECDSA = "ECDSA";

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

    static getNamedCurve(name: string): INamedCurve {
        let namedCurve: string;
        switch (name) {
            case "P-192":
                namedCurve = "secp192r1";
                break;
            case "P-256":
                namedCurve = "secp256r1";
                break;
            case "P-384":
                namedCurve = "secp384r1";
                break;
            case "P-521":
                namedCurve = "secp521r1";
                break;
            default:
                throw new Error(`Unsupported namedCurve in use ${namedCurve}`);
        }
        return NamedCurve.getByName(namedCurve);
    }

    static generateKey(session: Session, alg: Algorithm, extractable: boolean, keyUsages: string[], callback: (err: Error, key: CryptoKey | CryptoKeyPair) => void): void {
        try {
            let _alg: IEcKeyGenAlgorithm = <any>alg;
            this.checkAlgorithmIdentifier(alg);
            this.checkKeyGenAlgorithm(_alg);

            let template = create_template(_alg, extractable, keyUsages);

            // EC params
            template.publicKey.paramsEC = this.getNamedCurve(_alg.namedCurve).value;
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

    protected static exportJwkPublicKey(session: Session, key: CryptoKey, callback: (err: Error, data: IJwk) => void) {
        try {
            this.checkPublicKey(key);
            let pkey: ITemplate = (<P11CryptoKey>key).key.getAttribute({
                pointEC: null
            });
            let curve = this.getNamedCurve((<IEcKeyGenAlgorithm>key.algorithm).namedCurve);
            let ecPoint = EcUtils.decodePoint(pkey.pointEC, curve);
            let jwk = {
                kty: "EC",
                crv: (<IEcKeyGenAlgorithm>key.algorithm).namedCurve,
                ext: true,
                key_ops: key.usages,
                x: base64url(ecPoint.x),
                y: base64url(ecPoint.y),
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
                value: null
            });
            let jwk = {
                kty: "EC",
                crv: (<IEcKeyGenAlgorithm>key.algorithm).namedCurve,
                ext: true,
                key_ops: key.usages,
                d: base64url(pkey.value)
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

interface IEcPoint {
    x: Buffer;
    y: Buffer;
}

class EcUtils {

    public static getData(data: Buffer): Buffer {
        let octet = false;
        for (let i = 0; i < data.length; i++) {
            if (data[i] === 4) {
                if (octet)
                    return data.slice(i);
                else
                    octet = true;
            }
        }
        throw new Error("Wrong data");
    }

    // Used by SunPKCS11 and SunJSSE.
    public static decodePoint(data: Buffer, curve: INamedCurve): IEcPoint {
        data = this.getData(data);

        if ((data.length === 0) || (data[0] !== 4)) {
            throw new Error("Only uncompressed point format supported");
        }
        // Per ANSI X9.62, an encoded point is a 1 byte type followed by
        // ceiling(log base 2 field-size / 8) bytes of x and the same of y.
        let n = (data.length - 1) / 2;
        if (n !== (curve.size / 8)) {
            throw new Error("Point does not match field size");
        }

        let xb: Buffer = data.slice(1, 1 + n);
        let yb: Buffer = data.slice(n + 1, n + 1 + n);

        return { x: xb, y: yb };
    }

    public static encodePoint(point: IEcPoint, curve: INamedCurve): Buffer {
        // get field size in bytes (rounding up)
        let n = curve.size / 8;
        let xb = this.trimZeroes(point.x);
        let yb = this.trimZeroes(point.y);
        if ((xb.length > n) || (yb.length > n)) {
            throw new Error("Point coordinates do not match field size");
        }
        let b = Buffer.concat([new Buffer([4]), xb, yb]);
        return b;
    }

    public static trimZeroes(b: Buffer): Buffer {
        let i = 0;
        while ((i < b.length - 1) && (b[i] === 0)) {
            i++;
        }
        if (i === 0) {
            return b;
        }

        return b.slice(i, b.length);
    }
}