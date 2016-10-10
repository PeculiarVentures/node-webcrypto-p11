// Core
import * as webcrypto from "webcrypto-core";
const AlgorithmError = webcrypto.AlgorithmError;
const AlgorithmNames = webcrypto.AlgorithmNames;
const Base64Url = webcrypto.Base64Url;

import {
    Session,
    IAlgorithm,
    KeyGenMechanism,
    ITemplate,
    ObjectClass,
    KeyType,
    NamedCurve,
    INamedCurve,
    EcKdf
} from "graphene-pk11";
import * as graphene from "graphene-pk11";
import * as aes from "./aes";

import * as utils from "../utils";
import { CryptoKey, ITemplatePair } from "../key";
import { BaseCrypto } from "../base";

function create_template(session: Session, alg: EcKeyGenParams, extractable: boolean, keyUsages: string[]): ITemplatePair {
    const label = `EC-${alg.namedCurve}`;
    const id_pk = new Buffer(utils.GUID(session));
    const id_pubk = new Buffer(utils.GUID(session));
    const keyType = KeyType.ECDSA;
    return {
        privateKey: {
            token: !!process.env["WEBCRYPTO_PKCS11_TOKEN"],
            sensitive: !!process.env["WEBCRYPTO_PKCS11_SENSITIVE"],
            class: ObjectClass.PRIVATE_KEY,
            keyType: keyType,
            private: true,
            label: label,
            id: id_pk,
            extractable: extractable,
            derive: keyUsages.indexOf("deriveKey") !== -1 || keyUsages.indexOf("deriveBits") !== -1,
            sign: keyUsages.indexOf("sign") !== -1,
            decrypt: keyUsages.indexOf("decrypt") !== -1,
            unwrap: keyUsages.indexOf("unwrapKey") !== -1
        },
        publicKey: {
            token: !!process.env["WEBCRYPTO_PKCS11_TOKEN"],
            class: ObjectClass.PUBLIC_KEY,
            keyType: keyType,
            label: label,
            id: id_pubk,
            derive: keyUsages.indexOf("deriveKey") !== -1 || keyUsages.indexOf("deriveBits") !== -1,
            verify: keyUsages.indexOf("verify") !== -1,
            encrypt: keyUsages.indexOf("encrypt") !== -1,
            wrap: keyUsages.indexOf("wrapKey") !== -1,
        }
    };
}

export class EcCrypto extends BaseCrypto {

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
                throw new Error(`Unsupported namedCurve in use ${name}`);
        }
        return NamedCurve.getByName(namedCurve);
    }

    static generateKey(algorithm: EcKeyGenParams, extractable: boolean, keyUsages: string[], session?: Session): PromiseLike<CryptoKeyPair> {
        return (super.generateKey.apply(this, arguments) as PromiseLike<CryptoKeyPair>)
            .then(() => {
                return new Promise((resolve, reject) => {
                    let template = create_template(session!, algorithm, extractable, keyUsages);

                    // EC params
                    template.publicKey.paramsEC = this.getNamedCurve(algorithm.namedCurve).value;
                    // PKCS11 generation
                    session!.generateKeyPair(KeyGenMechanism.EC, template.publicKey, template.privateKey, (err, keys) => {
                        try {
                            if (err)
                                reject(err);
                            else {
                                let wcKeyPair: CryptoKeyPair = {
                                    privateKey: new CryptoKey(keys.privateKey, algorithm),
                                    publicKey: new CryptoKey(keys.publicKey, algorithm)
                                };
                                resolve(wcKeyPair);
                            }
                        }
                        catch (e) {
                            reject(e);
                        }
                    });
                });
            });
    }

    protected static exportJwkPublicKey(key: CryptoKey) {
        return new Promise((resolve, reject) => {
            let pkey: ITemplate = (<CryptoKey>key).key.getAttribute({
                pointEC: null
            });
            // TODO: lib.dom.d.ts has typedCurve
            let curve = this.getNamedCurve((key.algorithm as EcKeyGenParams).namedCurve);
            let ecPoint = EcUtils.decodePoint(pkey.pointEC!, curve);
            let jwk: JsonWebKey = {
                kty: "EC",
                crv: (key.algorithm as EcKeyGenParams).namedCurve,
                ext: true,
                key_ops: key.usages,
                x: Base64Url.encode(ecPoint.x),
                y: Base64Url.encode(ecPoint.y),
            };
            resolve(jwk);
        });
    }

    protected static exportJwkPrivateKey(key: CryptoKey) {
        return new Promise((resolve, reject) => {
            let pkey: ITemplate = key.key.getAttribute({
                value: null
            });
            let jwk: JsonWebKey = {
                kty: "EC",
                crv: (key.algorithm as EcKeyGenParams).namedCurve,
                ext: true,
                key_ops: key.usages,
                d: Base64Url.encode(pkey.value!)
            };
            resolve(jwk);
        });
    }

    static exportKey(format: string, key: CryptoKey, session?: Session): PromiseLike<JsonWebKey | ArrayBuffer> {
        return (super.exportKey.apply(this, arguments) as PromiseLike<CryptoKeyPair>)
            .then(() => {
                switch (format.toLowerCase()) {
                    case "jwk":
                        if (key.type === "private")
                            return this.exportJwkPrivateKey(key);
                        else
                            return this.exportJwkPublicKey(key);
                    default:
                        throw new Error(`Not supported format '${format}'`);
                }
            });
    }

    static importJwkPrivateKey(session: Session, jwk: JsonWebKey, algorithm: EcKeyGenParams, extractable: boolean, keyUsages: string[]) {
        return new Promise((resolve, reject) => {
            let namedCurve = this.getNamedCurve(jwk.crv!);
            let template = create_template(session, algorithm, extractable, keyUsages).privateKey;
            template.paramsEC = namedCurve.value;
            template.value = utils.b64_decode(jwk.d!);
            let p11key = session.create(template);
            resolve(new CryptoKey(<any>p11key, algorithm));
        });
    }

    static importJwkPublicKey(session: Session, jwk: JsonWebKey, algorithm: EcKeyGenParams, extractable: boolean, keyUsages: string[]) {
        return new Promise((resolve, reject) => {
            let namedCurve = this.getNamedCurve(jwk.crv!);
            let template = create_template(session, algorithm, extractable, keyUsages).publicKey;
            template.paramsEC = namedCurve.value;
            let pointEc = EcUtils.encodePoint({ x: utils.b64_decode(jwk.x!), y: utils.b64_decode(jwk.y!) }, namedCurve);
            template.pointEC = pointEc;
            let p11key = session.create(template);
            resolve(new CryptoKey(<any>p11key, algorithm));
        });
    }

    static importKey(format: string, keyData: JsonWebKey | BufferSource, algorithm: Algorithm, extractable: boolean, keyUsages: string[], session?: Session): PromiseLike<CryptoKey> {
        return (super.importKey.apply(this, arguments) as PromiseLike<CryptoKeyPair>)
            .then(() => {
                switch (format.toLowerCase()) {
                    case "jwk":
                        let jwk: any = keyData;
                        if (jwk.d)
                            return this.importJwkPrivateKey(session!, jwk, algorithm as EcKeyGenParams, extractable, keyUsages);
                        else
                            return this.importJwkPublicKey(session!, jwk, algorithm as EcKeyGenParams, extractable, keyUsages);
                    default:
                        throw new Error(`Not supported format '${format}'`);
                }
            });
    }

}

export class Ecdsa extends EcCrypto {

    static wc2pk11(alg: EcdsaParams, keyAlg: KeyAlgorithm): IAlgorithm {
        let _alg: string;
        switch ((alg.hash as Algorithm).name.toUpperCase()) {
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
                throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, (alg.hash as Algorithm).name);
        }
        return { name: _alg, params: null };
    }

    static sign(algorithm: EcdsaParams, key: CryptoKey, data: Buffer, session?: Session): PromiseLike<ArrayBuffer> {
        return (super.sign.apply(this, arguments) as PromiseLike<CryptoKeyPair>)
            .then(() => {
                return new Promise((resolve, reject) => {
                    session!.createSign(this.wc2pk11(algorithm, key.algorithm), key.key).once(data, (err, data) => {
                        if (err) reject(err);
                        else resolve(data.buffer);
                    });
                });
            });
    }

    static verify(algorithm: EcdsaParams, key: CryptoKey, signature: Buffer, data: Buffer, session?: Session): PromiseLike<boolean> {
        return (super.verify.apply(this, arguments) as PromiseLike<CryptoKeyPair>)
            .then(() => {
                return new Promise((resolve, reject) => {
                    session!.createVerify(this.wc2pk11(algorithm, key.algorithm), key.key).once(data, signature, (err, data) => {
                        if (err) reject(err);
                        else resolve(data);
                    });
                });
            });
    }

}

export class Ecdh extends EcCrypto {

    static deriveKey(algorithm: EcdsaParams, baseKey: CryptoKey, derivedKeyType: AesKeyGenParams, extractable: boolean, keyUsages: string[], session?: Session): PromiseLike<CryptoKey> {
        return super.deriveKey.apply(this, arguments)
            .then(() => {
                return new Promise((resolve, reject) => {

                    let AesClass: any = null;
                    switch (derivedKeyType.name.toLowerCase()) {
                        case AlgorithmNames.AesGCM.toLowerCase():
                            AesClass = aes.AesGCM;
                            break;
                        case AlgorithmNames.AesCBC.toLowerCase():
                            AesClass = aes.AesCBC;
                            break;
                        default:
                            throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, derivedKeyType.name);
                    }

                    let template = aes.create_template(session!, derivedKeyType, extractable, keyUsages);
                    template.valueLen = derivedKeyType.length >> 3;
                    // derive key
                    // TODO: EcdhParams no match for Chrome examples 
                    session!.deriveKey(
                        {
                            name: "ECDH1_DERIVE",
                            params: new graphene.EcdhParams(
                                EcKdf.NULL,
                                undefined,
                                (algorithm as any).public.key.getAttribute({ pointEC: null }).pointEC // CKA_EC_POINT
                            )
                        },
                        baseKey.key,
                        template,
                        (err, key) => {
                            if (err)
                                reject(err);
                            else
                                resolve(new CryptoKey(key, derivedKeyType));
                        });
                });
            });
    }

    /**
     * Calculates an AES key size
     * 
     * @protected
     * @static
     * @param {number} length
     * @returns
     * 
     * @memberOf Ecdh
     */
    protected static getAesKeyLength(length: number) {
        let res = 0;
        [128, 192, 256].forEach(function (keySize) {
            let byteLength = length >> 3;
            let byteKeySize = keySize >> 3;
            let calc = byteKeySize / byteLength;
            if (calc >= 1) {
                res = keySize;
            }
        });
        return res;
    }

    static deriveBits(algorithm: Algorithm, baseKey: CryptoKey, length: number, session?: Session): PromiseLike<ArrayBuffer> {
        return super.deriveBits.apply(this, arguments)
            .then(() => {
                return new Promise((resolve, reject) => {

                    const aesKeyLength = this.getAesKeyLength(length);
                    let template: ITemplate = aes.create_template(session!, { name: "AES-CBC", length: aesKeyLength }, true, ["encrypt"]);
                    template.valueLen = aesKeyLength >> 3;
                    // derive key
                    // TODO: EcdhParams no match for Chrome examples 
                    session!.deriveKey(
                        {
                            name: "ECDH1_DERIVE",
                            params: new graphene.EcdhParams(
                                EcKdf.NULL,
                                undefined,
                                (algorithm as any).public.key.getAttribute({ pointEC: null }).pointEC // CKA_EC_POINT
                            )
                        },
                        baseKey.key,
                        template,
                        (err, key) => {
                            if (err)
                                reject(err);
                            else {
                                const secretKey = key.toType<graphene.SecretKey>();
                                const value = secretKey.getAttribute({ value: null }).value as Buffer;
                                resolve(value.slice(0, length >> 3));
                            }
                        });
                });
            });
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

        // ASN1 encode OCTET_STRING
        let octet = Buffer.concat([new Buffer([4]), this.encodeAsn1Length(b.length), b]);
        return octet;
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

    public static encodeAsn1Length(length: number): Buffer {
        let enc: number[] = [];
        if (length !== (length & 0x7F)) {
            let code = length.toString(16);
            let _length = Math.round(code.length / 2);
            enc[0] = _length | 0x80;
            if (Math.floor(code.length % 2) > 0)
                code = "0" + code;
            for (let i = 0; i < code.length; i = i + 2) {
                enc[1 + (i / 2)] = parseInt(code.substring(i, i + 2), 16);
            }
        } else {
            enc[0] = length;
        }
        return new Buffer(enc);
    }
}