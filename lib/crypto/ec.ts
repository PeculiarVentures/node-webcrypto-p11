// Core
import * as webcrypto from "webcrypto-core";
const AlgorithmError = webcrypto.AlgorithmError;
const AlgorithmNames = webcrypto.AlgorithmNames;
const Base64Url = webcrypto.Base64Url;

import {
    EcKdf,
    IAlgorithm,
    INamedCurve,
    ITemplate,
    KeyGenMechanism,
    KeyType,
    NamedCurve,
    ObjectClass,
    Session,
} from "graphene-pk11";
import * as graphene from "graphene-pk11";
import * as aes from "./aes";

import { BaseCrypto } from "../base";
import { CryptoKey, ITemplatePair } from "../key";
import * as utils from "../utils";

import * as Asn1Js from "asn1js";
const { PrivateKeyInfo, PublicKeyInfo } = require("pkijs");

function create_template(session: Session, alg: EcKeyGenParams, extractable: boolean, keyUsages: string[]): ITemplatePair {
    const label = `EC-${alg.namedCurve}`;
    const idKey = new Buffer(utils.GUID(session));
    const keyType = KeyType.ECDSA;
    return {
        privateKey: {
            token: !!process.env["WEBCRYPTO_PKCS11_TOKEN"],
            sensitive: !!process.env["WEBCRYPTO_PKCS11_SENSITIVE"],
            class: ObjectClass.PRIVATE_KEY,
            keyType,
            private: true,
            label,
            id: idKey,
            extractable,
            derive: keyUsages.indexOf("deriveKey") !== -1 || keyUsages.indexOf("deriveBits") !== -1,
            sign: keyUsages.indexOf("sign") !== -1,
            decrypt: keyUsages.indexOf("decrypt") !== -1,
            unwrap: keyUsages.indexOf("unwrapKey") !== -1,
        },
        publicKey: {
            token: !!process.env["WEBCRYPTO_PKCS11_TOKEN"],
            class: ObjectClass.PUBLIC_KEY,
            keyType,
            private: false,
            label,
            id: idKey,
            derive: keyUsages.indexOf("deriveKey") !== -1 || keyUsages.indexOf("deriveBits") !== -1,
            verify: keyUsages.indexOf("verify") !== -1,
            encrypt: keyUsages.indexOf("encrypt") !== -1,
            wrap: keyUsages.indexOf("wrapKey") !== -1,
        },
    };
}

export class EcCrypto extends BaseCrypto {

    public static generateKey(algorithm: EcKeyGenParams, extractable: boolean, keyUsages: string[], session?: Session): PromiseLike<CryptoKeyPair> {
        return super.generateKey.apply(this, arguments)
            .then(() => {
                return new Promise((resolve, reject) => {
                    const template = create_template(session!, algorithm, extractable, keyUsages);

                    // EC params
                    template.publicKey.paramsEC = this.getNamedCurve(algorithm.namedCurve).value;
                    // PKCS11 generation
                    session!.generateKeyPair(KeyGenMechanism.EC, template.publicKey, template.privateKey, (err, keys) => {
                        try {
                            if (err) {
                                reject(err);
                            } else {
                                const wcKeyPair: CryptoKeyPair = {
                                    privateKey: new CryptoKey(keys.privateKey, algorithm),
                                    publicKey: new CryptoKey(keys.publicKey, algorithm),
                                };
                                resolve(wcKeyPair);
                            }
                        } catch (e) {
                            reject(e);
                        }
                    });
                });
            });
    }

    public static async exportKey(format: string, key: CryptoKey, session?: Session): Promise<JsonWebKey | ArrayBuffer> {
        await super.exportKey(format, key, session);
        switch (format.toLowerCase()) {
            case "jwk": {
                if (key.type === "private") {
                    return this.exportJwkPrivateKey(key);
                } else {
                    return this.exportJwkPublicKey(key);
                }
            }
            case "pkcs8": {
                const jwk = await this.exportJwkPrivateKey(key);
                const privateKey = new PrivateKeyInfo();
                privateKey.fromJSON(jwk);
                return privateKey.toSchema(true).toBER(false);
            }
            case "spki": {
                const jwk = await this.exportJwkPublicKey(key);
                const publicKey = new PublicKeyInfo();
                publicKey.fromJSON(jwk);
                return publicKey.toSchema(true).toBER(false);
            }
            default:
                throw new Error(`Not supported format '${format}'`);
        }
    }

    public static importKey(format: string, keyData: JsonWebKey | BufferSource, algorithm: Algorithm, extractable: boolean, keyUsages: string[], session?: Session): PromiseLike<CryptoKey> {
        return super.importKey.apply(this, arguments)
            .then(() => {
                switch (format.toLowerCase()) {
                    case "jwk": {
                        const jwk: any = keyData;
                        if (jwk.d) {
                            return this.importJwkPrivateKey(session!, jwk, algorithm as EcKeyGenParams, extractable, keyUsages);
                        } else {
                            return this.importJwkPublicKey(session!, jwk, algorithm as EcKeyGenParams, extractable, keyUsages);
                        }
                    }
                    case "spki": {
                        const arBuf = new Uint8Array(keyData as Uint8Array).buffer;
                        const asn1 = Asn1Js.fromBER(arBuf);

                        const jwk = new PublicKeyInfo({ schema: asn1.result }).toJSON();
                        return this.importJwkPublicKey(session!, jwk, algorithm as EcKeyGenParams, extractable, keyUsages);
                    }
                    case "pkcs8": {
                        const arBuf = new Uint8Array(keyData as Uint8Array).buffer;
                        const asn1 = Asn1Js.fromBER(arBuf);

                        const jwk = new PrivateKeyInfo({ schema: asn1.result }).toJSON();
                        return this.importJwkPrivateKey(session!, jwk, algorithm as EcKeyGenParams, extractable, keyUsages);
                    }
                    default:
                        throw new Error(`Not supported format '${format}'`);
                }
            });
    }

    protected static importJwkPrivateKey(session: Session, jwk: JsonWebKey, algorithm: EcKeyGenParams, extractable: boolean, keyUsages: string[]) {
        return new Promise((resolve, reject) => {
            const namedCurve = this.getNamedCurve(jwk.crv!);
            const template = create_template(session, algorithm, extractable, keyUsages).privateKey;
            template.paramsEC = namedCurve.value;
            template.value = utils.b64_decode(jwk.d!);
            const p11key = session.create(template).toType();
            resolve(new CryptoKey(p11key as any, algorithm));
        });
    }

    protected static importJwkPublicKey(session: Session, jwk: JsonWebKey, algorithm: EcKeyGenParams, extractable: boolean, keyUsages: string[]) {
        return new Promise((resolve, reject) => {
            const namedCurve = this.getNamedCurve(jwk.crv!);
            const template = create_template(session, algorithm, extractable, keyUsages).publicKey;
            template.paramsEC = namedCurve.value;
            const pointEc = EcUtils.encodePoint({ x: utils.b64_decode(jwk.x!), y: utils.b64_decode(jwk.y!) }, namedCurve);
            template.pointEC = pointEc;
            const p11key = session.create(template).toType();
            resolve(new CryptoKey(p11key as any, algorithm));
        });
    }


    protected static async exportJwkPublicKey(key: CryptoKey) {
        const pkey: ITemplate = (key as CryptoKey).key.getAttribute({
            pointEC: null,
        });
        // TODO: lib.dom.d.ts has typedCurve
        const curve = this.getNamedCurve((key.algorithm as EcKeyGenParams).namedCurve);
        const ecPoint = EcUtils.decodePoint(pkey.pointEC!, curve);
        const jwk: JsonWebKey = {
            kty: "EC",
            crv: (key.algorithm as EcKeyGenParams).namedCurve,
            ext: true,
            key_ops: key.usages,
            x: Base64Url.encode(ecPoint.x),
            y: Base64Url.encode(ecPoint.y),
        };
        return jwk;
    }

    protected static async exportJwkPrivateKey(key: CryptoKey) {
        const pkey: ITemplate = key.key.getAttribute({
            value: null,
        });
        const jwk: JsonWebKey = {
            kty: "EC",
            crv: (key.algorithm as EcKeyGenParams).namedCurve,
            ext: true,
            key_ops: key.usages,
            d: Base64Url.encode(pkey.value!),
        };
        return jwk;
    }

    protected static getNamedCurve(name: string): INamedCurve {
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

}

export class Ecdsa extends EcCrypto {

    public static sign(algorithm: EcdsaParams, key: CryptoKey, data: Buffer, session?: Session): PromiseLike<ArrayBuffer> {
        return super.sign.apply(this, arguments)
            .then(() => {
                return new Promise((resolve, reject) => {
                    session!.createSign(this.wc2pk11(algorithm, key.algorithm), key.key).once(data, (err, data2) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data2.buffer);
                        }
                    });
                });
            });
    }

    public static verify(algorithm: EcdsaParams, key: CryptoKey, signature: Buffer, data: Buffer, session?: Session): PromiseLike<boolean> {
        return super.verify.apply(this, arguments)
            .then(() => {
                return new Promise((resolve, reject) => {
                    session!.createVerify(this.wc2pk11(algorithm, key.algorithm), key.key).once(data, signature, (err, data2) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data2);
                        }
                    });
                });
            });
    }

    protected static wc2pk11(alg: EcdsaParams, keyAlg: KeyAlgorithm): IAlgorithm {
        let algName: string;
        switch ((alg.hash as Algorithm).name.toUpperCase()) {
            case "SHA-1":
                algName = "ECDSA_SHA1";
                break;
            case "SHA-224":
                algName = "ECDSA_SHA224";
                break;
            case "SHA-256":
                algName = "ECDSA_SHA256";
                break;
            case "SHA-384":
                algName = "ECDSA_SHA384";
                break;
            case "SHA-512":
                algName = "ECDSA_SHA512";
                break;
            default:
                throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, (alg.hash as Algorithm).name);
        }
        return { name: algName, params: null };
    }

}

export class Ecdh extends EcCrypto {

    public static deriveKey(algorithm: EcdhKeyDeriveParams, baseKey: CryptoKey, derivedKeyType: AesKeyGenParams, extractable: boolean, keyUsages: string[], session?: Session): PromiseLike<CryptoKey> {
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

                    const template = aes.create_template(session!, derivedKeyType, extractable, keyUsages);
                    template.valueLen = derivedKeyType.length >> 3;
                    // derive key
                    session!.deriveKey(
                        {
                            name: "ECDH1_DERIVE",
                            params: new graphene.EcdhParams(
                                EcKdf.NULL,
                                null as any,
                                (algorithm.public as CryptoKey).key.getAttribute({ pointEC: null }).pointEC!, // CKA_EC_POINT
                            ),
                        },
                        baseKey.key,
                        template,
                        (err, key) => {
                            if (err) {
                                reject(err);
                            } else {
                                resolve(new CryptoKey(key, derivedKeyType));
                            }
                        });
                });
            });
    }

    public static deriveBits(algorithm: EcdhKeyDeriveParams, baseKey: CryptoKey, length: number, session?: Session): PromiseLike<ArrayBuffer> {
        return super.deriveBits.apply(this, arguments)
            .then(() => {
                return new Promise((resolve, reject) => {

                    const aesKeyLength = this.getAesKeyLength(length);
                    const template: ITemplate = aes.create_template(session!, { name: "AES-CBC", length: aesKeyLength }, true, ["encrypt"]);
                    template.valueLen = aesKeyLength >> 3;
                    // derive key
                    session!.deriveKey(
                        {
                            name: "ECDH1_DERIVE",
                            params: new graphene.EcdhParams(
                                EcKdf.NULL,
                                null as any,
                                (algorithm.public as CryptoKey).key.getAttribute({ pointEC: null }).pointEC!, // CKA_EC_POINT
                            ),
                        },
                        baseKey.key,
                        template,
                        (err, key) => {
                            if (err) {
                                reject(err);
                            } else {
                                const secretKey = key.toType<graphene.SecretKey>();
                                const value = secretKey.getAttribute({ value: null }).value as Buffer;
                                resolve(value.slice(0, length >> 3));
                            }
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
        [128, 192, 256].forEach((keySize) => {
            const byteLength = length >> 3;
            const byteKeySize = keySize >> 3;
            const calc = byteKeySize / byteLength;
            if (calc >= 1) {
                res = keySize;
            }
        });
        return res;
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
                if (octet) {
                    return data.slice(i);
                } else {
                    octet = true;
                }
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
        const n = (data.length - 1) / 2;
        if (n !== (Math.ceil(curve.size / 8))) {
            throw new Error("Point does not match field size");
        }

        const xb: Buffer = data.slice(1, 1 + n);
        const yb: Buffer = data.slice(n + 1, n + 1 + n);

        return { x: xb, y: yb };
    }

    public static encodePoint(point: IEcPoint, curve: INamedCurve): Buffer {
        // get field size in bytes (rounding up)
        const n = Math.ceil(curve.size / 8);
        const xb = this.trimZeroes(point.x);
        const yb = this.trimZeroes(point.y);
        if ((xb.length > n) || (yb.length > n)) {
            throw new Error("Point coordinates do not match field size");
        }
        const b = Buffer.concat([new Buffer([4]), xb, yb]);

        // ASN1 encode OCTET_STRING
        const octet = Buffer.concat([new Buffer([4]), this.encodeAsn1Length(b.length), b]);
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
        const enc: number[] = [];
        if (length !== (length & 0x7F)) {
            let code = length.toString(16);
            const len = Math.round(code.length / 2);
            enc[0] = len | 0x80;
            if (Math.floor(code.length % 2) > 0) {
                code = "0" + code;
            }
            for (let i = 0; i < code.length; i = i + 2) {
                enc[1 + (i / 2)] = parseInt(code.substring(i, i + 2), 16);
            }
        } else {
            enc[0] = length;
        }
        return new Buffer(enc);
    }
}
