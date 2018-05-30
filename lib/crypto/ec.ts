// Core
import * as webcrypto from "webcrypto-core";
const AlgorithmError = webcrypto.AlgorithmError;
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
const { AlgorithmIdentifier, PrivateKeyInfo, PublicKeyInfo, ECPublicKey, ECPrivateKey } = require("pkijs");

function create_template(session: Session, alg: EcKeyGenParams, extractable: boolean, keyUsages: string[]): ITemplatePair {
    const label = `EC-${alg.namedCurve}`;
    const idKey = utils.GUID(session);
    const keyType = KeyType.ECDSA;
    return {
        privateKey: {
            token: !!process.env.WEBCRYPTO_PKCS11_TOKEN,
            sensitive: !!process.env.WEBCRYPTO_PKCS11_SENSITIVE,
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
            token: !!process.env.WEBCRYPTO_PKCS11_TOKEN,
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

    public static generateKey(algorithm: EcKeyGenParams, extractable: boolean, keyUsages: string[], session?: Session) {
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
                return jwk2pkcs(jwk);
            }
            case "spki": {
                const jwk = await this.exportJwkPublicKey(key);
                return jwk2spki(jwk);
            }
            case "raw": {
                // export subjectPublicKey BIT_STRING value
                const jwk = await this.exportJwkPublicKey(key);
                if ((key.algorithm as EcKeyGenParams).namedCurve === "X25519") {
                    return Base64Url.decode(jwk.x!).buffer as ArrayBuffer;
                } else {
                    const publicKey = new PublicKeyInfo();
                    publicKey.fromJSON(jwk);
                    return publicKey.toSchema(true).valueBlock.value[1].valueBlock.valueHex;
                }
            }
            default:
                throw new Error(`Not supported format '${format}'`);
        }
    }

    public static importKey(format: string, keyData: JsonWebKey | Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[], session?: Session): PromiseLike<CryptoKey> {
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
                        const jwk = spki2jwk(new Uint8Array(keyData as Uint8Array).buffer as ArrayBuffer);
                        return this.importJwkPublicKey(session!, jwk, algorithm as EcKeyGenParams, extractable, keyUsages);
                    }
                    case "pkcs8": {
                        const jwk = pkcs2jwk(new Uint8Array(keyData as Uint8Array).buffer as ArrayBuffer);
                        return this.importJwkPrivateKey(session!, jwk, algorithm as EcKeyGenParams, extractable, keyUsages);
                    }
                    default:
                        throw new Error(`Not supported format '${format}'`);
                }
            });
    }

    protected static importJwkPrivateKey(session: Session, jwk: JsonWebKey, algorithm: EcKeyGenParams, extractable: boolean, keyUsages: string[]) {
        return new Promise((resolve, reject) => {
            const namedCurve = this.getNamedCurve(algorithm.namedCurve);
            const template = create_template(session, algorithm, extractable, keyUsages).privateKey;
            template.paramsEC = namedCurve.value;
            template.value = utils.b64_decode(jwk.d!);
            const p11key = session.create(template).toType();
            resolve(new CryptoKey(p11key as any, algorithm));
        });
    }

    protected static importJwkPublicKey(session: Session, jwk: JsonWebKey, algorithm: EcKeyGenParams, extractable: boolean, keyUsages: string[]) {
        return new Promise((resolve, reject) => {
            const namedCurve = this.getNamedCurve(algorithm.namedCurve);
            const template = create_template(session, algorithm, extractable, keyUsages).publicKey;
            template.paramsEC = namedCurve.value;
            let pointEc: Buffer;
            if (namedCurve.name === "curve25519") {
                pointEc = utils.b64_decode(jwk.x!);
            } else {
                pointEc = EcUtils.encodePoint({ x: utils.b64_decode(jwk.x!), y: utils.b64_decode(jwk.y!) }, namedCurve);
            }
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
        };
        if (curve.name !== "curve25519") {
            jwk.y = Base64Url.encode(ecPoint.y);
        }
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
            case "K-256":
                const p256 = NamedCurve.getByName("secp256r1");
                return {
                    name: "secp256k1",
                    oid: "1.3.132.0.10",
                    value: Buffer.from("06052b8104000A", "hex"),
                    size: p256.size,
                };
            case "P-256":
                namedCurve = "secp256r1";
                break;
            case "P-384":
                namedCurve = "secp384r1";
                break;
            case "P-521":
                namedCurve = "secp521r1";
                break;
            case "X25519":
                namedCurve = "curve25519";
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
                    const mechanism = this.wc2pk11(algorithm, key.algorithm);
                    mechanism.name = this.getAlgorithm(session, mechanism.name);
                    if (mechanism.name === "ECDSA") {
                        data = this.prepareData((algorithm as any).hash.name, data);
                    }
                    session!.createSign(mechanism, key.key).once(data, (err, data2) => {
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
                    const mechanism = this.wc2pk11(algorithm, key.algorithm);
                    mechanism.name = this.getAlgorithm(session, mechanism.name);
                    if (mechanism.name === "ECDSA") {
                        data = this.prepareData((algorithm as any).hash.name, data);
                    }
                    session!.createVerify(mechanism, key.key).once(data, signature, (err, data2) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data2);
                        }
                    });
                });
            });
    }

    public static prepareData(hashAlgorithm: string, data: Buffer) {
        // use nodejs crypto for digest calculating
        return utils.digest(hashAlgorithm.replace("-", ""), data);
    }

    protected static getAlgorithm(session: Session, p11AlgorithmName: string) {
        const mechanisms = session.slot.getMechanisms();
        const ECDSA = "ECDSA";
        for (let i = 0; i < mechanisms.length; i++) {
            const mechanism = mechanisms.items(i);
            if (mechanism.name === ECDSA) {
                return ECDSA;
            }
        }
        return p11AlgorithmName;
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
    y?: Buffer;
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
        if (curve.name === "curve25519") {
            return {
                x: data,
            };
        }

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
        // const xb = this.trimZeroes(point.x);
        // const yb = this.trimZeroes(point.y);
        const xb = this.padZeroes(point.x, n);
        const yb = this.padZeroes(point.y, n);
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

    public static padZeroes(b: Buffer, size: number): Buffer {
        const pad = new Buffer(size - b.length);
        pad.fill(0, 0, pad.length);
        return Buffer.concat([pad, b]);
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

function getCoordinate(b64: string, coordinateLength: number) {
    const buf = Base64Url.decode(b64);
    const offset = coordinateLength - buf.byteLength;
    const res = new Uint8Array(coordinateLength);
    res.set(buf, offset);

    return res.buffer as ArrayBuffer;
}

function jwk2spki(jwk: JsonWebKey) {
    const parsedKey = new ECPublicKey();
    let coordinateLength = 0;

    if ("crv" in jwk) {
        switch (jwk.crv.toUpperCase()) {
            case "K-256":
                parsedKey.namedCurve = "1.3.132.0.10";
                coordinateLength = 32;
                break;
            case "P-256":
                parsedKey.namedCurve = "1.2.840.10045.3.1.7";
                coordinateLength = 32;
                break;
            case "P-384":
                parsedKey.namedCurve = "1.3.132.0.34";
                coordinateLength = 48;
                break;
            case "P-521":
                parsedKey.namedCurve = "1.3.132.0.35";
                coordinateLength = 66;
                break;
            default:
        }
    } else {
        throw new Error("Absent mandatory parameter \"crv\"");
    }

    ["x", "y"].forEach((name) => {
        if (name in jwk) {
            parsedKey[name] = getCoordinate((jwk as any)[name], coordinateLength);
        } else {
            throw new Error(`Absent mandatory parameter '${name}'`);
        }
    });

    const spki = new PublicKeyInfo();
    spki.algorithm = new AlgorithmIdentifier({
        algorithmId: "1.2.840.10045.2.1",
        algorithmParams: new Asn1Js.ObjectIdentifier({ value: parsedKey.namedCurve }),
    });
    spki.subjectPublicKey = new Asn1Js.BitString({ valueHex: parsedKey.toSchema().toBER(false) });

    return spki.toSchema().toBER(false);
}

function spki2jwk(raw: ArrayBuffer): JsonWebKey {
    const asn1Spki = Asn1Js.fromBER(raw);
    const spki = new PublicKeyInfo({ schema: asn1Spki.result });

    if (spki.algorithm.algorithmId !== "1.2.840.10045.2.1") {
        throw new Error("SPKI is not EC public key");
    }

    const algId = spki.algorithm.algorithmParams.valueBlock.toString();
    let crvName = algId;

    switch (crvName) {
        case "1.3.132.0.10": // K-256
            crvName = "K-256";
            break;
        case "1.2.840.10045.3.1.7": // P-256
            crvName = "P-256";
            break;
        case "1.3.132.0.34": // P-384
            crvName = "P-384";
            break;
        case "1.3.132.0.35": // P-521
            crvName = "P-521";
            break;
        default:
            throw new Error(`Unsupported EC named curve '${crvName}'`);
    }

    const parsedKey = new ECPublicKey({
        namedCurve: algId === "1.3.132.0.10" ? "1.2.840.10045.3.1.7" : algId,
        schema: spki.subjectPublicKey.valueBlock.valueHex,
    });

    return {
        kty: "EC",
        crv: crvName,
        x: Base64Url.encode(new Uint8Array(parsedKey.x)),
        y: Base64Url.encode(new Uint8Array(parsedKey.y)),
    };
}

function jwk2pkcs(jwk: JsonWebKey): ArrayBuffer {
    const parsedKey = new ECPrivateKey();
    let coordinateLength = 0;

    if ("crv" in jwk) {
        switch (jwk.crv.toUpperCase()) {
            case "K-256":
                parsedKey.namedCurve = "1.3.132.0.10";
                coordinateLength = 32;
                break;
            case "P-256":
                parsedKey.namedCurve = "1.2.840.10045.3.1.7";
                coordinateLength = 32;
                break;
            case "P-384":
                parsedKey.namedCurve = "1.3.132.0.34";
                coordinateLength = 48;
                break;
            case "P-521":
                parsedKey.namedCurve = "1.3.132.0.35";
                coordinateLength = 66;
                break;
            default:
        }
    } else {
        throw new Error("Absent mandatory parameter \"crv\"");
    }

    ["d"].forEach((name) => {
        if (name in jwk) {
            parsedKey.privateKey = new Asn1Js.OctetString({ valueHex: getCoordinate((jwk as any)[name], coordinateLength) });
        } else {
            throw new Error(`Absent mandatory parameter '${name}'`);
        }
    });

    const pkcs8 = new PrivateKeyInfo();
    pkcs8.privateKeyAlgorithm = new AlgorithmIdentifier({
        algorithmId: "1.2.840.10045.2.1",
        algorithmParams: new Asn1Js.ObjectIdentifier({ value: parsedKey.namedCurve }),
    });
    pkcs8.privateKey = new Asn1Js.OctetString({ valueHex: parsedKey.toSchema().toBER(false) });

    return pkcs8.toSchema().toBER(false);
}

function pkcs2jwk(raw: ArrayBuffer): JsonWebKey {
    const asn1Pkcs8 = Asn1Js.fromBER(raw);
    const pkcs8 = new PrivateKeyInfo({ schema: asn1Pkcs8.result });

    if (pkcs8.privateKeyAlgorithm.algorithmId !== "1.2.840.10045.2.1") {
        throw new Error("PKCS8 is not EC private key");
    }

    const algId = pkcs8.privateKeyAlgorithm.algorithmParams.valueBlock.toString();
    let crvName = algId;

    switch (crvName) {
        case "1.3.132.0.10": // K-256
            crvName = "K-256";
            break;
        case "1.2.840.10045.3.1.7": // P-256
            crvName = "P-256";
            break;
        case "1.3.132.0.34": // P-384
            crvName = "P-384";
            break;
        case "1.3.132.0.35": // P-521
            crvName = "P-521";
            break;
        default:
            throw new Error(`Unsupported EC named curve '${crvName}'`);
    }

    const asn1PrvKey = Asn1Js.fromBER(pkcs8.privateKey.valueBlock.valueHex);

    const parsedKey = new ECPrivateKey({
        namedCurve: algId === "1.3.132.0.10" ? "1.2.840.10045.3.1.7" : algId,
        schema: asn1PrvKey.result,
    });

    return {
        kty: "EC",
        crv: crvName,
        d: Base64Url.encode(new Uint8Array(parsedKey.privateKey.valueBlock.valueHex)),
    };
}
