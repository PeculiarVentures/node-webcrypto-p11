// Core
import * as webcrypto from "webcrypto-core";
const WebCryptoError = webcrypto.WebCryptoError;
const AlgorithmError = webcrypto.AlgorithmError;
const Base64Url = webcrypto.Base64Url;

import {
    IAlgorithm,
    ITemplate,
    KeyGenMechanism,
    KeyType,
    MechanismEnum,
    ObjectClass,
    PrivateKey,
    PublicKey,
    RsaMgf,
    Session,
} from "graphene-pk11";
import * as graphene from "graphene-pk11";

import { BaseCrypto } from "../base";
import { CryptoKey, ITemplatePair } from "../key";
import * as utils from "../utils";
// import * as aes from "./aes";

import * as Asn1Js from "asn1js";
const { PrivateKeyInfo, PublicKeyInfo } = require("pkijs");

const HASH_PREFIXES: { [alg: string]: Buffer } = {
    "sha-1": new Buffer([0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14]),
    "sha-256": new Buffer([0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]),
    "sha-384": new Buffer([0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30]),
    "sha-512": new Buffer([0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40]),
};

function create_template(session: Session, alg: RsaHashedKeyGenParams, extractable: boolean, keyUsages: string[]): ITemplatePair {
    const label = `RSA-${alg.modulusLength}`;
    const idKey = new Buffer(utils.GUID(session));
    return {
        privateKey: {
            token: !!process.env["WEBCRYPTO_PKCS11_TOKEN"],
            sensitive: !!process.env["WEBCRYPTO_PKCS11_SENSITIVE"],
            class: ObjectClass.PRIVATE_KEY,
            keyType: KeyType.RSA,
            private: true,
            label,
            id: idKey,
            extractable,
            derive: false,
            sign: keyUsages.indexOf("sign") > -1,
            decrypt: keyUsages.indexOf("decrypt") > -1,
            unwrap: keyUsages.indexOf("unwrapKey") > -1,
        },
        publicKey: {
            token: !!process.env["WEBCRYPTO_PKCS11_TOKEN"],
            class: ObjectClass.PUBLIC_KEY,
            keyType: KeyType.RSA,
            label,
            id: idKey,
            verify: keyUsages.indexOf("verify") > -1,
            encrypt: keyUsages.indexOf("encrypt") > -1,
            wrap: keyUsages.indexOf("wrapKey") > -1,
        },
    };
}

export abstract class RsaCrypto extends BaseCrypto {

    public static generateKey(algorithm: RsaHashedKeyGenParams, extractable: boolean, keyUsages: string[], session?: Session): PromiseLike<CryptoKeyPair> {
        return super.generateKey.apply(this, arguments)
            .then(() => {
                return new Promise((resolve, reject) => {
                    const size = algorithm.modulusLength;
                    const exp = new Buffer(algorithm.publicExponent);

                    const template = create_template(session!, algorithm as any, extractable, keyUsages);

                    // RSA params
                    template.publicKey.publicExponent = exp;
                    template.publicKey.modulusBits = size;

                    // PKCS11 generation
                    session!.generateKeyPair(KeyGenMechanism.RSA, template.publicKey, template.privateKey, (err, keys) => {
                        try {
                            if (err) {
                                reject(new WebCryptoError(`Rsa: Can not generate new key\n${err.message}`));
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
        await super.exportKey.call(this, format, key, session);
        switch (format.toLowerCase()) {
            case "jwk":
                if (key.type === "private") {
                    return this.exportJwkPrivateKey(key);
                } else {
                    return this.exportJwkPublicKey(key);
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
                    case "jwk":
                        const jwk: any = keyData;
                        if (jwk.d) {
                            return this.importJwkPrivateKey(session!, jwk, algorithm as RsaHashedKeyGenParams, extractable, keyUsages);
                        } else {
                            return this.importJwkPublicKey(session!, jwk, algorithm as RsaHashedKeyGenParams, extractable, keyUsages);
                        }
                    case "spki": {
                        const arBuf = new Uint8Array(keyData as Uint8Array).buffer;
                        const asn1 = Asn1Js.fromBER(arBuf);

                        const jwk = new PublicKeyInfo({ schema: asn1.result }).toJSON();
                        return this.importJwkPublicKey(session!, jwk, algorithm as RsaHashedKeyGenParams, extractable, keyUsages);
                    }
                    case "pkcs8": {
                        const arBuf = new Uint8Array(keyData as Uint8Array).buffer;
                        const asn1 = Asn1Js.fromBER(arBuf);

                        const jwk = new PrivateKeyInfo({ schema: asn1.result }).toJSON();
                        return this.importJwkPrivateKey(session!, jwk, algorithm as RsaHashedKeyGenParams, extractable, keyUsages);
                    }
                    default:
                        throw new Error(`Not supported format '${format}'`);
                }
            });
    }

    protected static jwkAlgName(alg: RsaHashedKeyAlgorithm): string {
        throw new WebCryptoError(WebCryptoError.NOT_SUPPORTED);
    }

    protected static async exportJwkPublicKey(key: CryptoKey) {
        const pkey: ITemplate = key.key.getAttribute({
            publicExponent: null,
            modulus: null,
        });
        const alg = this.jwkAlgName(key.algorithm as RsaHashedKeyAlgorithm);
        const jwk: JsonWebKey = {
            kty: "RSA",
            alg,
            ext: true,
            key_ops: key.usages,
            e: Base64Url.encode(pkey.publicExponent as Uint8Array),
            n: Base64Url.encode(pkey.modulus as Uint8Array),
        };
        return jwk;
    }

    protected static async exportJwkPrivateKey(key: CryptoKey) {
        const pkey: ITemplate = key.key.getAttribute({
            publicExponent: null,
            modulus: null,
            privateExponent: null,
            prime1: null,
            prime2: null,
            exp1: null,
            exp2: null,
            coefficient: null,
        });
        const alg = this.jwkAlgName(key.algorithm as RsaHashedKeyAlgorithm);
        const jwk: JsonWebKey = {
            kty: "RSA",
            alg,
            ext: true,
            key_ops: key.usages,
            e: Base64Url.encode(pkey.publicExponent as Uint8Array),
            n: Base64Url.encode(pkey.modulus as Uint8Array),
            d: Base64Url.encode(pkey.privateExponent as Uint8Array),
            p: Base64Url.encode(pkey.prime1 as Uint8Array),
            q: Base64Url.encode(pkey.prime2 as Uint8Array),
            dp: Base64Url.encode(pkey.exp1 as Uint8Array),
            dq: Base64Url.encode(pkey.exp2 as Uint8Array),
            qi: Base64Url.encode(pkey.coefficient as Uint8Array),
        };
        return jwk;
    }

    protected static importJwkPrivateKey(session: Session, jwk: JsonWebKey, algorithm: RsaHashedKeyGenParams, extractable: boolean, keyUsages: string[]) {
        return Promise.resolve()
            .then(() => {
                const template = create_template(session, algorithm, extractable, keyUsages).privateKey;
                template.publicExponent = utils.b64_decode(jwk.e!);
                template.modulus = utils.b64_decode(jwk.n!);
                template.privateExponent = utils.b64_decode(jwk.d!);
                template.prime1 = utils.b64_decode(jwk.p!);
                template.prime2 = utils.b64_decode(jwk.q!);
                template.exp1 = utils.b64_decode(jwk.dp!);
                template.exp2 = utils.b64_decode(jwk.dq!);
                template.coefficient = utils.b64_decode(jwk.qi!);
                const p11key = session.create(template).toType<PrivateKey>();
                return new CryptoKey(p11key, algorithm);
            });
    }

    protected static importJwkPublicKey(session: Session, jwk: JsonWebKey, algorithm: RsaHashedKeyGenParams, extractable: boolean, keyUsages: string[]) {
        return new Promise((resolve, reject) => {
            const template = create_template(session, algorithm, extractable, keyUsages).publicKey;
            template.publicExponent = utils.b64_decode(jwk.e!);
            template.modulus = utils.b64_decode(jwk.n!);
            const p11key = session.create(template).toType<PublicKey>();
            resolve(new CryptoKey(p11key, algorithm));
        });
    }

}

export class RsaPKCS1 extends RsaCrypto {

    public static sign(algorithm: Algorithm, key: CryptoKey, data: Buffer, session?: Session): PromiseLike<ArrayBuffer> {
        return super.sign.apply(this, arguments)
            .then(() => {
                return new Promise((resolve, reject) => {
                    const mechanism = this.wc2pk11(algorithm, key.algorithm);
                    mechanism.name = this.rsaPkcs(session, mechanism.name);
                    if (mechanism.name === "RSA_PKCS") {
                        data = this.rsaPkcsPrepareData((key as any).algorithm.hash.name, data);
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

    public static verify(algorithm: Algorithm, key: CryptoKey, signature: Buffer, data: Buffer, session?: Session): PromiseLike<boolean> {
        return super.verify.apply(this, arguments)
            .then(() => {
                return new Promise((resolve, reject) => {
                    const mechanism = this.wc2pk11(algorithm, key.algorithm);
                    mechanism.name = this.rsaPkcs(session, mechanism.name);
                    if (mechanism.name === "RSA_PKCS") {
                        data = this.rsaPkcsPrepareData((key as any).algorithm.hash.name, data);
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

    public static rsaPkcsPrepareData(hashAlgorithm: string, data: Buffer) {
        // use nodejs crypto for digest calculating
        const hash = utils.digest(hashAlgorithm.replace("-", ""), data);

        // enveloping hash
        const hashPrefix = HASH_PREFIXES[hashAlgorithm.toLowerCase()];
        if (!hashPrefix) {
            throw new Error(`Cannot get prefix for hash '${hashAlgorithm}'`);
        }
        return Buffer.concat([hashPrefix, hash]);
    }

    protected static rsaPkcs(session: Session, p11AlgorithmName: string) {
        const mechanisms = session.slot.getMechanisms();
        let res = "RSA_PKCS";
        for (let i = 0; i < mechanisms.length; i++) {
            const mechanism = mechanisms.items(i);
            if (mechanism.name === p11AlgorithmName) {
                res = p11AlgorithmName;
                break;
            }
        }
        return res;
    }

    protected static wc2pk11(alg: Algorithm, keyAlg: KeyAlgorithm): IAlgorithm {
        let res: string;
        switch ((keyAlg as any).hash.name.toUpperCase()) {
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
                throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, (keyAlg as any).hash.name);
        }
        return { name: res, params: null };
    }

    protected static jwkAlgName(alg: RsaHashedKeyAlgorithm): string {
        const algName = /(\d+)$/.exec((alg as any).hash.name)![1];
        return `RS${algName === "1" ? "" : algName}`;
    }

}

export class RsaPSS extends RsaPKCS1 {

    protected static jwkAlgName(alg: RsaHashedKeyAlgorithm): string {
        const algName = /(\d+)$/.exec((alg as any).hash.name)![1];
        return `RP${algName === "1" ? "" : algName}`;
    }

    protected static wc2pk11(alg: Algorithm, keyAlg: Algorithm): IAlgorithm {
        let mech: string;
        let param: graphene.RsaPssParams;
        const saltLen = (alg as any).saltLength;
        switch ((keyAlg as any).hash.name.toUpperCase()) {
            case "SHA-1":
                mech = "SHA1_RSA_PKCS_PSS";
                param = new graphene.RsaPssParams(MechanismEnum.SHA1, RsaMgf.MGF1_SHA1, saltLen);
                break;
            case "SHA-224":
                mech = "SHA224_RSA_PKCS_PSS";
                param = new graphene.RsaPssParams(MechanismEnum.SHA224, RsaMgf.MGF1_SHA224, saltLen);
                break;
            case "SHA-256":
                mech = "SHA256_RSA_PKCS_PSS";
                param = new graphene.RsaPssParams(MechanismEnum.SHA256, RsaMgf.MGF1_SHA256, saltLen);
                break;
            case "SHA-384":
                mech = "SHA384_RSA_PKCS_PSS";
                param = new graphene.RsaPssParams(MechanismEnum.SHA384, RsaMgf.MGF1_SHA384, saltLen);
                break;
            case "SHA-512":
                mech = "SHA512_RSA_PKCS_PSS";
                param = new graphene.RsaPssParams(MechanismEnum.SHA512, RsaMgf.MGF1_SHA512, saltLen);
                break;
            default:
                throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, (keyAlg as any).hash.name);
        }
        return { name: mech, params: param };
    }
}

export class RsaOAEP extends RsaCrypto {

    public static encrypt(algorithm: Algorithm, key: CryptoKey, data: Buffer, session?: Session): PromiseLike<ArrayBuffer> {
        return super.encrypt.apply(this, arguments)
            .then(() => {
                return new Promise((resolve, reject) => {
                    session!.createCipher(this.wc2pk11(algorithm, key.algorithm), key.key).once(data, new Buffer((key.algorithm as RsaHashedKeyAlgorithm).modulusLength >> 3), (err, data2) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data2.buffer);
                        }
                    });
                });
            });
    }

    public static decrypt(algorithm: Algorithm, key: CryptoKey, data: Buffer, session?: Session): PromiseLike<ArrayBuffer> {
        return super.decrypt.apply(this, arguments)
            .then(() => {
                return new Promise((resolve, reject) => {
                    session!.createDecipher(this.wc2pk11(algorithm, key.algorithm), key.key).once(data, new Buffer((key.algorithm as RsaHashedKeyAlgorithm).modulusLength >> 3), (err, data2) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data2.buffer);
                        }
                    });
                });
            });
    }

    protected static jwkAlgName(alg: RsaHashedKeyAlgorithm): string {
        const algName = /(\d+)$/.exec((alg as any).hash.name)![1];
        return `RSA-OAEP${algName === "1" ? "" : ("-" + algName)}`;
    }

    protected static wc2pk11(alg: Algorithm, keyAlg: KeyAlgorithm): IAlgorithm {
        let params: graphene.RsaOaepParams;
        const sourceData = (alg as RsaOaepParams).label ? new Buffer((alg as RsaOaepParams).label as Uint8Array) : undefined;
        switch ((keyAlg as any).hash.name.toUpperCase()) {
            case "SHA-1":
                params = new graphene.RsaOaepParams(MechanismEnum.SHA1, RsaMgf.MGF1_SHA1, sourceData);
                break;
            case "SHA-224":
                params = new graphene.RsaOaepParams(MechanismEnum.SHA224, RsaMgf.MGF1_SHA224, sourceData);
                break;
            case "SHA-256":
                params = new graphene.RsaOaepParams(MechanismEnum.SHA256, RsaMgf.MGF1_SHA256, sourceData);
                break;
            case "SHA-384":
                params = new graphene.RsaOaepParams(MechanismEnum.SHA384, RsaMgf.MGF1_SHA384, sourceData);
                break;
            case "SHA-512":
                params = new graphene.RsaOaepParams(MechanismEnum.SHA512, RsaMgf.MGF1_SHA512, sourceData);
                break;
            default:
                throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, (keyAlg as any).hash.name);
        }
        const res = { name: "RSA_PKCS_OAEP", params };
        return res;
    }

}
