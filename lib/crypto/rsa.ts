// Core
import * as webcrypto from "webcrypto-core";
const WebCryptoError = webcrypto.WebCryptoError;
const AlgorithmError = webcrypto.AlgorithmError;
const Base64Url = webcrypto.Base64Url;

import {
    Session,
    IAlgorithm,
    KeyGenMechanism,
    MechanismEnum,
    ITemplate,
    ObjectClass,
    KeyType,
    RsaMgf,
    PublicKey,
    PrivateKey,
} from "graphene-pk11";
import * as graphene from "graphene-pk11";


import { ITemplatePair, CryptoKey } from "../key";
import { BaseCrypto } from "../base";
import * as utils from "../utils";
// import * as aes from "./aes";


function create_template(session: Session, alg: RsaHashedKeyGenParams, extractable: boolean, keyUsages: string[]): ITemplatePair {
    const label = `RSA-${alg.modulusLength}`;
    const id_pk = new Buffer(utils.GUID(session));
    const id_pubk = new Buffer(utils.GUID(session));
    return {
        privateKey: {
            token: !!process.env["WEBCRYPTO_PKCS11_TOKEN"],
            sensitive: !!process.env["WEBCRYPTO_PKCS11_SENSITIVE"],
            class: ObjectClass.PRIVATE_KEY,
            keyType: KeyType.RSA,
            private: true,
            label: label,
            id: id_pk,
            extractable: extractable,
            derive: false,
            sign: keyUsages.indexOf("sign") > -1,
            decrypt: keyUsages.indexOf("decrypt") > -1,
            unwrap: keyUsages.indexOf("unwrapKey") > -1
        },
        publicKey: {
            token: !!process.env["WEBCRYPTO_PKCS11_TOKEN"],
            class: ObjectClass.PUBLIC_KEY,
            keyType: KeyType.RSA,
            label: label,
            id: id_pubk,
            verify: keyUsages.indexOf("verify") > -1,
            encrypt: keyUsages.indexOf("encrypt") > -1,
            wrap: keyUsages.indexOf("wrapKey") > -1,
        }
    };
}

export abstract class RsaCrypto extends BaseCrypto {

    static generateKey(algorithm: RsaHashedKeyGenParams, extractable: boolean, keyUsages: string[], session?: Session): PromiseLike<CryptoKeyPair> {
        return (super.generateKey.apply(this, arguments) as PromiseLike<CryptoKeyPair>)
            .then(() => {
                return new Promise((resolve, reject) => {
                    let size = algorithm.modulusLength;
                    let exp = new Buffer(algorithm.publicExponent);

                    let template = create_template(session!, algorithm as any, extractable, keyUsages);

                    // RSA params
                    template.publicKey.publicExponent = exp;
                    template.publicKey.modulusBits = size;

                    // PKCS11 generation
                    session!.generateKeyPair(KeyGenMechanism.RSA, template.publicKey, template.privateKey, (err, keys) => {
                        try {
                            if (err) {
                                reject(new WebCryptoError(`Rsa: Can not generate new key\n${err.message}`));
                            }
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

    protected static jwkAlgName(alg: RsaHashedKeyAlgorithm): string {
        throw new WebCryptoError(WebCryptoError.NOT_SUPPORTED);
    }

    protected static exportJwkPublicKey(key: CryptoKey) {
        return new Promise((resolve, reject) => {
            let pkey: ITemplate = (<CryptoKey>key).key.getAttribute({
                publicExponent: null,
                modulus: null
            });
            let alg = this.jwkAlgName(key.algorithm as RsaHashedKeyAlgorithm);
            let jwk: JsonWebKey = {
                kty: "RSA",
                alg: alg,
                ext: true,
                key_ops: key.usages,
                e: Base64Url.encode(pkey.publicExponent as Uint8Array),
                n: Base64Url.encode(pkey.modulus as Uint8Array)
            };
            resolve(jwk);
        });
    }

    protected static exportJwkPrivateKey(key: CryptoKey) {
        return new Promise((resolve, reject) => {
            let pkey: ITemplate = key.key.getAttribute({
                publicExponent: null,
                modulus: null,
                privateExponent: null,
                prime1: null,
                prime2: null,
                exp1: null,
                exp2: null,
                coefficient: null
            });
            let alg = this.jwkAlgName(key.algorithm as RsaHashedKeyAlgorithm);
            let jwk: JsonWebKey = {
                kty: "RSA",
                alg: alg,
                ext: true,
                key_ops: key.usages,
                e: Base64Url.encode(pkey.publicExponent as Uint8Array),
                n: Base64Url.encode(pkey.modulus as Uint8Array),
                d: Base64Url.encode(pkey.privateExponent as Uint8Array),
                p: Base64Url.encode(pkey.prime1 as Uint8Array),
                q: Base64Url.encode(pkey.prime2 as Uint8Array),
                dp: Base64Url.encode(pkey.exp1 as Uint8Array),
                dq: Base64Url.encode(pkey.exp2 as Uint8Array),
                qi: Base64Url.encode(pkey.coefficient as Uint8Array)
            };
            resolve(jwk);
        });
    }

    static exportKey(format: string, key: CryptoKey, session?: Session): PromiseLike<JsonWebKey | ArrayBuffer> {
        return super.exportKey.apply(this, arguments)
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

    static importJwkPrivateKey(session: Session, jwk: JsonWebKey, algorithm: RsaHashedKeyGenParams, extractable: boolean, keyUsages: string[]) {
        return new Promise((resolve, reject) => {
            let template = create_template(session, algorithm, extractable, keyUsages).privateKey;
            template.publicExponent = utils.b64_decode(jwk.e!);
            template.modulus = utils.b64_decode(jwk.n!);
            template.privateExponent = utils.b64_decode(jwk.d!);
            template.prime1 = utils.b64_decode(jwk.p!);
            template.prime2 = utils.b64_decode(jwk.q!);
            template.exp1 = utils.b64_decode(jwk.dp!);
            template.exp2 = utils.b64_decode(jwk.dq!);
            template.coefficient = utils.b64_decode(jwk.qi!);
            let p11key = session.create(template).toType<PrivateKey>();
            resolve(new CryptoKey(p11key, algorithm));
        });
    }

    static importJwkPublicKey(session: Session, jwk: JsonWebKey, algorithm: RsaHashedKeyGenParams, extractable: boolean, keyUsages: string[]) {
        return new Promise((resolve, reject) => {
            let template = create_template(session, algorithm, extractable, keyUsages).publicKey;
            template.publicExponent = utils.b64_decode(jwk.e!);
            template.modulus = utils.b64_decode(jwk.n!);
            let p11key = session.create(template).toType<PublicKey>();
            resolve(new CryptoKey(p11key, algorithm));
        });
    }

    static importKey(format: string, keyData: JsonWebKey | BufferSource, algorithm: Algorithm, extractable: boolean, keyUsages: string[], session?: Session): PromiseLike<CryptoKey> {
        return super.importKey.apply(this, arguments)
            .then(() => {
                switch (format.toLowerCase()) {
                    case "jwk":
                        let jwk: any = keyData;
                        if (jwk.d)
                            return this.importJwkPrivateKey(session!, jwk, algorithm as RsaHashedKeyGenParams, extractable, keyUsages);
                        else
                            return this.importJwkPublicKey(session!, jwk, algorithm as RsaHashedKeyGenParams, extractable, keyUsages);
                    default:
                        throw new Error(`Not supported format '${format}'`);
                }
            });
    }

}

export class RsaPKCS1 extends RsaCrypto {

    static wc2pk11(alg: Algorithm, keyAlg: KeyAlgorithm): IAlgorithm {
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
        let algName = /(\d+)$/.exec((alg as any).hash.name) ![1];
        return `RS${algName === "1" ? "" : algName}`;
    }

    static sign(algorithm: Algorithm, key: CryptoKey, data: Buffer, session?: Session): PromiseLike<ArrayBuffer> {
        return super.sign.apply(this, arguments)
            .then(() => {
                return new Promise((resolve, reject) => {
                    session!.createSign(this.wc2pk11(algorithm, key.algorithm), key.key).once(data, (err, data) => {
                        if (err) reject(err);
                        else resolve(data.buffer);
                    });
                });
            });
    }

    static verify(algorithm: Algorithm, key: CryptoKey, signature: Buffer, data: Buffer, session?: Session): PromiseLike<boolean> {
        return super.verify.apply(this, arguments)
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

export class RsaPSS extends RsaPKCS1 {
    protected static jwkAlgName(alg: RsaHashedKeyAlgorithm): string {
        let algName = /(\d+)$/.exec((alg as any).hash.name) ![1];
        return `RP${algName === "1" ? "" : algName}`;
    }

    static wc2pk11(alg: Algorithm, keyAlg: Algorithm): IAlgorithm {
        let mech: string;
        let param: graphene.RsaPssParams;
        let saltLen = (alg as any).saltLength;
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

    protected static jwkAlgName(alg: RsaHashedKeyAlgorithm): string {
        let algName = /(\d+)$/.exec((alg as any).hash.name) ![1];
        return `RSA-OAEP${algName === "1" ? "" : ("-" + algName)}`;
    }

    static wc2pk11(alg: Algorithm, keyAlg: KeyAlgorithm): IAlgorithm {
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
        let res = { name: "RSA_PKCS_OAEP", params: params };
        return res;
    }

    static encrypt(algorithm: Algorithm, key: CryptoKey, data: Buffer, session?: Session): PromiseLike<ArrayBuffer> {
        return super.encrypt.apply(this, arguments)
            .then(() => {
                return new Promise((resolve, reject) => {
                    session!.createCipher(this.wc2pk11(algorithm, key.algorithm), key.key).once(data, new Buffer((key.algorithm as RsaHashedKeyAlgorithm).modulusLength >> 3), (err, data) => {
                        if (err) reject(err);
                        else resolve(data.buffer);
                    });
                });
            });
    }

    static decrypt(algorithm: Algorithm, key: CryptoKey, data: Buffer, session?: Session): PromiseLike<ArrayBuffer> {
        return super.decrypt.apply(this, arguments)
            .then(() => {
                return new Promise((resolve, reject) => {
                    session!.createDecipher(this.wc2pk11(algorithm, key.algorithm), key.key).once(data, new Buffer((key.algorithm as RsaHashedKeyAlgorithm).modulusLength >> 3), (err, data) => {
                        if (err) reject(err);
                        else resolve(data.buffer);
                    });
                });
            });
    }
}
