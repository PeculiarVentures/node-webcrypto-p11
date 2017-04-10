// Core
import * as webcrypto from "webcrypto-core";
const AlgorithmError = webcrypto.AlgorithmError;
const PrepareAlgorithm = webcrypto.PrepareAlgorithm;
const AlgorithmNames = webcrypto.AlgorithmNames;
import * as graphene from "graphene-pk11";

import { ID_DIGEST } from "./const";
import { CryptoKey, CryptoKeyPair } from "./key";

import * as aes from "./crypto/aes";
import * as ec from "./crypto/ec";
import * as rsa from "./crypto/rsa";
import * as sha from "./crypto/sha";

import { BaseCrypto } from "./base";
import * as utils from "./utils";

export class SubtleCrypto extends webcrypto.SubtleCrypto {
    protected session: graphene.Session;

    constructor(session: graphene.Session) {
        super();

        this.session = session;
    }

    public digest(algorithm: AlgorithmIdentifier, data: NodeBufferSource): PromiseLike<ArrayBuffer> {
        return super.digest.apply(this, arguments)
            .then(() => {
                const alg = PrepareAlgorithm(algorithm);
                const data2 = utils.PrepareData(data);
                const algName = alg.name.toLowerCase();
                let AlgClass: typeof BaseCrypto;
                switch (algName) {
                    case "sha-1":
                    case "sha-224":
                    case "sha-256":
                    case "sha-384":
                    case "sha-512":
                        AlgClass = sha.ShaCrypto;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, algName);
                }
                return AlgClass.digest(alg, data2, this.session);
            });
    }

    public generateKey(algorithm: string, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKeyPair | CryptoKey>;
    public generateKey(algorithm: RsaHashedKeyGenParams | EcKeyGenParams | DhKeyGenParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKeyPair>;
    public generateKey(algorithm: AesKeyGenParams | HmacKeyGenParams | Pbkdf2Params, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
    public generateKey(algorithm: any, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKeyPair | CryptoKey> {
        return super.generateKey.apply(this, arguments)
            .then(() => {
                const alg = PrepareAlgorithm(algorithm);

                let AlgClass: typeof BaseCrypto;
                switch (alg.name.toLowerCase()) {
                    case AlgorithmNames.RsaSSA.toLowerCase():
                        AlgClass = rsa.RsaPKCS1;
                        break;
                    case AlgorithmNames.RsaPSS.toLowerCase():
                        AlgClass = rsa.RsaPSS;
                        break;
                    case AlgorithmNames.RsaOAEP.toLowerCase():
                        AlgClass = rsa.RsaOAEP;
                        break;
                    case AlgorithmNames.AesCBC.toLowerCase():
                        AlgClass = aes.AesCBC;
                        break;
                    case AlgorithmNames.AesGCM.toLowerCase():
                        AlgClass = aes.AesGCM;
                        break;
                    case AlgorithmNames.EcDSA.toLowerCase():
                    case AlgorithmNames.EcDH.toLowerCase():
                        AlgClass = ec.EcCrypto;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, alg.name);
                }
                return AlgClass.generateKey(alg as any, extractable, keyUsages, this.session)
                    .then((keys) => {
                        const publicKey = (keys as CryptoKeyPair).publicKey;
                        const privateKey = (keys as CryptoKeyPair).privateKey;
                        if (publicKey) {
                            return this.exportKey("spki", publicKey)
                                .then((spki) => {
                                    const digest = utils.digest(ID_DIGEST, spki);
                                    publicKey.key.id = digest;
                                    publicKey.id = CryptoKey.getID(publicKey.key);
                                    privateKey.key.id = digest;
                                    privateKey.id = CryptoKey.getID(privateKey.key);
                                    return keys;
                                });
                        } else {
                            return keys;
                        }
                    });
            });
    }

    public wrapKey(format: string, key: CryptoKey, wrappingKey: CryptoKey, wrapAlgorithm: AlgorithmIdentifier): PromiseLike<ArrayBuffer> {
        return super.wrapKey.apply(this, arguments)
            .then(() => {
                return this.exportKey(format as any, key)
                    .then((exportedKey) => {
                        let data: Buffer;
                        if (!(exportedKey instanceof ArrayBuffer)) {
                            data = new Buffer(JSON.stringify(exportedKey));
                        } else {
                            data = new Buffer(exportedKey);
                        }
                        return this.encrypt(wrapAlgorithm, wrappingKey, data);
                    });
            });
    }

    public unwrapKey(format: string, wrappedKey: NodeBufferSource, unwrappingKey: CryptoKey, unwrapAlgorithm: AlgorithmIdentifier, unwrappedKeyAlgorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return super.unwrapKey.apply(this, arguments)
            .then(() => {
                return Promise.resolve()
                    .then(() => {
                        return this.decrypt(unwrapAlgorithm, unwrappingKey, wrappedKey);
                    })
                    .then((decryptedKey) => {
                        let keyData: JsonWebKey | Buffer;
                        if (format === "jwk") {
                            keyData = JSON.parse(new Buffer(decryptedKey).toString());
                        } else {
                            keyData = new Buffer(decryptedKey);
                        }
                        return this.importKey(format as any, keyData as Buffer, unwrappedKeyAlgorithm, extractable, keyUsages);
                    });
            });
    }

    public encrypt(algorithm: string | RsaOaepParams | AesCtrParams | AesCbcParams | AesCmacParams | AesGcmParams | AesCfbParams, key: CryptoKey, data: NodeBufferSource): PromiseLike<ArrayBuffer>;
    public encrypt(algorithm: any, key: CryptoKey, data: NodeBufferSource): PromiseLike<ArrayBuffer> {
        return super.encrypt.apply(this, arguments)
            .then(() => {
                const alg = PrepareAlgorithm(algorithm);
                const data2 = utils.PrepareData(data);

                let AlgClass: typeof BaseCrypto;
                switch (alg.name.toLowerCase()) {
                    case AlgorithmNames.RsaOAEP.toLowerCase():
                        AlgClass = rsa.RsaOAEP;
                        break;
                    case AlgorithmNames.AesCBC.toLowerCase():
                        AlgClass = aes.AesCBC;
                        break;
                    case AlgorithmNames.AesGCM.toLowerCase():
                        AlgClass = aes.AesGCM;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, alg.name);
                }
                return AlgClass.encrypt(alg, key, data2, this.session);
            });
    }

    public decrypt(algorithm: string | RsaOaepParams | AesCtrParams | AesCbcParams | AesCmacParams | AesGcmParams | AesCfbParams, key: CryptoKey, data: NodeBufferSource): PromiseLike<ArrayBuffer>;
    public decrypt(algorithm: any, key: CryptoKey, data: NodeBufferSource): PromiseLike<ArrayBuffer> {
        return super.decrypt.apply(this, arguments)
            .then(() => {
                const alg = PrepareAlgorithm(algorithm);
                const data2 = utils.PrepareData(data);

                let AlgClass: typeof BaseCrypto;
                switch (alg.name.toLowerCase()) {
                    case AlgorithmNames.RsaOAEP.toLowerCase():
                        AlgClass = rsa.RsaOAEP;
                        break;
                    case AlgorithmNames.AesCBC.toLowerCase():
                        AlgClass = aes.AesCBC;
                        break;
                    case AlgorithmNames.AesGCM.toLowerCase():
                        AlgClass = aes.AesGCM;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, alg.name);
                }
                return AlgClass.decrypt(alg, key, data2, this.session);
            });
    }

    public exportKey(format: "jwk", key: CryptoKey): PromiseLike<JsonWebKey>;
    public exportKey(format: "raw" | "pkcs8" | "spki", key: CryptoKey): PromiseLike<ArrayBuffer>;
    public exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer>;
    public exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer> {
        return super.exportKey.apply(this, arguments)
            .then(() => {
                let AlgClass: typeof BaseCrypto;
                switch (key.algorithm.name!.toLowerCase()) {
                    case AlgorithmNames.RsaSSA.toLowerCase():
                        AlgClass = rsa.RsaPKCS1;
                        break;
                    case AlgorithmNames.RsaPSS.toLowerCase():
                        AlgClass = rsa.RsaPSS;
                        break;
                    case AlgorithmNames.RsaOAEP.toLowerCase():
                        AlgClass = rsa.RsaOAEP;
                        break;
                    case AlgorithmNames.AesCBC.toLowerCase():
                        AlgClass = aes.AesCBC;
                        break;
                    case AlgorithmNames.AesGCM.toLowerCase():
                        AlgClass = aes.AesGCM;
                        break;
                    case AlgorithmNames.EcDSA.toLowerCase():
                    case AlgorithmNames.EcDH.toLowerCase():
                        AlgClass = ec.EcCrypto;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, key.algorithm.name);
                }
                return AlgClass.exportKey(format, key, this.session);
            });
    }

    public importKey(format: "jwk", keyData: JsonWebKey, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
    public importKey(format: "raw" | "pkcs8" | "spki", keyData: NodeBufferSource, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
    public importKey(format: string, keyData: JsonWebKey | NodeBufferSource, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
    public importKey(format: string, keyData: JsonWebKey | NodeBufferSource, algorithm: any, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return super.importKey.apply(this, arguments)
            .then(() => {
                const alg = PrepareAlgorithm(algorithm as string);

                let data = keyData;
                if (format !== "jwk") {
                    data = utils.PrepareData(data as NodeBufferSource);
                }

                let AlgClass: typeof BaseCrypto;
                switch (alg.name.toLowerCase()) {
                    case AlgorithmNames.RsaSSA.toLowerCase():
                        AlgClass = rsa.RsaPKCS1;
                        break;
                    case AlgorithmNames.RsaPSS.toLowerCase():
                        AlgClass = rsa.RsaPSS;
                        break;
                    case AlgorithmNames.RsaOAEP.toLowerCase():
                        AlgClass = rsa.RsaOAEP;
                        break;
                    case AlgorithmNames.AesCBC.toLowerCase():
                        AlgClass = aes.AesCBC;
                        break;
                    case AlgorithmNames.AesGCM.toLowerCase():
                        AlgClass = aes.AesGCM;
                        break;
                    case AlgorithmNames.EcDSA.toLowerCase():
                    case AlgorithmNames.EcDH.toLowerCase():
                        AlgClass = ec.EcCrypto;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, alg.name);
                }
                return AlgClass.importKey(format, data, alg, extractable, keyUsages, this.session)
                    .then((key) => {
                        // update key id for type 'public'
                        if (key.type === "public") {
                            return this.exportKey("spki", key)
                                .then((spki) => {
                                    const digest = utils.digest(ID_DIGEST, spki);
                                    key.key.id = digest;
                                    key.id = CryptoKey.getID(key.key);
                                    return key;
                                });
                        } else {
                            return key;
                        }
                    });
            });
    }

    public sign(algorithm: string | RsaPssParams | EcdsaParams | AesCmacParams, key: CryptoKey, data: NodeBufferSource): PromiseLike<ArrayBuffer>;
    public sign(algorithm: any, key: CryptoKey, data: NodeBufferSource): PromiseLike<ArrayBuffer> {
        return super.sign.apply(this, arguments)
            .then(() => {
                const alg = PrepareAlgorithm(algorithm as string);
                const data2 = utils.PrepareData(data);

                let AlgClass: typeof BaseCrypto;
                switch (alg.name.toLowerCase()) {
                    case AlgorithmNames.RsaSSA.toLowerCase():
                        AlgClass = rsa.RsaPKCS1;
                        break;
                    case AlgorithmNames.RsaPSS.toLowerCase():
                        AlgClass = rsa.RsaPSS;
                        break;
                    case AlgorithmNames.EcDSA.toLowerCase():
                        AlgClass = ec.Ecdsa;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, alg.name);
                }
                return AlgClass.sign(alg as any, key, data2, this.session);
            });
    }

    public verify(algorithm: string | RsaPssParams | EcdsaParams | AesCmacParams, key: CryptoKey, signature: NodeBufferSource, data: NodeBufferSource): PromiseLike<boolean>;
    public verify(algorithm: any, key: CryptoKey, signature: NodeBufferSource, data: NodeBufferSource): PromiseLike<boolean> {
        return super.verify.apply(this, arguments)
            .then(() => {
                const alg = PrepareAlgorithm(algorithm as string);
                const signature2 = utils.PrepareData(signature);
                const data2 = utils.PrepareData(data);

                let AlgClass: typeof BaseCrypto;
                switch (alg.name.toLowerCase()) {
                    case AlgorithmNames.RsaSSA.toLowerCase():
                        AlgClass = rsa.RsaPKCS1;
                        break;
                    case AlgorithmNames.RsaPSS.toLowerCase():
                        AlgClass = rsa.RsaPSS;
                        break;
                    case AlgorithmNames.EcDSA.toLowerCase():
                        AlgClass = ec.Ecdsa;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, alg.name);
                }
                return AlgClass.verify(alg as any, key, signature2, data2, this.session);
            });
    }

    public deriveKey(algorithm: string | EcdhKeyDeriveParams | DhKeyDeriveParams | ConcatParams | HkdfCtrParams | Pbkdf2Params, baseKey: CryptoKey, derivedKeyType: string | AesDerivedKeyParams | HmacImportParams | ConcatParams | HkdfCtrParams | Pbkdf2Params, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
    public deriveKey(algorithm: any, baseKey: CryptoKey, derivedKeyType: any, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return super.deriveKey.apply(this, arguments)
            .then(() => {
                const alg = PrepareAlgorithm(algorithm);
                const derivedKeyType2 = PrepareAlgorithm(derivedKeyType);

                let AlgClass: typeof BaseCrypto;
                switch (alg.name.toLowerCase()) {
                    case AlgorithmNames.EcDH.toLowerCase():
                        AlgClass = ec.Ecdh;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, alg.name);
                }
                return AlgClass.deriveKey(alg as any, baseKey, derivedKeyType2, extractable, keyUsages, this.session);
            });
    }

    public deriveBits(algorithm: string | EcdhKeyDeriveParams | DhKeyDeriveParams | ConcatParams | HkdfCtrParams | Pbkdf2Params, baseKey: CryptoKey, length: number): PromiseLike<ArrayBuffer>;
    public deriveBits(algorithm: any, baseKey: CryptoKey, length: number): PromiseLike<ArrayBuffer> {
        return super.deriveBits.apply(this, arguments)
            .then(() => {
                const alg = PrepareAlgorithm(algorithm);

                let AlgClass: typeof BaseCrypto;
                switch (alg.name.toLowerCase()) {
                    case AlgorithmNames.EcDH.toLowerCase():
                        AlgClass = ec.Ecdh;
                        break;
                    default:
                        throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, alg.name);
                }
                return AlgClass.deriveBits(alg as any, baseKey, length, this.session);
            });
    }

}
