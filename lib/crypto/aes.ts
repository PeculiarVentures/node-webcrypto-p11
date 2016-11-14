// Core
import * as webcrypto from "webcrypto-core";
const WebCryptoError = webcrypto.WebCryptoError;
const Base64Url = webcrypto.Base64Url;

import { Session, IAlgorithm, SecretKey, KeyGenMechanism, ITemplate, ObjectClass, KeyType } from "graphene-pk11";
import * as graphene from "graphene-pk11";

import * as utils from "../utils";
import { CryptoKey } from "../key";
import { BaseCrypto } from "../base";

export function create_template(session: Session, alg: AesKeyGenParams, extractable: boolean, keyUsages: string[]): ITemplate {

    let id = utils.GUID(session);
    return {
        token: !!process.env["WEBCRYPTO_PKCS11_TOKEN"],
        sensitive: !!process.env["WEBCRYPTO_PKCS11_SENSITIVE"],
        class: ObjectClass.SECRET_KEY,
        keyType: KeyType.AES,
        label: `AES-${alg.length}`,
        id: new Buffer(id),
        extractable: extractable,
        derive: false,
        sign: keyUsages.indexOf("sign") !== -1,
        verify: keyUsages.indexOf("verify") !== -1,
        encrypt: keyUsages.indexOf("encrypt") !== -1,
        decrypt: keyUsages.indexOf("decrypt") !== -1,
        wrap: keyUsages.indexOf("wrapKey") !== -1,
        unwrap: keyUsages.indexOf("unwrapKey") !== -1,
    };
}

export abstract class AesCrypto extends BaseCrypto {

    static generateKey(algorithm: AesKeyGenParams, extractable: boolean, keyUsages: string[], session?: Session): PromiseLike<CryptoKey> {
        return (super.generateKey.apply(this, arguments) as PromiseLike<CryptoKeyPair>)
            .then(() => {
                return new Promise((resolve, reject) => {
                    let template = create_template(session!, algorithm, extractable, keyUsages);
                    template.valueLen = algorithm.length >> 3,

                    // PKCS11 generation
                    session!.generateKey(KeyGenMechanism.AES, template, (err, aesKey) => {
                        try {
                            if (err) {
                                reject(new WebCryptoError(`Aes: Can not generate new key\n${err.message}`));
                            }
                            else {
                                let key = new CryptoKey(aesKey, algorithm);
                                resolve(key);
                            }
                        }
                        catch (e) {
                            reject(e);
                        }
                    });
                });
            });
    }

    static exportKey(format: string, key: CryptoKey, session?: Session): PromiseLike<JsonWebKey | ArrayBuffer> {
        return super.exportKey.apply(this, arguments)
            .then(() => {
                return new Promise((resolve, reject) => {
                    let vals = key.key.getAttribute({ value: null, valueLen: null });
                    switch (format.toLowerCase()) {
                        case "jwk":
                            let aes: string = /AES-(\w+)/.exec(key.algorithm.name!) ![1];
                            let jwk: JsonWebKey = {
                                kty: "oct",
                                k: Base64Url.encode(vals.value!),
                                alg: `A${vals.valueLen * 8}${aes}`,
                                ext: true
                            };
                            resolve(jwk);
                            break;
                        case "raw":
                            resolve(vals.value!.buffer);
                        default:
                            throw new WebCryptoError(`Unknown format '${format}'`);
                    }
                });
            });
    }

    static importKey(format: string, keyData: JsonWebKey | BufferSource, algorithm: Algorithm, extractable: boolean, keyUsages: string[], session?: Session): PromiseLike<CryptoKey> {
        return (super.importKey.apply(this, arguments) as PromiseLike<CryptoKeyPair>)
            .then(() => {
                return new Promise((resolve, reject) => {
                    // get key value
                    let value: Buffer;
                    if (format === "jwk")
                        value = utils.b64_decode((keyData as JsonWebKey).k!);
                    else
                        value = <Buffer>keyData;

                    // prepare key algorithm
                    let _alg: AesKeyGenParams = {
                        name: algorithm.name,
                        length: value.length * 8
                    };
                    let template: ITemplate = create_template(session!, _alg, extractable, keyUsages);
                    template.value = value;

                    // create session object
                    let sobj = session!.create(template);
                    resolve(new CryptoKey(sobj.toType<SecretKey>(), _alg));
                });
            });
    }

    /**
     * Returns a size of output buffer of enc/dec operation 
     * 
     * @protected
     * @static
     * @param {KeyAlgorithm} keyAlg key algorithm
     * @param {boolean} enc type of operation
     * `true` - encryption operation 
     * `false` - decryption operation 
     * @param {number} dataSize size of incoming data
     * @returns {number}
     * 
     * @memberOf AesCrypto
     */
    protected static getOutputBufferSize(keyAlg: AesKeyAlgorithm, enc: boolean, dataSize: number): number {
        const len = keyAlg.length >> 3;
        if (enc)
            return (Math.ceil(dataSize / len) * len) + len;
        else
            return dataSize;
    }

    static encrypt(algorithm: Algorithm, key: CryptoKey, data: Buffer, session?: Session): PromiseLike<ArrayBuffer> {
        return (super.encrypt.apply(this, arguments) as PromiseLike<CryptoKeyPair>)
            .then(() => {
                return new Promise((resolve, reject) => {
                    session!.createCipher(this.wc2pk11(algorithm), key.key).once(data, new Buffer(this.getOutputBufferSize(key.algorithm as AesKeyAlgorithm, true, data.length)), (err, data) => {
                        if (err) reject(err);
                        else resolve(data.buffer);
                    });
                });
            });
    }

    static decrypt(algorithm: Algorithm, key: CryptoKey, data: Buffer, session?: Session): PromiseLike<ArrayBuffer> {
        return (super.decrypt.apply(this, arguments) as PromiseLike<CryptoKeyPair>)
            .then(() => {
                return new Promise((resolve, reject) => {
                    session!.createDecipher(this.wc2pk11(algorithm), key.key).once(data, new Buffer(this.getOutputBufferSize(key.algorithm as AesKeyAlgorithm, false, data.length)), (err, data) => {
                        if (err) reject(err);
                        else resolve(data.buffer);
                    });
                });
            });
    }

    static wc2pk11(alg: Algorithm): IAlgorithm {
        throw new WebCryptoError(WebCryptoError.NOT_SUPPORTED);
    }

}

export class AesGCM extends AesCrypto {

    static wc2pk11(alg: AesGcmParams): IAlgorithm {
        let aad = alg.additionalData ? utils.PrepareData(alg.additionalData) : undefined;
        let params = new graphene.AesGcmParams(utils.PrepareData(alg.iv), aad, alg.tagLength);
        return { name: "AES_GCM", params: params };
    }

}

export class AesCBC extends AesCrypto {
    static wc2pk11(alg: AesCbcParams): IAlgorithm {
        return { name: "AES_CBC_PAD", params: utils.PrepareData(alg.iv) };
    }
}