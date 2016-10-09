// Core
import * as webcrypto from "webcrypto-core";
const AlgorithmError = webcrypto.AlgorithmError;
const PrepareAlgorithm = webcrypto.PrepareAlgorithm;
let BaseCrypto = webcrypto.BaseCrypto;
const AlgorithmNames = webcrypto.AlgorithmNames;
import * as graphene from "graphene-pk11";

import { CryptoKey } from "./key";

import * as aes from "./crypto/aes";
import * as rsa from "./crypto/rsa";
import * as ec from "./crypto/ec";

export class SubtleCrypto extends webcrypto.SubtleCrypto {
    protected session: graphene.Session;

    constructor(session: graphene.Session) {
        super();

        this.session = session;
    }

    generateKey(algorithm: string, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKeyPair | CryptoKey>;
    generateKey(algorithm: RsaHashedKeyGenParams | EcKeyGenParams | DhKeyGenParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKeyPair>;
    generateKey(algorithm: AesKeyGenParams | HmacKeyGenParams | Pbkdf2Params, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
    generateKey(algorithm: any, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKeyPair | CryptoKey> {
        return super.generateKey.apply(this, arguments)
            .then(() => {
                let _alg = PrepareAlgorithm(algorithm);

                let AlgClass: typeof BaseCrypto;
                switch (_alg.name.toLowerCase()) {
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
                        throw new AlgorithmError(AlgorithmError.NOT_SUPPORTED, _alg.name);
                }
                return AlgClass.generateKey(_alg as any, extractable, keyUsages);
            });
    }

    wrapKey(format: string, key: CryptoKey, wrappingKey: CryptoKey, wrapAlgorithm: AlgorithmIdentifier): PromiseLike<ArrayBuffer> {
        return super.wrapKey.apply(this, arguments)
            .then(() => {
                return this.exportKey(format as any, key)
                    .then(exportedKey => {
                        let _data: Buffer;
                        if (!(exportedKey instanceof ArrayBuffer)) {
                            _data = new Buffer(JSON.stringify(exportedKey));
                        }
                        else {
                            _data = new Buffer(exportedKey);
                        }
                        return this.encrypt(wrapAlgorithm, wrappingKey, _data);
                    });
            });
    }

    unwrapKey(format: string, wrappedKey: NodeBufferSource, unwrappingKey: CryptoKey, unwrapAlgorithm: AlgorithmIdentifier, unwrappedKeyAlgorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return super.unwrapKey.apply(this, arguments)
            .then(() => {
                return Promise.resolve()
                    .then(() => {
                        return this.decrypt(unwrapAlgorithm, unwrappingKey, wrappedKey);
                    })
                    .then(decryptedKey => {
                        let keyData: JsonWebKey | Buffer;
                        if (format === "jwk") {
                            keyData = JSON.parse(new Buffer(decryptedKey).toString());
                        }
                        else {
                            keyData = new Buffer(decryptedKey);
                        }
                        return this.importKey(format as any, keyData as Buffer, unwrappedKeyAlgorithm, extractable, keyUsages);
                    });
            });
    }

}