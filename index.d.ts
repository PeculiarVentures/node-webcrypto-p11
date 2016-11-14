// Type definitions for node-webcrypto-p11
// Project: https://github.com/PeculiarVentures/node-webcrypto-p11
// Definitions by: Stepan Miroshin <https://github.com/microshine>

/// <reference types="node" />
/// <reference types="webcrypto-core" />
/// <reference types="graphene-pk11" />

declare namespace NodeWebcryptoPkcs11 {

    type NodeBufferSource = BufferSource | Buffer;

    interface CryptoKeyPair extends NativeCryptoKey {
        privateKey: CryptoKey;
        publicKey: CryptoKey;
    }

    class CryptoKey implements NativeCryptoKey {
        type: string;
        extractable: boolean;
        algorithm: KeyAlgorithm;
        id: string;
        usages: string[];
        private _key;
        readonly key: GraphenePkcs11.Key;
        constructor(key: GraphenePkcs11.Key, alg: Algorithm);
        protected initPrivateKey(key: GraphenePkcs11.PrivateKey): void;
        protected initPublicKey(key: GraphenePkcs11.PublicKey): void;
        protected initSecretKey(key: GraphenePkcs11.SecretKey): void;
    }

    class KeyStorage {
        protected session: GraphenePkcs11.Session;
        constructor(session: GraphenePkcs11.Session);
        readonly length: number;
        clear(): void;
        protected getItemById(id: string): GraphenePkcs11.SessionObject | null;
        getItem(key: string): CryptoKey | null;
        key(index: number): string;
        removeItem(key: string): void;
        setItem(key: string, data: CryptoKey): void;
    }

    class SubtleCrypto extends WebcryptoCore.SubtleCrypto {
        protected session: GraphenePkcs11.Session;
        constructor(session: GraphenePkcs11.Session);
        digest(algorithm: AlgorithmIdentifier, data: NodeBufferSource): PromiseLike<ArrayBuffer>;
        generateKey(algorithm: string, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKeyPair | CryptoKey>;
        generateKey(algorithm: RsaHashedKeyGenParams | EcKeyGenParams | DhKeyGenParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKeyPair>;
        generateKey(algorithm: AesKeyGenParams | HmacKeyGenParams | Pbkdf2Params, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
        wrapKey(format: string, key: CryptoKey, wrappingKey: CryptoKey, wrapAlgorithm: AlgorithmIdentifier): PromiseLike<ArrayBuffer>;
        unwrapKey(format: string, wrappedKey: NodeBufferSource, unwrappingKey: CryptoKey, unwrapAlgorithm: AlgorithmIdentifier, unwrappedKeyAlgorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
        encrypt(algorithm: string | RsaOaepParams | AesCtrParams | AesCbcParams | AesCmacParams | AesGcmParams | AesCfbParams, key: CryptoKey, data: NodeBufferSource): PromiseLike<ArrayBuffer>;
        decrypt(algorithm: string | RsaOaepParams | AesCtrParams | AesCbcParams | AesCmacParams | AesGcmParams | AesCfbParams, key: CryptoKey, data: NodeBufferSource): PromiseLike<ArrayBuffer>;
        exportKey(format: "jwk", key: CryptoKey): PromiseLike<JsonWebKey>;
        exportKey(format: "raw" | "pkcs8" | "spki", key: CryptoKey): PromiseLike<ArrayBuffer>;
        exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer>;
        importKey(format: "jwk", keyData: JsonWebKey, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
        importKey(format: "raw" | "pkcs8" | "spki", keyData: NodeBufferSource, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
        importKey(format: string, keyData: JsonWebKey | NodeBufferSource, algorithm: string | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
        sign(algorithm: string | RsaPssParams | EcdsaParams | AesCmacParams, key: CryptoKey, data: NodeBufferSource): PromiseLike<ArrayBuffer>;
        verify(algorithm: string | RsaPssParams | EcdsaParams | AesCmacParams, key: CryptoKey, signature: NodeBufferSource, data: NodeBufferSource): PromiseLike<boolean>;
        deriveKey(algorithm: string | EcdhKeyDeriveParams | DhKeyDeriveParams | ConcatParams | HkdfCtrParams | Pbkdf2Params, baseKey: CryptoKey, derivedKeyType: string | AesDerivedKeyParams | HmacImportParams | ConcatParams | HkdfCtrParams | Pbkdf2Params, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey>;
        deriveBits(algorithm: string | EcdhKeyDeriveParams | DhKeyDeriveParams | ConcatParams | HkdfCtrParams | Pbkdf2Params, baseKey: CryptoKey, length: number): PromiseLike<ArrayBuffer>;
    }

    class WebCrypto implements NativeCrypto {
        private module;
        private session;
        private slot;
        private initialized;
        subtle: SubtleCrypto;
        keyStorage: KeyStorage;
        getRandomValues(array: NodeBufferSource): NodeBufferSource;
        getRandomValues(array: ArrayBufferView): ArrayBufferView;
        getGUID(): string;
        constructor(props: P11WebCryptoParams);
        close(): void;
    }

    interface P11WebCryptoParams extends Object {
        library: string;
        name: string;
        slot: number;
        sessionFlags?: number;
        pin?: string;
        vendors?: string[];
    }

}

declare module "node-webcrypto-p11" {
    export = NodeWebcryptoPkcs11.WebCrypto;
}