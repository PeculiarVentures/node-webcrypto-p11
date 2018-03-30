// Type definitions for node-webcrypto-p11
// Project: https://github.com/PeculiarVentures/node-webcrypto-p11
// Definitions by: Stepan Miroshin <https://github.com/microshine>

/// <reference types="node" />
/// <reference types="webcrypto-core" />
/// <reference types="graphene-pk11" />

import { EventEmitter } from "events";

declare module "node-webcrypto-p11" {
    type NodeBufferSource = BufferSource | Buffer;

    type HexString = string;

    type CryptoCertificateFormat = string | "x509" | "request";

    interface ICryptoCertificate {
        type: CryptoCertificateFormat;
        publicKey: NativeCryptoKey;
    }

    interface ICryptoX509Certificate extends ICryptoCertificate {
        notBefore: Date;
        notAfter: Date;
        serialNumber: HexString;
        issuerName: string;
        subjectName: string;
    }

    interface ICryptoX509CertificateRequest extends ICryptoCertificate {
        subjectName: string;
    }

    interface ICertificateStorage {

        keys(): Promise<string[]>;
        /**
         * Returns identity of item from storage.
         * If item is not found, then returns `null`
         */
        indexOf(item: ICryptoCertificate): Promise<string | null>;

        /**
         * Import certificate from data
         *
         * @param {CertificateItemType} type Type of certificate
         * @param {(ArrayBuffer)} data Raw of certificate item
         * @returns {Promise<ICryptoCertificate>}
         *
         * @memberOf CertificateStorage
         */
        importCert(type: "request", data: BufferSource, algorithm: Algorithm, keyUsages: string[]): Promise<ICryptoX509CertificateRequest>;
        importCert(type: "x509", data: BufferSource, algorithm: Algorithm, keyUsages: string[]): Promise<ICryptoX509Certificate>;
        importCert(type: CryptoCertificateFormat, data: BufferSource, algorithm: Algorithm, keyUsages: string[]): Promise<ICryptoCertificate>;

        exportCert(format: "pem", item: ICryptoCertificate): Promise<string>;
        exportCert(format: "raw", item: ICryptoCertificate): Promise<ArrayBuffer>;
        exportCert(format: CryptoCertificateFormat, item: ICryptoCertificate): Promise<ArrayBuffer | string>;

        setItem(item: ICryptoCertificate): Promise<string>;
        getItem(key: string): Promise<ICryptoCertificate>;
        getItem(key: string, algorithm: Algorithm, keyUsages: string[]): Promise<ICryptoCertificate>;
        removeItem(key: string): Promise<void>;
        clear(): Promise<void>;
    }

    interface IKeyStorage {

        /**
         * Return list of names of stored keys
         *
         * @returns {Promise<string[]>}
         *
         * @memberOf KeyStorage
         */
        keys(): Promise<string[]>;
        /**
         * Returns identity of item from storage.
         * If item is not found, then returns `null`
         */
        indexOf(item: NativeCryptoKey): Promise<string | null>;
        /**
         * Returns key from storage
         *
         * @param {string} key
         * @returns {Promise<CryptoKey>}
         *
         * @memberOf KeyStorage
         */
        getItem(key: string): Promise<NativeCryptoKey>;
        getItem(key: string, algorithm: Algorithm, usages: string[]): Promise<NativeCryptoKey>;
        /**
         * Add key to storage
         *
         * @param {string} key
         * @param {CryptoKey} value
         * @returns {Promise<void>}
         *
         * @memberOf KeyStorage
         */
        setItem(value: NativeCryptoKey): Promise<string>;

        /**
         * Removes item from storage by given key
         *
         * @param {string} key
         * @returns {Promise<void>}
         *
         * @memberOf KeyStorage
         */
        removeItem(key: string): Promise<void>;
        clear(): Promise<void>;
    }

    class WebCrypto implements NativeCrypto {
        public readonly info: IProvider;
        public session: GraphenePkcs11.Session;
        public isLoggedIn: boolean;
        public isReadWrite: boolean;
        public isLoginRequired: boolean;
        public subtle: SubtleCrypto;
        public keyStorage: IKeyStorage;
        public certStorage: ICertificateStorage;

        public module: GraphenePkcs11.Module;
        public slot: GraphenePkcs11.Slot;
        public token: GraphenePkcs11.Token;

        constructor(props: P11WebCryptoParams);

        public getRandomValues(array: Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | null): Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | null;
        public getGUID(): string;
        public open(rw?: boolean): void;
        public close(): void;
        public login(pin: string): void;
        public logout(): void;
        public reset(): void;
    }

    export class SubtleCrypto implements NativeSubtleCrypto {
        protected crypto: WebCrypto;

        constructor(crypto: WebCrypto);

        public decrypt(algorithm: string | RsaOaepParams | AesCtrParams | AesCbcParams | AesCmacParams | AesGcmParams | AesCfbParams, key: NativeCryptoKey, data: ArrayBuffer | Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView): PromiseLike<ArrayBuffer>;
        public deriveBits(algorithm: string | EcdhKeyDeriveParams | DhKeyDeriveParams | ConcatParams | HkdfCtrParams | Pbkdf2Params, baseKey: NativeCryptoKey, length: number): PromiseLike<ArrayBuffer>;
        public deriveKey(algorithm: string | EcdhKeyDeriveParams | DhKeyDeriveParams | ConcatParams | HkdfCtrParams | Pbkdf2Params, baseKey: NativeCryptoKey, derivedKeyType: string | ConcatParams | HkdfCtrParams | Pbkdf2Params | AesDerivedKeyParams | HmacImportParams, extractable: boolean, keyUsages: string[]): PromiseLike<NativeCryptoKey>;
        public digest(algorithm: string | Algorithm, data: ArrayBuffer | Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView): PromiseLike<ArrayBuffer>;
        public encrypt(algorithm: string | RsaOaepParams | AesCtrParams | AesCbcParams | AesCmacParams | AesGcmParams | AesCfbParams, key: NativeCryptoKey, data: ArrayBuffer | Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView): PromiseLike<ArrayBuffer>;
        public exportKey(format: "jwk", key: NativeCryptoKey): PromiseLike<JsonWebKey>;
        public exportKey(format: "raw" | "pkcs8" | "spki", key: NativeCryptoKey): PromiseLike<ArrayBuffer>;
        public exportKey(format: string, key: NativeCryptoKey): PromiseLike<ArrayBuffer | JsonWebKey>;
        public exportKey(format: any, key: any): PromiseLike<ArrayBuffer | JsonWebKey>;
        public generateKey(algorithm: string, extractable: boolean, keyUsages: string[]): PromiseLike<NativeCryptoKey | NativeCryptoKeyPair>;
        public generateKey(algorithm: RsaHashedKeyGenParams | EcKeyGenParams | DhKeyGenParams, extractable: boolean, keyUsages: string[]): PromiseLike<NativeCryptoKeyPair>;
        public generateKey(algorithm: Pbkdf2Params | AesKeyGenParams | HmacKeyGenParams, extractable: boolean, keyUsages: string[]): PromiseLike<NativeCryptoKey>;
        public generateKey(algorithm: any, extractable: any, keyUsages: any): PromiseLike<NativeCryptoKey | NativeCryptoKeyPair>;
        public importKey(format: "jwk", keyData: JsonWebKey, algorithm: string | HmacImportParams | RsaHashedImportParams | EcKeyImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<NativeCryptoKey>;
        public importKey(format: "raw" | "pkcs8" | "spki", keyData: ArrayBuffer | Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView, algorithm: string | HmacImportParams | RsaHashedImportParams | EcKeyImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<NativeCryptoKey>;
        public importKey(format: string, keyData: ArrayBuffer | Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | JsonWebKey, algorithm: string | HmacImportParams | RsaHashedImportParams | EcKeyImportParams | DhImportKeyParams, extractable: boolean, keyUsages: string[]): PromiseLike<NativeCryptoKey>;
        public importKey(format: any, keyData: any, algorithm: any, extractable: any, keyUsages: any): PromiseLike<NativeCryptoKey>;
        public sign(algorithm: string | AesCmacParams | RsaPssParams | EcdsaParams, key: NativeCryptoKey, data: ArrayBuffer | Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView): PromiseLike<ArrayBuffer>;
        public unwrapKey(format: string, wrappedKey: ArrayBuffer | Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView, unwrappingKey: NativeCryptoKey, unwrapAlgorithm: string | Algorithm, unwrappedKeyAlgorithm: string | Algorithm, extractable: boolean, keyUsages: string[]): PromiseLike<NativeCryptoKey>;
        public verify(algorithm: string | AesCmacParams | RsaPssParams | EcdsaParams, key: NativeCryptoKey, signature: ArrayBuffer | Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView, data: ArrayBuffer | Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView): PromiseLike<boolean>;
        public wrapKey(format: string, key: NativeCryptoKey, wrappingKey: NativeCryptoKey, wrapAlgorithm: string | Algorithm): PromiseLike<ArrayBuffer>;
    }

    interface P11WebCryptoParams extends Object {
        library: string;
        name?: string;
        slot: number;
        readWrite?: boolean;
        pin?: string;
        vendors?: string[];
        libraryParameters?: string;
    }

    interface IModule {
        name: string;
        providers: IProvider[];
    }

    interface IProvider {
        id: string;
        slot: number;
        name: string;
        reader: string;
        serialNumber: string;
        algorithms: string[];
        isRemovable: boolean;
        isHardware: boolean;
    }

    type ProviderTokenHandler = (info: { removed: IProvider[], added: IProvider[] }) => void;
    type ProviderListeningHandler = (info: IModule) => void;
    type ProviderErrorHandler = (e: Error) => void;
    type ProviderStopHandler = () => void;

    export class Provider extends EventEmitter {

        public readonly library: string;

        constructor(lib: string);

        public on(event: "stop", listener: ProviderStopHandler): this;
        public on(event: "listening", listener: ProviderListeningHandler): this;
        public on(event: "token", listener: ProviderTokenHandler): this;
        public on(event: "error", listener: ProviderErrorHandler): this;

        public once(event: "stop", listener: ProviderStopHandler): this;
        public once(event: "listening", listener: ProviderListeningHandler): this;
        public once(event: "token", listener: ProviderTokenHandler): this;
        public once(event: "error", listener: ProviderErrorHandler): this;

        public open(watch?: boolean): void;
        public reset(): void;
        public stop(): void;

        public login(pin: string): void;
        public logout(): void;

    }

    export class KeyStorage implements IKeyStorage {

        protected crypto: WebCrypto;

        constructor(crypto: WebCrypto);

        /**
         * Return list of names of stored keys
         */
        public keys(): Promise<string[]>;
        /**
         * Returns identity of item from storage.
         * If item is not found, then returns `null`
         */
        public indexOf(item: NativeCryptoKey): Promise<string>;
        public getItem(key: string): Promise<NativeCryptoKey>;
        public getItem(key: string, algorithm: Algorithm, usages: string[]): Promise<NativeCryptoKey>;
        public getItem(key: any, algorithm?: any, usages?: any): Promise<NativeCryptoKey>;
        /**
         * Add key to storage
         */
        public setItem(value: NativeCryptoKey): Promise<string>;
        /**
         * Removes item from storage by given key
         */
        public removeItem(key: string): Promise<void>;
        public clear(): Promise<void>;
        public hasItem(key: NativeCryptoKey): boolean;
        protected getItemById(id: string): GraphenePkcs11.SessionObject;
    }

    export class CertificateStorage implements ICertificateStorage {
        protected crypto: WebCrypto;

        constructor(crypto: WebCrypto);

        public keys(): Promise<string[]>;
        /**
         * Returns identity of item from storage.
         * If item is not found, then returns `null`
         */
        public indexOf(item: ICryptoCertificate): Promise<string>;
        public importCert(type: "request", data: BufferSource, algorithm: Algorithm, keyUsages: string[]): Promise<ICryptoX509CertificateRequest>;
        public importCert(type: "x509", data: BufferSource, algorithm: Algorithm, keyUsages: string[]): Promise<ICryptoX509Certificate>;
        public importCert(type: string, data: BufferSource, algorithm: Algorithm, keyUsages: string[]): Promise<ICryptoCertificate>;
        public importCert(type: any, data: any, algorithm: any, keyUsages: any): Promise<ICryptoCertificate>;
        public exportCert(format: "pem", item: ICryptoCertificate): Promise<string>;
        public exportCert(format: "raw", item: ICryptoCertificate): Promise<ArrayBuffer>;
        public exportCert(format: string, item: ICryptoCertificate): Promise<string | ArrayBuffer>;
        public exportCert(format: any, item: any): Promise<string | ArrayBuffer>;
        public setItem(item: ICryptoCertificate): Promise<string>;
        public getItem(key: string): Promise<ICryptoCertificate>;
        public getItem(key: string, algorithm: Algorithm, keyUsages: string[]): Promise<ICryptoCertificate>;
        public getItem(key: any, algorithm?: any, keyUsages?: any): Promise<ICryptoCertificate>;
        public removeItem(key: string): Promise<void>;
        public clear(): Promise<void>;
        protected getItemById(id: string): GraphenePkcs11.SessionObject;
    }

    class Pkcs11Object {
        public p11Object: GraphenePkcs11.Storage;

        constructor(object?: GraphenePkcs11.Storage);
    }

    export abstract class CryptoCertificate extends Pkcs11Object implements ICryptoCertificate {
        public static getID(p11Object: Storage): string;

        public readonly id: string;
        public type: string;
        public publicKey: CryptoKey;
        protected crypto: WebCrypto;

        constructor(crypto: WebCrypto);

        public abstract importCert(data: Buffer, algorithm: Algorithm, keyUsages: string[]): Promise<void>;
        public abstract exportCert(): Promise<ArrayBuffer>;
        public abstract exportKey(): Promise<CryptoKey>;
        public abstract exportKey(algorithm: Algorithm, usages: string[]): Promise<CryptoKey>;
    }

    interface JsonPublicKey {
        algorithm: Algorithm;
        type: string;
        usages: string[];
        extractable: boolean;
    }

    interface JsonX509Certificate {
        publicKey: JsonPublicKey;
        notBefore: Date;
        notAfter: Date;
        subjectName: string;
        issuerName: string;
        serialNumber: string;
        type: string;
        value: string;
    }

    export class X509Certificate extends CryptoCertificate implements ICryptoX509Certificate {
        public notBefore: Date;
        public notAfter: Date;
        public serialNumber: string;
        public issuerName: string;
        public subjectName: string;
        public readonly value: ArrayBuffer;
        public importCert(data: Buffer, algorithm: Algorithm, keyUsages: string[]): Promise<void>;
        public exportCert(): Promise<ArrayBuffer>;
        public exportKey(): Promise<CryptoKey>;
        public exportKey(algorithm: Algorithm, usages: string[]): Promise<CryptoKey>;
        public exportKey(algorithm?: any, usages?: any): Promise<CryptoKey>;
        public toJSON(): JsonX509Certificate;
        protected parse(data: ArrayBuffer): void;
        /**
         * returns parsed ASN1 value
         */
        protected getData(): any;
    }

    interface JsonX509CertificateRequest {
        publicKey: JsonPublicKey;
        subjectName: string;
        type: string;
        value: string;
    }

    export class X509CertificateRequest extends CryptoCertificate implements ICryptoX509CertificateRequest {
        public subjectName: string;
        public readonly value: ArrayBuffer;
        public importCert(data: Buffer, algorithm: Algorithm, keyUsages: string[]): Promise<void>;
        public exportCert(): Promise<ArrayBuffer>;
        public exportKey(): Promise<CryptoKey>;
        public exportKey(algorithm: Algorithm, usages: string[]): Promise<CryptoKey>;
        public exportKey(algorithm?: any, usages?: any): Promise<CryptoKey>;
        public toJSON(): JsonX509CertificateRequest;
        protected parse(data: ArrayBuffer): void;
        /**
         * returns parsed ASN1 value
         */
        protected getData(): any;
    }

    export class CryptoKey extends Pkcs11Object implements NativeCryptoKey {
        public static getID(p11Key: GraphenePkcs11.Key): string;

        public id: string;
        public algorithm: KeyAlgorithm;
        public extractable: boolean;
        public type: string;
        public usages: string[];
        public readonly key: GraphenePkcs11.Key;

        constructor(key: GraphenePkcs11.Key, alg: Algorithm);

        public toJSON(): JsonPublicKey;
        protected initPrivateKey(key: GraphenePkcs11.PrivateKey): void;
        protected initPublicKey(key: GraphenePkcs11.PublicKey): void;
        protected initSecretKey(key: GraphenePkcs11.SecretKey): void;

    }

}
