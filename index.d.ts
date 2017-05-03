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

    interface CryptoCertificate {
        type: CryptoCertificateFormat;
        publicKey: CryptoKey;
    }

    interface CryptoX509Certificate extends CryptoCertificate {
        notBefore: Date;
        notAfter: Date;
        serialNumber: HexString;
        issuerName: string;
        subjectName: string;
    }

    interface CryptoX509CertificateRequest extends CryptoCertificate {
        subjectName: string;
    }

    interface CertificateStorage {

        keys(): Promise<string[]>;
        /**
         * Returns identity of item from storage.
         * If item is not found, then returns `null`
         */
        indexOf(item: CryptoCertificate): Promise<string | null>;

        /**
         * Import certificate from data
         * 
         * @param {CertificateItemType} type Type of certificate
         * @param {(ArrayBuffer)} data Raw of certificate item
         * @returns {Promise<CryptoCertificate>} 
         * 
         * @memberOf CertificateStorage
         */
        importCert(type: "request", data: BufferSource, algorithm: Algorithm, keyUsages: string[]): Promise<CryptoX509CertificateRequest>;
        importCert(type: "x509", data: BufferSource, algorithm: Algorithm, keyUsages: string[]): Promise<CryptoX509Certificate>;
        importCert(type: CryptoCertificateFormat, data: BufferSource, algorithm: Algorithm, keyUsages: string[]): Promise<CryptoCertificate>;

        exportCert(format: "pem", item: CryptoCertificate): Promise<string>
        exportCert(format: "raw", item: CryptoCertificate): Promise<ArrayBuffer>
        exportCert(format: CryptoCertificateFormat, item: CryptoCertificate): Promise<ArrayBuffer | string>

        setItem(item: CryptoCertificate): Promise<string>;
        getItem(key: string): Promise<CryptoCertificate>;
        getItem(key: string, algorithm: Algorithm, keyUsages: string[]): Promise<CryptoCertificate>;
        removeItem(key: string): Promise<void>;
        clear(): Promise<void>;
    }

    interface KeyStorage {

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
        indexOf(item: CryptoKey): Promise<string | null>;
        /**
         * Returns key from storage
         * 
         * @param {string} key 
         * @returns {Promise<CryptoKey>} 
         * 
         * @memberOf KeyStorage
         */
        getItem(key: string): Promise<CryptoKey>;
        getItem(key: string, algorithm: Algorithm, usages: string[]): Promise<CryptoKey>;
        /**
         * Add key to storage
         * 
         * @param {string} key 
         * @param {CryptoKey} value 
         * @returns {Promise<void>} 
         * 
         * @memberOf KeyStorage
         */
        setItem(value: CryptoKey): Promise<string>;

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
        isLoggedIn: boolean;
        subtle: SubtleCrypto;
        keyStorage: KeyStorage;
        certStorage: CertificateStorage;
        getRandomValues(array: NodeBufferSource): NodeBufferSource;
        getRandomValues(array: ArrayBufferView): ArrayBufferView;
        getGUID(): string;
        constructor(props: P11WebCryptoParams);
        open(rw?: boolean): void;
        close(): void;
        login(pin: string): void;
        logout(): void;
    }

    interface P11WebCryptoParams extends Object {
        library: string;
        name?: string;
        slot: number;
        readWrite?: boolean;
        pin?: string;
        vendors?: string[];
    }

    interface IModule {
        name: string;
        providers: IProvider[];
    }

    interface IProvider {
        id: string;
        slot: number;
        name: string;
        serialNumber: string;
        algorithms: string[];
        isRemovable: boolean;
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
        public stop(): void;

    }
}
