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

    type CertificateItemType = string | "x509" | "request";

    interface ICertificateStorageItem {
        id: string;
        type: CertificateItemType;
        publicKey: CryptoKey;
        value: ArrayBuffer;
    }

    interface IX509Certificate extends ICertificateStorageItem {
        serialNumber?: HexString;
        issuerName?: string;
        subjectName?: string;
    }

    interface IX509Request extends ICertificateStorageItem {
        subjectName?: string;
    }

    interface ICertificateStorage {

        keys(): Promise<string[]>;

        /**
         * Import certificate from data
         * 
         * @param {CertificateItemType} type Type of certificate
         * @param {(ArrayBuffer)} data Raw of certificate item
         * @returns {Promise<ICertificateStorageItem>} 
         * 
         * @memberOf CertificateStorage
         */
        importCert(type: CertificateItemType, data: ArrayBuffer, algorithm: Algorithm, keyUsages: string[]): Promise<ICertificateStorageItem>;

        setItem(key: string, item: ICertificateStorageItem): Promise<void>;
        getItem(key: string): Promise<ICertificateStorageItem>;
        removeItem(key: string): Promise<void>;

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
         * Returns key from storage
         * 
         * @param {string} key 
         * @returns {Promise<CryptoKey>} 
         * 
         * @memberOf KeyStorage
         */
        getItem(key: string): Promise<CryptoKey>;
        /**
         * Add key to storage
         * 
         * @param {string} key 
         * @param {CryptoKey} value 
         * @returns {Promise<void>} 
         * 
         * @memberOf KeyStorage
         */
        setItem(key: string, value: CryptoKey): Promise<void>;

        /**
         * Removes item from storage by given key
         * 
         * @param {string} key 
         * @returns {Promise<void>} 
         * 
         * @memberOf KeyStorage
         */
        removeItem(key: string): Promise<void>;

    }

    class WebCrypto implements NativeCrypto {
        isLoggedIn: boolean;
        subtle: SubtleCrypto;
        keyStorage: IKeyStorage;
        certStorage: ICertificateStorage;
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
        name: string;
        serialNumber: string;
        algorithms: string[];
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

        public open(): void;
        public stop(): void;

    }
}
