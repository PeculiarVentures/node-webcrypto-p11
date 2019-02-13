type NodeBufferSource = BufferSource | Buffer;

type NativeCrypto = Crypto;
type NativeSubtleCrypto = SubtleCrypto;
type NativeCryptoKey = CryptoKey;

interface P11WebCryptoParams {
    /**
     * Path to labrary
     */
    library: string;
    /**
     * Name of PKCS11 module
     */
    name?: string;
    /**
     * Index of slot
     */
    slot?: number;
    readWrite?: boolean;
    /**
     * PIN of slot
     */
    pin?: string;
    /**
     * list of vendor json files
     */
    vendors?: string[];
    /**
     * NSS library parameters
     */
    libraryParameters?: string;
}

// TODO: Remove interfaces to webcrypto-core
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

    /**
     * Removes all keys from storage
     *
     * @returns {Promise<void>}
     *
     * @memberOf IKeyStorage
     */
    clear(): Promise<void>;

}

type HexString = string;

type CryptoCertificateFormat = string | "x509" | "request";

interface ICryptoCertificate {
    type: CryptoCertificateFormat;
    publicKey: CryptoKey;
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

    exportCert(type: "pem", item: ICryptoCertificate): Promise<string>;
    exportCert(type: "raw", item: ICryptoCertificate): Promise<ArrayBuffer>;
    exportCert(type: string, item: ICryptoCertificate): Promise<ArrayBuffer | string>;

    setItem(item: ICryptoCertificate): Promise<string>;
    getItem(key: string): Promise<ICryptoCertificate>;
    getItem(key: string, algorithm: Algorithm, keyUsages: string[]): Promise<ICryptoCertificate>;
    removeItem(key: string): Promise<void>;
    clear(): Promise<void>;

}

interface IModule {
    name: string;
    providers: IProvider[];
}

interface IProvider {
    id: string;
    name: string;
    reader: string;
    slot: number;
    serialNumber: string;
    algorithms: string[];
    isRemovable: boolean;
    isHardware: boolean;
}
