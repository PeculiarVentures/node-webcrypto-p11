type NodeBufferSource = BufferSource | Buffer;

interface P11WebCryptoParams extends Object {
    /**
     * Path to labrary
     */
    library: string;
    /**
     * Name of PKCS11 module
     */
    name: string;
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

}

type HexString = string;

type CryptoCertificateType = string | "x509" | "request";

interface CryptoCertificate {
    type: CryptoCertificateType;
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
     * Import certificate from data
     * 
     * @param {CertificateItemType} type Type of certificate
     * @param {(ArrayBuffer)} data Raw of certificate item
     * @returns {Promise<ICertificateStorageItem>} 
     * 
     * @memberOf CertificateStorage
     */
    importCert(type: CryptoCertificateType, data: ArrayBuffer, algorithm: Algorithm, keyUsages: string[]): Promise<CryptoCertificate>;
    exportCert(cert: CryptoCertificate): Promise<ArrayBuffer>;

    setItem(item: CryptoCertificate): Promise<string>;
    getItem(key: string): Promise<CryptoCertificate>;
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
    serialNumber: string;
    algorithms: string[];
}
