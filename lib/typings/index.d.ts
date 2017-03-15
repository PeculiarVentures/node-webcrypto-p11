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
    slot: number;
    sessionFlags?: number;
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

type HexString = string;

type CertificateItemType = string | "x509" | "request";

interface ICertificateStorageItem {
    id: string;
    type: CertificateItemType;
    publicKey: CryptoKey;
    value: ArrayBuffer;
}

interface IX509Certificate extends ICertificateStorageItem {
    serialNumber: HexString;
    issuerName: string;
    subjectName: string;
}

interface IX509Request extends ICertificateStorageItem {
    subjectName: string;
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

interface IModule {
    name: string;
    providers: IProvider[];
}

interface IProvider {
    id: string;
    name: string;
    algorithms: string[];
}