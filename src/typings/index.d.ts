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
