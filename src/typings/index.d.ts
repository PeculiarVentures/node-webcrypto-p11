interface CryptoParams {
    /**
     * Path to library
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

interface ProviderInfo {
    id: string;
    name: string;
    reader: string;
    slot: number;
    serialNumber: string;
    algorithms: string[];
    isRemovable: boolean;
    isHardware: boolean;
}
