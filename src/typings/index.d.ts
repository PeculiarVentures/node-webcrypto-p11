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

interface Pkcs11Params {
  token?: boolean;
  sensitive?: boolean;
  label?: string;
}
interface Pkcs11KeyGenParams extends Algorithm, Pkcs11Params { }

interface Pkcs11AesKeyGenParams extends AesKeyGenParams, Pkcs11KeyGenParams { }

interface Pkcs11HmacKeyGenParams extends HmacKeyGenParams, Pkcs11KeyGenParams { }

interface Pkcs11EcKeyGenParams extends EcKeyGenParams, Pkcs11KeyGenParams { }

interface Pkcs11RsaHashedKeyGenParams extends RsaHashedKeyGenParams, Pkcs11KeyGenParams { }

interface Pkcs11KeyImportParams extends Algorithm, Pkcs11Params { }

interface Pkcs11EcKeyImportParams extends EcKeyImportParams, Pkcs11KeyImportParams { }

interface Pkcs11RsaHashedImportParams extends RsaHashedImportParams, Pkcs11KeyImportParams { }

interface Pkcs11HmacKeyImportParams extends HmacImportParams, Pkcs11KeyImportParams { }

interface Pkcs11AesKeyImportParams extends Algorithm, Pkcs11KeyImportParams { }

interface Pkcs11KeyAlgorithm extends KeyAlgorithm {
  token: boolean;
  sensitive: boolean;
  label: string;
}

interface Pkcs11RsaHashedKeyAlgorithm extends RsaHashedKeyAlgorithm, Pkcs11KeyAlgorithm { }

interface Pkcs11EcKeyAlgorithm extends EcKeyAlgorithm, Pkcs11KeyAlgorithm { }

interface Pkcs11AesKeyAlgorithm extends AesKeyAlgorithm, Pkcs11KeyAlgorithm { }

interface Pkcs11HmacKeyAlgorithm extends HmacKeyAlgorithm, Pkcs11KeyAlgorithm { }
