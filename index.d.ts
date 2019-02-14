// Type definitions for node-webcrypto-p11
// Project: https://github.com/PeculiarVentures/node-webcrypto-p11
// Definitions by: Stepan Miroshin <https://github.com/microshine>

import * as core from "webcrypto-core";

export interface CryptoParams {
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

export interface ProviderInfo {
  id: string;
  name: string;
  reader: string;
  slot: number;
  serialNumber: string;
  algorithms: string[];
  isRemovable: boolean;
  isHardware: boolean;
}

export declare const SubtleCrypto: {
  readonly prototype: core.NativeSubtleCrypto;
  new(crypto: Crypto): core.NativeSubtleCrypto;
};

export declare const KeyStorage: {
  readonly prototype: core.CryptoKeyStorage
  new(crypto: Crypto): core.CryptoKeyStorage;
};

export declare const CertificateStorage: {
  readonly prototype: core.CryptoCertificateStorage;
  new(crypto: Crypto): core.CryptoCertificateStorage;
};

export class Crypto implements core.NativeCrypto, core.CryptoStorages {
  public keyStorage: core.CryptoKeyStorage;
  public certStorage: core.CryptoCertificateStorage;
  public subtle: core.NativeSubtleCrypto;

  public info: ProviderInfo;
  public isReadWrite: boolean;
  public isLoggedIn: boolean;
  public isLoginRequired: boolean;

  /**
   * Creates an instance of WebCrypto.
   * @param props PKCS11 module init parameters
   */
  constructor(props: CryptoParams);

  public getRandomValues<T extends Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | null>(array: T): T;

  public open(rw?: boolean): void;
  public reset(): void;
  public login(pin?: string): void;
  public logout(): void;
  public close(): void;
}

export declare class CryptoKey extends core.CryptoKey {
  private constructor();
}

export declare class CryptoCertificate implements core.CryptoCertificate {
  public readonly type: core.CryptoCertificateType;
  public readonly publicKey: CryptoKey;
}

export declare class CryptoX509Certificate extends CryptoCertificate implements core.CryptoX509Certificate {
  public readonly type: "x509";
  public readonly notBefore: Date;
  public readonly notAfter: Date;
  public readonly serialNumber: string;
  public readonly issuerName: string;
  public readonly subjectName: string;
  private constructor();
}

export declare class CryptoX509CertificateRequest extends CryptoCertificate implements core.CryptoX509CertificateRequest {
  public readonly type: "request";
  public readonly subjectName: string;
  private constructor();
}
