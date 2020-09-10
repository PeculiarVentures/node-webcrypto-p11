// Type definitions for node-webcrypto-p11
// Project: https://github.com/PeculiarVentures/node-webcrypto-p11
// Definitions by: Stepan Miroshin <https://github.com/microshine>

import * as core from "webcrypto-core";

export interface Pkcs11KeyAttributes {
  token: boolean;
  sensitive?: boolean;
  label: string;
}

interface Pkcs11CertificateAttributes {
  label: string;
  token: boolean;
}

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

export class SubtleCrypto implements core.NativeSubtleCrypto {
  constructor(crypto: Crypto);
  public decrypt(algorithm: string | RsaOaepParams | AesCtrParams | AesCbcParams | AesCmacParams | AesGcmParams | AesCfbParams, key: CryptoKey, data: Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer): Promise<ArrayBuffer>;
  public deriveBits(algorithm: string | EcdhKeyDeriveParams | DhKeyDeriveParams | ConcatParams | HkdfCtrParams | Pbkdf2Params, baseKey: CryptoKey, length: number): Promise<ArrayBuffer>;
  public deriveKey(algorithm: string | EcdhKeyDeriveParams | DhKeyDeriveParams | ConcatParams | HkdfCtrParams | Pbkdf2Params, baseKey: CryptoKey, derivedKeyType: string | ConcatParams | HkdfCtrParams | Pbkdf2Params | AesDerivedKeyParams | HmacImportParams, extractable: boolean, keyUsages: string[], attrs?: Partial<Pkcs11KeyAttributes>): Promise<CryptoKey>;
  public digest(algorithm: string | Algorithm, data: Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer): Promise<ArrayBuffer>;
  public encrypt(algorithm: string | RsaOaepParams | AesCtrParams | AesCbcParams | AesCmacParams | AesGcmParams | AesCfbParams, key: CryptoKey, data: Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer): Promise<ArrayBuffer>;
  public exportKey(format: "jwk", key: CryptoKey): Promise<JsonWebKey>;
  public exportKey(format: "raw" | "pkcs8" | "spki", key: CryptoKey): Promise<ArrayBuffer>;
  public exportKey(format: string, key: CryptoKey): Promise<ArrayBuffer | JsonWebKey>;
  public generateKey(algorithm: string, extractable: boolean, keyUsages: string[], attrs?: Partial<Pkcs11KeyAttributes>): Promise<CryptoKey | CryptoKeyPair>;
  public generateKey(algorithm: RsaHashedKeyGenParams | EcKeyGenParams | DhKeyGenParams, extractable: boolean, keyUsages: string[], attrs?: Partial<Pkcs11KeyAttributes>): Promise<CryptoKeyPair>;
  public generateKey(algorithm: Pbkdf2Params | AesKeyGenParams | HmacKeyGenParams, extractable: boolean, keyUsages: string[], attrs?: Partial<Pkcs11KeyAttributes>): Promise<CryptoKey>;
  public importKey(format: "jwk", keyData: JsonWebKey, algorithm: string | core.ImportAlgorithms, extractable: boolean, keyUsages: string[], attrs?: Partial<Pkcs11KeyAttributes>): Promise<CryptoKey>;
  public importKey(format: "raw" | "pkcs8" | "spki", keyData: Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer, algorithm: string | core.ImportAlgorithms, extractable: boolean, keyUsages: string[], attrs?: Partial<Pkcs11KeyAttributes>): Promise<CryptoKey>;
  public importKey(format: string, keyData: Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer | JsonWebKey, algorithm: string | core.ImportAlgorithms, extractable: boolean, keyUsages: string[], attrs?: Partial<Pkcs11KeyAttributes>): Promise<CryptoKey>;
  public sign(algorithm: string | AesCmacParams | RsaPssParams | EcdsaParams, key: CryptoKey, data: Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer): Promise<ArrayBuffer>;
  public unwrapKey(format: string, wrappedKey: Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer, unwrappingKey: CryptoKey, unwrapAlgorithm: string | Algorithm, unwrappedKeyAlgorithm: string | Algorithm, extractable: boolean, keyUsages: string[], attrs?: Partial<Pkcs11KeyAttributes>): Promise<CryptoKey>;
  public verify(algorithm: string | AesCmacParams | RsaPssParams | EcdsaParams, key: CryptoKey, signature: Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer, data: Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer): Promise<boolean>;
  public wrapKey(format: string, key: CryptoKey, wrappingKey: CryptoKey, wrapAlgorithm: string | Algorithm): Promise<ArrayBuffer>;
}

declare class KeyStorage implements core.CryptoKeyStorage {
  public constructor(crypto: Crypto)
  public getItem(index: string): Promise<CryptoKey>;
  public getItem(index: string, algorithm: core.ImportAlgorithms, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey>;
  public keys(): Promise<string[]>;
  public indexOf(item: CryptoKey): Promise<string | null>;
  public setItem(item: CryptoKey, attrs?: Partial<Pkcs11KeyAttributes>): Promise<string>;
  public hasItem(item: CryptoKey): Promise<boolean>;
  public clear(): Promise<void>;
  public removeItem(index: string): Promise<void>;
}

export interface IGetValue {
  /**
   * Returns item blob
   * @param key Object identifier
   */
  getValue(key: string): Promise<ArrayBuffer | null>
}

export class CertificateStorage implements core.CryptoCertificateStorage, IGetValue {
  public constructor(crypto: Crypto)
  public getValue(index: string): Promise<ArrayBuffer | null>;
  public getItem(index: string): Promise<CryptoCertificate>;
  public getItem(index: string, algorithm: core.ImportAlgorithms, keyUsages: KeyUsage[]): Promise<CryptoCertificate>;
  public exportCert(format: core.CryptoCertificateFormat, item: core.CryptoCertificate): Promise<string | ArrayBuffer>;
  public exportCert(format: "raw", item: CryptoCertificate): Promise<ArrayBuffer>;
  public exportCert(format: "pem", item: CryptoCertificate): Promise<string>;
  public importCert(format: core.CryptoCertificateFormat, data: BufferSource | string, algorithm: core.ImportAlgorithms, keyUsages: KeyUsage[], attrs?: Partial<Pkcs11CertificateAttributes>): Promise<CryptoCertificate>;
  public importCert(format: "raw", data: BufferSource, algorithm: core.ImportAlgorithms, keyUsages: KeyUsage[], attrs?: Partial<Pkcs11CertificateAttributes>): Promise<CryptoCertificate>;
  public importCert(format: "pem", data: string, algorithm: core.ImportAlgorithms, keyUsages: KeyUsage[], attrs?: Partial<Pkcs11CertificateAttributes>): Promise<CryptoCertificate>;
  public keys(): Promise<string[]>;
  public indexOf(item: CryptoCertificate): Promise<string | null>;
  public setItem(item: CryptoCertificate, attrs?: Partial<Pkcs11CertificateAttributes>): Promise<string>;
  public hasItem(item: CryptoCertificate): Promise<boolean>;
  public clear(): Promise<void>;
  public removeItem(index: string): Promise<void>;
}

export class Crypto implements core.NativeCrypto, core.CryptoStorages {
  public keyStorage: KeyStorage;
  public certStorage: CertificateStorage;
  public subtle: SubtleCrypto;

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

export declare class CryptoKey extends core.CryptoKey implements Pkcs11KeyAttributes {
  public readonly token: boolean;
  public readonly sensitive?: boolean | undefined;
  public readonly label: string;
  public readonly algorithm: KeyAlgorithm;
  private constructor();
}

export interface CryptoKeyPair {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}

export declare class CryptoCertificate implements core.CryptoCertificate, Pkcs11CertificateAttributes {
  public readonly token: boolean;
  public readonly label: string;
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
