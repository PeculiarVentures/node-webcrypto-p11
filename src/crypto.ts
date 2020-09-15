/// <reference path="./typings/index.d.ts" />

// Core
import * as core from "webcrypto-core";
import * as graphene from "graphene-pk11";
import { CertificateStorage } from "./cert_storage";
import { KeyStorage } from "./key_storage";
import { SubtleCrypto } from "./subtle";
import * as utils from './utils';
import { CryptoModule, CryptoModuleInitParams } from './module';

export enum CryptoTokenFlags {
  RNG = 0x00000001,
  writeProtected = 0x00000002,
  loginRequired = 0x00000004,
  userPinInitialized = 0x00000008,
  restoreKeyNotNeeded = 0x00000020,
  ClockOnToken = 0x00000040,
  protectedAuthenticationPath = 0x00000100,
  dualCryptoOperations = 0x00000200,
  tokenInitialized = 0x00000400,
  secondaryAuthentication = 0x00000800,
  userPinCountLow = 0x00010000,
  userPinFinalTry = 0x00020000,
  userPinLocked = 0x00040000,
  userPinToBeChanged = 0x00080000,
  soPinCountLow = 0x00100000,
  soPinFinalTry = 0x00200000,
  soPinLocked = 0x00400000,
  soPinToBeChanged = 0x00800000,
  errorState = 0x01000000,
}

export interface CryptoVersions {
  hardware: string;
  firmware: string;
}

export interface CryptoTokenInfo {
  manufacturer: string;
  flags: CryptoTokenFlags;
  model: string;
  label: string;
  serialNumber: string;
  versions: CryptoVersions;
}

export interface CryptoInfo {
  description: string;
  manufacturer: string;
  removable: boolean;
  hardware: boolean;
  token?: CryptoTokenInfo;
  versions: CryptoVersions
}

export interface CryptoInitParams extends CryptoModuleInitParams {
  slot: number | string;
  readWrite?: boolean;
  pin?: string;
}

/**
 * PKCS11 with WebCrypto Interface
 */
export class Crypto implements core.Crypto, core.CryptoStorages {

  public static assertSession(obj: graphene.Session | undefined): asserts obj is graphene.Session {
    if (!obj) {
      throw new Error("PKCS#11 session is not initialized");
    }
  }

  public static assertModule(obj: graphene.Module | undefined): asserts obj is graphene.Module {
    if (!obj) {
      throw new Error("PKCS#11 module is not initialized");
    }
  }

  public subtle: SubtleCrypto;
  public keyStorage: KeyStorage;
  public certStorage: CertificateStorage;
  public readWrite: boolean = false;

  /**
   * PKCS11 Slot
   * @internal
   */
  private slot: graphene.Slot;
  /**
   * PKCS11 session
   * @internal
   */
  public session?: graphene.Session;

  /**
   * Creates an instance of WebCrypto.
   * @param params PKCS11 init params
   * @internal
   */
  public constructor(slot: CryptoInitParams);
  /**
   * Creates an instance of WebCrypto.
   * @param slot PKCS11 module init parameters
   * @internal
   */
  public constructor(slot: graphene.Slot);
  public constructor(params: graphene.Slot | CryptoInitParams) {
    if (params instanceof graphene.Slot) {
      this.slot = params
    } else {
      const prov = new CryptoModule(params)
      const crypto = prov.getItem(params.slot);
      if (!crypto) {
        throw new Error(`Cannot load slot '${params.slot}' for '${params.library}' library. Slot is not found`);
      }
      this.slot = crypto.slot;
    }

    this.subtle = new SubtleCrypto(this);
    this.keyStorage = new KeyStorage(this);
    this.certStorage = new CertificateStorage(this);

    if (!(params instanceof graphene.Slot)) {
      this.readWrite = !!params.readWrite;
      this.open(this.readWrite);
      if (params.pin) {
        this.login(params.pin);
      }
    } else {
      this.open();
    }
  }

  public info() {
    const p11Slot = this.slot;

    const info: CryptoInfo = {
      manufacturer: p11Slot.manufacturerID,
      description: p11Slot.slotDescription,
      removable: !!(p11Slot.flags & graphene.SlotFlag.REMOVABLE_DEVICE),
      hardware: !!(p11Slot.flags & graphene.SlotFlag.HW_SLOT),
      versions: {
        hardware: utils.getVersion(this.slot.hardwareVersion),
        firmware: utils.getVersion(this.slot.firmwareVersion),
      }
    };

    if (this.slot.flags & graphene.SlotFlag.TOKEN_PRESENT) {
      info.token = this.tokenInfo();
    }

    return info;
  }

  public tokenInfo() {
    const p11Token = this.slot.getToken();

    const info: CryptoTokenInfo = {
      manufacturer: p11Token.manufacturerID,
      model: p11Token.model,
      label: p11Token.label,
      serialNumber: p11Token.serialNumber,
      versions: {
        hardware: utils.getVersion(this.slot.hardwareVersion),
        firmware: utils.getVersion(this.slot.firmwareVersion),
      },
      flags: p11Token.flags,
    };

    return info;
  }

  public mechanismInfo() {
    const algorithms = this.slot.getMechanisms();
    const info: string[] = [];

    for (let i = 0; i < algorithms.length; i++) {
      const algorithm = algorithms.tryGetItem(i);
      if (!algorithm) {
        continue;
      }

      let algName = "";
      switch (algorithm.name) {
        case "SHA_1":
          algName = "SHA-1";
          break;
        case "SHA256":
          algName = "SHA-256";
          break;
        case "SHA384":
          algName = "SHA-384";
          break;
        case "SHA512":
          algName = "SHA-512";
          break;
        case "RSA_PKCS":
        case "SHA1_RSA_PKCS":
        case "SHA256_RSA_PKCS":
        case "SHA384_RSA_PKCS":
        case "SHA512_RSA_PKCS":
          algName = "RSASSA-PKCS1-v1_5";
          break;
        case "SHA1_RSA_PSS":
        case "SHA256_RSA_PSS":
        case "SHA384_RSA_PSS":
        case "SHA512_RSA_PSS":
          algName = "RSA-PSS";
          break;
        case "SHA1_RSA_PKCS_PSS":
        case "SHA256_RSA_PKCS_PSS":
        case "SHA384_RSA_PKCS_PSS":
        case "SHA512_RSA_PKCS_PSS":
          algName = "RSA-PSS";
          break;
        case "RSA_PKCS_OAEP":
          algName = "RSA-OAEP";
          break;
        case "ECDSA":
        case "ECDSA_SHA1":
        case "ECDSA_SHA256":
        case "ECDSA_SHA384":
        case "ECDSA_SHA512":
          algName = "ECDSA";
          break;
        case "ECDH1_DERIVE":
          algName = "ECDH";
          break;
        case "AES_CBC_PAD":
          algName = "AES-CBC";
          break;
        case "AES_ECB":
        case "AES_ECB_PAD":
          algName = "AES-ECB";
          break;
        case "AES_GCM_PAD":
          algName = "AES-GCM";
          break;
        case "AES_KEY_WRAP_PAD":
          algName = "AES-KW";
          break;
        case "SHA_1_HMAC":
          algName = "HMAC";
          break;
        case "SHA_1_HMAC":
        case "SHA256_HMAC":
        case "SHA384_HMAC":
        case "SHA512_HMAC":
          algName = "HMAC";
          break;
        default:
      }
      if (algName && !info.includes(algName)) {
        info.push(algName);
      }
    }

    return info.sort();
  }

  public open(readWrite: boolean = this.readWrite) {
    let flags = graphene.SessionFlag.SERIAL_SESSION;
    if (readWrite) {
      flags |= graphene.SessionFlag.RW_SESSION;
    }

    this.session = this.slot.open(flags);
    this.readWrite = !!(this.session.flags & graphene.SessionFlag.RW_SESSION)
  }


  public reset() {
    Crypto.assertSession(this.session);

    this.session.close();
    this.open(this.readWrite);
  }

  public login(pin: string) {
    Crypto.assertSession(this.session);

    try {
      this.session.login(pin);
    } catch (error) {
      if (!/CKR_USER_ALREADY_LOGGED_IN\:256/.test(error.message)) {
        throw error;
      }
    }
  }

  public logout() {
    Crypto.assertSession(this.session);

    try {
      this.session.logout();
    } catch (error) {
      if (!/CKR_USER_NOT_LOGGED_IN\:257/.test(error.message)) {
        throw error;
      }
    }
  }

  /**
   * Generates cryptographically random values
   * @param array Initialize array
   */
  // Based on: https://github.com/KenanY/get-random-values
  public getRandomValues<T extends ArrayBufferView>(array: T): T {
    Crypto.assertSession(this.session);

    if (array.byteLength > 65536) {
      throw new core.CryptoError(`Failed to execute 'getRandomValues' on 'Crypto': The ArrayBufferView's byte length (${array.byteLength}) exceeds the number of bytes of entropy available via this API (65536).`);
    }
    const bytes = new Uint8Array(this.session.generateRandom(array.byteLength));
    (array as unknown as Uint8Array).set(bytes);
    return array;
  }

  /**
   * Close PKCS11 module
   */
  public close() {
    if (this.session) {
      this.session.logout();
      this.session.close();

      delete this.session;
    }
  }
}
