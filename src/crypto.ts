/// <reference path="./typings/index.d.ts" />

// Core
import * as core from "webcrypto-core";
const WebCryptoError = core.CryptoError;

import * as graphene from "graphene-pk11";
import { CertificateStorage } from "./cert_storage";
import { KeyStorage } from "./key_storage";
import { SubtleCrypto } from "./subtle";
import * as utils from "./utils";

// Fix btoa and atob for NodeJS
(global as any).btoa = (data: string) => Buffer.from(data, "binary").toString("base64");
(global as any).atob = (data: string) => Buffer.from(data, "base64").toString("binary");

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

  public info?: ProviderInfo;
  public subtle: SubtleCrypto;

  public keyStorage: KeyStorage;
  public certStorage: CertificateStorage;
  public isReadWrite: boolean;
  public isLoggedIn: boolean;
  public isLoginRequired: boolean;

  /**
   * PKCS11 Module
   * @internal
   */
  public module?: graphene.Module;
  /**
   * PKCS11 Slot
   * @internal
   */
  public slot: graphene.Slot;
  /**
   * PKCS11 Token
   * @internal
   */
  public token: graphene.Token;
  /**
   * PKCS11 token
   * @internal
   */
  public session?: graphene.Session;

  protected name?: string;

  private initialized: boolean;

  /**
   * Creates an instance of WebCrypto.
   * @param props PKCS11 module init parameters
   */
  constructor(props: CryptoParams) {
    const mod = graphene.Module.load(props.library, props.name || props.library);
    this.name = props.name;
    try {
      if (props.libraryParameters) {
        mod.initialize({
          libraryParameters: props.libraryParameters,
        });
      } else {
        mod.initialize();
      }
    } catch (e) {
      if (!/CKR_CRYPTOKI_ALREADY_INITIALIZED/.test(e.message)) {
        throw e;
      }
    }
    this.initialized = true;

    const slotIndex = props.slot || 0;
    const slots = mod.getSlots(true);
    if (!(0 <= slotIndex && slotIndex < slots.length)) {
      throw new WebCryptoError(`Slot by index ${props.slot} is not found`);
    }
    this.slot = slots.items(slotIndex);
    this.token = this.slot.getToken();
    this.isLoginRequired = !!(this.token.flags & graphene.TokenFlag.LOGIN_REQUIRED);
    this.isLoggedIn = !this.isLoginRequired;
    this.isReadWrite = !!props.readWrite;
    this.open(props.readWrite);

    if (props.pin && this.isLoginRequired) {
      this.login(props.pin);
    }
    for (const i in props.vendors!) {
      graphene.Mechanism.vendor(props.vendors![i]);
    }

    this.subtle = new SubtleCrypto(this);
    this.keyStorage = new KeyStorage(this);
    this.certStorage = new CertificateStorage(this);
  }

  public open(rw?: boolean) {
    let flags = graphene.SessionFlag.SERIAL_SESSION;
    if (rw) {
      flags |= graphene.SessionFlag.RW_SESSION;
    }
    this.session = this.slot.open(flags);
    this.info = utils.getProviderInfo(this.slot);
    if (this.name) {
      this.info.name = this.name;
    }
  }

  public reset() {
    Crypto.assertSession(this.session);
    if (this.isLoggedIn && this.isLoginRequired) {
      this.logout();
    }
    this.session.close();

    this.open(this.isReadWrite);
  }

  public login(pin: string) {
    if (!this.isLoginRequired) {
      return;
    }
    Crypto.assertSession(this.session);

    try {
      this.session.login(pin);
    } catch (error) {
      if (!/CKR_USER_ALREADY_LOGGED_IN\:256/.test(error.message)) {
        throw error;
      }
    }

    this.isLoggedIn = true;
  }

  public logout() {
    if (!this.isLoginRequired) {
      return;
    }
    Crypto.assertSession(this.session);

    try {
      this.session.logout();
    } catch (error) {
      if (!/CKR_USER_NOT_LOGGED_IN\:257/.test(error.message)) {
        throw error;
      }
    }

    this.isLoggedIn = false;
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
    if (this.initialized) {
      Crypto.assertSession(this.session);
      Crypto.assertModule(this.module);

      this.session.logout();
      this.session.close();
      this.module.finalize();
      this.module.close();
    }
  }
}
