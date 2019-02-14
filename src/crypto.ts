/// <reference path="./typings/index.d.ts" />

// Core
import * as core from "webcrypto-core";
const WebCryptoError = core.CryptoError;

import { Mechanism, Module, SessionFlag, TokenFlag } from "graphene-pk11";
import { CertificateStorage } from "./cert_storage";
import { KeyStorage } from "./key_storage";
import { P11Session } from "./p11_session";
import { SubtleCrypto } from "./subtle";
import * as utils from "./utils";

// Fix btoa and atob for NodeJS
(global as any).btoa = (data: string) => Buffer.from(data, "binary").toString("base64");
(global as any).atob = (data: string) => Buffer.from(data, "base64").toString("binary");

/**
 * PKCS11 with WebCrypto Interface
 */
export class Crypto implements core.Crypto, core.CryptoStorages {

  public info: ProviderInfo;
  public subtle: SubtleCrypto;

  public keyStorage: KeyStorage;
  public certStorage: CertificateStorage;
  public isReadWrite: boolean;
  public isLoggedIn: boolean;
  public isLoginRequired: boolean;

  public session = new P11Session();

  protected name?: string;

  private initialized: boolean;

  /**
   * Creates an instance of WebCrypto.
   * @param props PKCS11 module init parameters
   */
  constructor(props: CryptoParams) {
    const mod = Module.load(props.library, props.name || props.library);
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
    this.session.slot = slots.items(slotIndex);
    this.session.token = this.session.slot.getToken();
    this.isLoginRequired = !!(this.session.token.flags & TokenFlag.LOGIN_REQUIRED);
    this.isLoggedIn = !this.isLoginRequired;
    this.isReadWrite = !!props.readWrite;
    this.open(props.readWrite);

    if (props.pin && this.isLoginRequired) {
      this.login(props.pin);
    }
    for (const i in props.vendors!) {
      Mechanism.vendor(props.vendors![i]);
    }

    this.subtle = new SubtleCrypto(this.session);
    this.keyStorage = new KeyStorage(this);
    this.certStorage = new CertificateStorage(this);
  }

  public open(rw?: boolean) {
    let flags = SessionFlag.SERIAL_SESSION;
    if (rw) {
      flags |= SessionFlag.RW_SESSION;
    }
    this.session.value = this.session.slot.open(flags);
    this.info = utils.getProviderInfo(this.session.slot);
    if (this.name) {
      this.info.name = this.name;
    }
  }

  public reset() {
    if (this.isLoggedIn && this.isLoginRequired) {
      this.logout();
    }
    this.session.value.close();

    this.open(this.isReadWrite);
  }

  public login(pin: string) {
    if (!this.isLoginRequired) {
      return;
    }

    try {
      this.session.value.login(pin);
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

    try {
      this.session.value.logout();
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
    if (array.byteLength > 65536) {
      throw new core.CryptoError(`Failed to execute 'getRandomValues' on 'Crypto': The ArrayBufferView's byte length (${array.byteLength}) exceeds the number of bytes of entropy available via this API (65536).`);
    }
    const bytes = new Uint8Array(this.session.value.generateRandom(array.byteLength));
    (array as unknown as Uint8Array).set(bytes);
    return array;
  }

  /**
   * Close PKCS11 module
   */
  public close() {
    if (this.initialized) {
      this.session.value.logout();
      this.session.value.close();
      this.session.module.finalize();
      this.session.module.close();
    }
  }
}
