// Core
import * as webcrypto from "webcrypto-core";
const WebCryptoError = webcrypto.WebCryptoError;

import { Module, Mechanism, Session, Slot } from "graphene-pk11";
import { SubtleCrypto } from "./subtle";
import { KeyStorage } from "./key_storage";
import * as utils from "./utils";

const ERR_RANDOM_VALUE_LENGTH = "Failed to execute 'getRandomValues' on 'Crypto': The ArrayBufferView's byte length (%1) exceeds the number of bytes of entropy available via this API (65536).";

// Fix btoa and atob for NodeJS
let _global = global as any;
_global.btoa = (data: string) => new Buffer(data, "binary").toString("base64");
_global.atob = (data: string) => new Buffer(data, "base64").toString("binary");

/**
 * PKCS11 with WebCrypto Interface
 */
export class WebCrypto implements NativeCrypto {

    private module: Module;
    private session: Session;
    private slot: Slot;
    private initialized: boolean;

    public subtle: SubtleCrypto;

    keyStorage: KeyStorage;

    /**
     * Generates cryptographically random values
     * @param array Initialize array
     */
    // Based on: https://github.com/KenanY/get-random-values
    getRandomValues(array: NodeBufferSource): NodeBufferSource;
    getRandomValues(array: ArrayBufferView): ArrayBufferView;
    getRandomValues(array: NodeBufferSource): NodeBufferSource {
        if (array.byteLength > 65536) {
            let error = new webcrypto.WebCryptoError(ERR_RANDOM_VALUE_LENGTH, array.byteLength);
            error.code = 22;
            throw error;
        }
        let bytes = new Uint8Array(this.session.generateRandom(array.byteLength));
        (array as Uint8Array).set(bytes);
        return array;
    }

    getGUID() {
        return utils.GUID(this.session);
    }

    /**
     * @param  {P11WebCryptoParams} props PKCS11 module init parameters
     */
    constructor(props: P11WebCryptoParams) {
        let mod = this.module = Module.load(props.library, props.name);
        mod.initialize();
        this.initialized = true;
        this.slot = mod.getSlots(props.slot);
        if (!this.slot)
            throw new WebCryptoError(`Slot by index ${props.slot} is not found`);
        this.session = this.slot.open(props.sessionFlags);
        this.session.login(props.pin!);
        for (let i in props.vendors!) {
            Mechanism.vendor(props.vendors![i]);
        }
        this.subtle = new SubtleCrypto(this.session);
        this.keyStorage = new KeyStorage(this.session);
    }

    /**
     * Close PKCS11 module
     */
    close() {
        if (this.initialized) {
            this.session.logout();
            this.session.close();
            this.module.finalize();
        }
    }
}

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