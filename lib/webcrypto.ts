// Core
import * as webcrypto from "webcrypto-core";
const WebCryptoError = webcrypto.WebCryptoError;

import { Mechanism, Module, Session, Slot } from "graphene-pk11";
import { KeyStorage } from "./key_storage";
import { SubtleCrypto } from "./subtle";
import * as utils from "./utils";
import { CertificateStorage } from "./cert_storage";

const ERR_RANDOM_VALUE_LENGTH = "Failed to execute 'getRandomValues' on 'Crypto': The ArrayBufferView's byte length (%1) exceeds the number of bytes of entropy available via this API (65536).";

// Fix btoa and atob for NodeJS
let _global = global as any;
_global.btoa = (data: string) => new Buffer(data, "binary").toString("base64");
_global.atob = (data: string) => new Buffer(data, "base64").toString("binary");

/**
 * PKCS11 with WebCrypto Interface
 */
export class WebCrypto implements NativeCrypto {

    public subtle: SubtleCrypto;
    public keyStorage: KeyStorage;
    public certStorage: CertificateStorage;

    private module: Module;
    private session: Session;
    private slot: Slot;
    private initialized: boolean;

    /**
     * Creates an instance of WebCrypto.
     * @param {P11WebCryptoParams} props PKCS11 module init parameters
     *
     * @memberOf WebCrypto
     */
    constructor(props: P11WebCryptoParams) {
        const mod = this.module = Module.load(props.library, props.name);
        mod.initialize();
        this.initialized = true;

        this.slot = mod.getSlots(props.slot);
        if (!this.slot) {
            throw new WebCryptoError(`Slot by index ${props.slot} is not found`);
        }

        this.session = this.slot.open(props.sessionFlags);
        this.session.login(props.pin!);
        for (const i in props.vendors!) {
            Mechanism.vendor(props.vendors![i]);
        }

        this.subtle = new SubtleCrypto(this.session);
        this.keyStorage = new KeyStorage(this.session);
        this.certStorage = new CertificateStorage(this.session);
    }

    /**
     * Generates cryptographically random values
     * @param array Initialize array
     */
    // Based on: https://github.com/KenanY/get-random-values
    public getRandomValues(array: NodeBufferSource): NodeBufferSource;
    public getRandomValues(array: ArrayBufferView): ArrayBufferView;
    public getRandomValues(array: NodeBufferSource): NodeBufferSource {
        if (array.byteLength > 65536) {
            const error = new webcrypto.WebCryptoError(ERR_RANDOM_VALUE_LENGTH, array.byteLength);
            error.code = 22;
            throw error;
        }
        const bytes = new Uint8Array(this.session.generateRandom(array.byteLength));
        (array as Uint8Array).set(bytes);
        return array;
    }

    public getGUID() {
        return utils.GUID(this.session);
    }

    /**
     * Close PKCS11 module
     */
    public close() {
        if (this.initialized) {
            this.session.logout();
            this.session.close();
            this.module.finalize();
        }
    }
}
