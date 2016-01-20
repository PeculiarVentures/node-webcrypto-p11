import {Module, Session, Slot} from "graphene-pk11";
import * as iwc from "./iwebcrypto";
import * as subtle from "./subtlecrypto";

/**
 * PKCS11 with WebCrypto Interface
 */
export default class P11WebCrypto implements iwc.IWebCrypto {

    private module: Module;
    private session: Session;
    private slot: Slot;
    private initialized: boolean;

    public subtle: iwc.ISubtleCrypto = null;

    /**
     * Generates cryptographically random values
     * @param array Initialize array
     */
    getRandomValues(array): any {
        return this.session.generateRandom(array.byteLength);
    }

    /**
     * Constructor
     * @param params Init params
     */
    constructor(params: P11WebCryptoParams) {
        let mod = this.module = Module.load(params.library, params.name);
        mod.initialize();
        let slots = mod.getSlots();
        let slot = this.slot = slots[params.slot];
        if (!slot)
            throw new Error("Slot by index " + params.slot + " is not found");
        let session = this.session = slot.session;
        session.start(2 | 4);
        session.login(params.pin);
        this.subtle = new subtle.P11SubtleCrypto(session);
    }

    /**
     * Close PKCS11 module
     */
    close() {
        if (this.initialized) {
            this.session.logout();
            this.session.stop();
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
    /**
     * PIN of slot
     */
    pin?: string;
}
