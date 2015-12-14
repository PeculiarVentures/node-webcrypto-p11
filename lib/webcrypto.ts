import {Module, Session, Slot} from "graphene-pk11";
import * as iwc from "./iwebcrypto"

/**
 * PKCS11 with WebCrypto Interface
 */
export default class P11WebCrypto implements iwc.IWebCrypto {

    private module: Module;
    private session: Session;
    private slot: Slot;
    private initialized: boolean;

    public subtle: iwc.ISubtleCrypto;
    
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
        var mod = this.module = Module.load(params.library, params.name);
        mod.initialize();
        var slots = mod.getSlots();
        var slot = this.slot = slots[params.slot];
        if (!slot)
            throw new Error('Slot by index ' + params.slot + ' is not found');
        var session = this.session = slot.session;
        session.start();
        session.login(params.pin);
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
    library: string 
    /**
     * Name of PKCS11 module
     */
    name: string,
    /**
     * Index of slot
     */
    slot: number,  
    /**
     * PIN of slot
     */
    pin?: string
}
