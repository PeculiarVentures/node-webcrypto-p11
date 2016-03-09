import {Module, Mechanism, Session, Slot, SessionFlag} from "graphene-pk11";
import {P11SubtleCrypto} from "./subtlecrypto";

/**
 * PKCS11 with WebCrypto Interface
 */
export class WebCrypto implements Crypto, RandomSource {

    private module: Module;
    private session: Session;
    private slot: Slot;
    private initialized: boolean;

    public subtle: SubtleCrypto = null;

    /**
     * Generates cryptographically random values
     * @param  {ArrayBufferView} array
     * @returns ArrayBufferView
     */
    getRandomValues(array: ArrayBufferView): ArrayBufferView {
        return new Uint8Array(this.session.generateRandom(array.byteLength));
    }

    /**
     * @param  {P11WebCryptoParams} params PKCS11 module init parameters
     */
    constructor(params: P11WebCryptoParams) {
        let mod = this.module = Module.load(params.library, params.name);
        mod.initialize();
        this.initialized = true;

        let slot = mod.getSlots(params.slot);
        if (!slot)
            throw new Error(`Slot by index ${params.slot} is not found`);
        this.session = slot.open(params.slotFlags);
        this.session.login(params.pin);
        for (let i in params.vendors){
            Mechanism.vendor(params.vendors[i]);
        }
        this.subtle = new P11SubtleCrypto(this.session);
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
    slotFlags?: number;
    /**
     * PIN of slot
     */
    pin?: string;
    /**
     * list of vendor json files
     */
    vendors: string[];
}
