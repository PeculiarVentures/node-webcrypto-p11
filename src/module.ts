import * as graphene from "graphene-pk11";
import * as utils from './utils';

export interface CryptoModuleInitParams {
  /**
   * Path to library
   */
  library: string;
  /**
   * Name of PKCS11 module
   */
  name?: string;
  /**
   * list of vendor json files
   */
  vendors?: { [key: string]: number };
  /**
   * NSS library parameters
   * @see https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/PKCS11/Module_Specs#NSS_Specific_Parameters_in_Module_Specs
   * @example
   * ```js
   * "configdir='' certPrefix='' keyPrefix='' secmod='' flags=readOnly,noCertDB,noModDB,forceOpen,optimizeSpace"
   * ```
   */
  libraryParameters?: string;
  /**
   * Indicates whether the list obtained includes only those slots with a token present
   */
  tokenPresent?: boolean;
}

export interface CryptoModuleInformation {
  /**
   * Path to PKCS# library
   */
  library: string;
  /**
   * ID of the Cryptoki library manufacturer
   */
  manufacturer: string;
  /**
   * List of Cryptoki version
   */
  versions: {
    /**
     * Cryptoki interface version number
     */
    cryptoki: string;
    /**
     * Cryptoki library version number
     */
    library: string;
  };
  /**
   * Character-string description of the library
   */
  description: string;
}

export class CryptoModule {

  private module: graphene.Module;
  private initialized = false;

  protected options: CryptoModuleInitParams;


  public get length() {
    return this.module.getSlots(this.options.tokenPresent);
  }

  public constructor(options: CryptoModuleInitParams) {
    this.options = options;
    this.module = graphene.Module.load(this.options.library, this.options.name);

    this.initialize();
  }

  /**
   * Returns information about PKCS#11 module
   */
  public info() {
    const info: CryptoModuleInformation = {
      library: this.options.library,
      manufacturer: this.module.manufacturerID,
      versions: {
        cryptoki: utils.getVersion(this.module.cryptokiVersion),
        library: utils.getVersion(this.module.libraryVersion),
      },
      description: this.module.libraryDescription,
    };

    return info;
  }

  /**
   * Returns a list of Crypto objects
   * @param cb Fires on error
   */
  public items(cb?: (e: Error, slot: graphene.Slot, slots: Crypto[]) => void) {
    const slots = this.module.getSlots(this.options.tokenPresent);
    const res: Crypto[] = [];
    for (const slot of slots) {
      try {
        res.push(new Crypto(slot));
      } catch (e) {
        cb?.(e, slot, res);
      }
    }
    return res;
  }

  /**
   * Returns a Crypto object or null if slot does not exist
   * @param indexOrName Slot index or PKCS#11 slot description
   */
  public getItem(indexOrName: number | string) {
    if (typeof indexOrName === "number") {
      const slots = this.module.getSlots(this.options.tokenPresent);
      if (slots.length > indexOrName) {
        return new Crypto(slots.items(indexOrName));
      }
    } else {
      const slots = this.module.getSlots(this.options.tokenPresent);
      for (const slot of slots) {
        if (slot.slotDescription === indexOrName) {
          return new Crypto(slot);
        }
      }
    }
    return null;
  }

  /**
   * Initializes the Cryptoki library
   */
  public initialize() {
    if (!this.initialized) {
      this.module = graphene.Module.load(this.options.library, this.options.name);
    }

    if (this.options.libraryParameters) {
      this.module.initialize({
        libraryParameters: this.options.libraryParameters,
      });
    } else {
      this.module.initialize();
    }
    this.initialized = true;

    if (this.options.vendors) {
      for (const key in this.options.vendors) {
        graphene.Mechanism.vendor(key, this.options.vendors[key]);
      }
    }
  }

  /**
   * Close the Cryptoki module
   */
  public close() {
    if (this.initialized) {
      this.module.finalize();
      this.module.close();

      this.initialized = false;
    }
  }

}

import { Crypto } from './crypto';