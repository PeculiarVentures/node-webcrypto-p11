/**
 * Opens PKCS#11 module and prints to stdout JSON information about it's slots
 *
 * args:
 *   - path to PKCS#11 library
 */

import { Module } from "graphene-pk11";
import { getProviderInfo } from "./utils";

// get arguments from process
const libPath = process.argv[2];
const mod = Module.load(libPath);

try {
    mod.initialize();

    const slots = mod.getSlots(true);

    const info: IModule = {
        name: mod.libraryDescription,
        providers: [],
    };
    for (let i = 0; i < slots.length; i++) {
        const slot = slots.items(i);
        const provider = getProviderInfo(slot);

        info.providers.push(provider);
    }
    console.log(JSON.stringify(info));

} catch (err) {
    console.log(-1);
}
mod.finalize();
