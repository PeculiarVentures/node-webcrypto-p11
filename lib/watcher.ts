import * as crypto from "crypto";
import { Module } from "graphene-pk11";

const libPath = process.argv[2];
const mod = Module.load(libPath);

function CalculateID(data: string) {
    const digest = crypto.createHash("SHA256");
    digest.update(data);
    return digest.digest("hex");
}


try {
    mod.initialize();

    const slots = mod.getSlots(true);

    const info: IModule = {
        name: mod.libraryDescription,
        providers: [],
    };
    for (let i = 0; i < slots.length; i++) {
        const slot = slots.items(i);
        const provider: IProvider = {
            id: CalculateID(slot.manufacturerID + slot.slotDescription + slot.getToken().serialNumber + i.toString()),
            name: slot.slotDescription,
            serialNumber: slot.getToken().serialNumber,
            algorithms: [],
        };

        const algorithms = slot.getMechanisms();
        for (let i = 0; i < algorithms.length; i++) {
            const algorithm = algorithms.items(i);
            let algName = "";
            switch (algorithm.name) {
                case "SHA1":
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
                case "AES_GCM_PAD":
                    algName = "AES-GCM";
                    break;
                case "AES_KEY_WRAP_PAD":
                    algName = "AES-KW";
                    break;
                default:
            }
            if (algName && !provider.algorithms.some((alg) => alg === algName)) {
                provider.algorithms.push(algName);
            }

        }

        info.providers.push(provider);
    }
    console.log(JSON.stringify(info));

} catch (err) {
    console.log(-1);
}
mod.finalize();
