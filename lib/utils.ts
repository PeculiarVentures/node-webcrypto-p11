import * as crypto from "crypto";
import { Session, Slot } from "graphene-pk11";
import * as webcrypto from "webcrypto-core";

export function GUID(session: Session): string {
    const buf = crypto.randomBytes(10);
    // buf to string
    let bufStr = "";
    // tslint:disable-next-line:prefer-for-of
    for (let i = 0; i < buf.length; i++) {
        let str = buf[i].toString(32);
        if (str.length === 1) {
            str = "0" + str;
        }
        // some chars to Upper case
        let newStr = "";
        for (let j = 0; j < str.length; j++) {
            const isUpper = +Math.random().toString().slice(2, 3) % 2;
            if (isUpper) {
                newStr += str.charAt(j).toUpperCase();
            } else {
                newStr += str.charAt(j);
            }
        }
        bufStr += newStr;
    }
    // split chars to 4 groups
    const res: string[] = [];
    for (let i = 0; i < 4; i++) {
        const str = bufStr.slice(i * 5, (i + 1) * 5);
        // to upper case
        res.push(str);
    }
    return res.join("-");
}

export function b64_decode(b64url: string): Buffer {
    return new Buffer(webcrypto.Base64Url.decode(b64url));
}

/**
 * Prepare array of data before it's using
 * @param data Array which must be prepared
 */
export function PrepareData(data: NodeBufferSource): Buffer {
    return ab2b(data);
}

/**
 * Converts ArrayBuffer to Buffer
 * @param ab ArrayBuffer value which must be converted to Buffer
 */
function ab2b(ab: NodeBufferSource) {
    return new Buffer(ab as any);
}

/**
 * Calculates digest for given data
 * @param algorithm
 * @param data
 */
export function digest(algorithm: string, data: NodeBufferSource): Buffer {
    const hash = crypto.createHash(algorithm.replace("-", ""));
    hash.update(PrepareData(data));
    return hash.digest();
}

function calculateProviderID(slot: Slot) {
    const str = slot.manufacturerID + slot.slotDescription + slot.getToken().serialNumber + slot.handle.toString("hex");
    return digest("SHA-256", new Buffer(str)).toString("hex");
}

export function getProviderInfo(slot: Slot) {
    // get index of slot
    const slots = slot.module.getSlots(true);
    let index = -1;
    for (let i = 0; i < slots.length; i++) {
        if (slots.items(i).handle.equals(slot.handle)) {
            index = i;
            break;
        }
    }
    const provider: IProvider = {
        id: calculateProviderID(slot),
        slot: index,
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
            case "RSA_PKCS":
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

    return provider;
}
