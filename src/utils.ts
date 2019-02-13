import * as crypto from "crypto";
import { Session, Slot, SlotFlag } from "graphene-pk11";
import { Convert } from "pvtsutils";
import { ID_DIGEST } from "./const";

export interface HashedAlgorithm extends Algorithm {
  hash: AlgorithmIdentifier;
}

export function GUID(session: Session): Buffer {
  return crypto.randomBytes(20);
}

export function b64UrlDecode(b64url: string): Buffer {
  return Buffer.from(Convert.FromBase64Url(b64url));
}

/**
 * Prepare array of data before it's using
 * @param data Array which must be prepared
 */
export function prepareData(data: NodeBufferSource): Buffer {
  return ab2b(data);
}

export function isHashedAlgorithm(data: any): data is HashedAlgorithm {
  return data instanceof Object
    && "name" in data
    && "hash" in data;
}

export function prepareAlgorithm(algorithm: AlgorithmIdentifier): Algorithm {
  if (typeof algorithm === "string") {
    return {
      name: algorithm,
    } as Algorithm;
  }
  if (isHashedAlgorithm(algorithm)) {
    const preparedAlgorithm = { ...algorithm };
    preparedAlgorithm.hash = this.prepareAlgorithm(algorithm.hash);
    return preparedAlgorithm as HashedAlgorithm;
  }
  return { ...algorithm };
}

/**
 * Converts ArrayBuffer to Buffer
 * @param ab ArrayBuffer value which must be converted to Buffer
 */
function ab2b(ab: NodeBufferSource) {
  return Buffer.from(ab as any);
}

/**
 * Calculates digest for given data
 * @param algorithm
 * @param data
 */
export function digest(algorithm: string, data: NodeBufferSource): Buffer {
  const hash = crypto.createHash(algorithm.replace("-", ""));
  hash.update(prepareData(data));
  return hash.digest();
}

function calculateProviderID(slot: Slot) {
  const str = slot.manufacturerID + slot.slotDescription + slot.getToken().serialNumber + slot.handle.toString("hex");
  return digest(ID_DIGEST, Buffer.from(str)).toString("hex");
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

  const token = slot.getToken();
  const provider: IProvider = {
    id: calculateProviderID(slot),
    slot: index,
    name: token.label,
    reader: slot.slotDescription,
    serialNumber: slot.getToken().serialNumber,
    algorithms: [],
    isRemovable: !!(slot.flags & SlotFlag.REMOVABLE_DEVICE),
    isHardware: !!(slot.flags & SlotFlag.HW_SLOT),
  };

  const algorithms = slot.getMechanisms();
  for (let i = 0; i < algorithms.length; i++) {
    const algorithm = algorithms.items(i);
    let algName = "";
    switch (algorithm.name) {
      case "SHA_1":
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
      case "ECDSA":
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
      case "AES_ECB":
      case "AES_ECB_PAD":
        algName = "AES-ECB";
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
