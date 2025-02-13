import * as crypto from "crypto";
import * as graphene from "graphene-pk11";
import * as pvtsutils from "pvtsutils";
import * as core from "webcrypto-core";
import { ID_DIGEST } from "./const";
import { ISessionContainer, ProviderInfo } from "./types";
import { CryptoKey } from "./key";

export interface HashedAlgorithm extends Algorithm {
  hash: AlgorithmIdentifier;
}

export function GUID(): Buffer {
  return crypto.randomBytes(20);
}

export function b64UrlDecode(b64url: string): Buffer {
  return Buffer.from(pvtsutils.Convert.FromBase64Url(b64url));
}

/**
 * Converts BufferSource to Buffer
 * @param data Array which must be prepared
 */
export function prepareData(data: BufferSource): Buffer {
  return Buffer.from(pvtsutils.BufferSourceConverter.toArrayBuffer(data));
}

export function isHashedAlgorithm(data: unknown): data is HashedAlgorithm {
  return data instanceof Object
    && "name" in data
    && "hash" in data;
}

export function isCryptoKeyPair(data: unknown): data is CryptoKeyPair {
  return data instanceof Object
    && "privateKey" in data
    && "publicKey" in data;
}

export function prepareAlgorithm(algorithm: AlgorithmIdentifier): Algorithm {
  if (typeof algorithm === "string") {
    return {
      name: algorithm,
    } as Algorithm;
  }
  if (isHashedAlgorithm(algorithm)) {
    const preparedAlgorithm = { ...algorithm };
    preparedAlgorithm.hash = prepareAlgorithm(algorithm.hash);
    return preparedAlgorithm as HashedAlgorithm;
  }
  return { ...algorithm };
}

/**
 * Calculates digest for given data
 * @param algorithm
 * @param data
 */
export function digest(algorithm: string, data: BufferSource): Buffer {
  const hash = crypto.createHash(algorithm.replace("-", ""));
  hash.update(prepareData(Buffer.from(pvtsutils.BufferSourceConverter.toArrayBuffer(data))));
  return hash.digest();
}

function calculateProviderID(slot: graphene.Slot): string {
  const str = slot.manufacturerID + slot.slotDescription + slot.getToken().serialNumber + slot.handle.toString("hex");
  return digest(ID_DIGEST, Buffer.from(str)).toString("hex");
}

export function getProviderInfo(slot: graphene.Slot): ProviderInfo {
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
  const provider: ProviderInfo = {
    id: calculateProviderID(slot),
    slot: index,
    name: token.label,
    reader: slot.slotDescription,
    serialNumber: slot.getToken().serialNumber,
    algorithms: [],
    isRemovable: !!(slot.flags & graphene.SlotFlag.REMOVABLE_DEVICE),
    isHardware: !!(slot.flags & graphene.SlotFlag.HW_SLOT),
  };

  const algorithms = slot.getMechanisms();
  for (let i = 0; i < algorithms.length; i++) {
    const algorithm = algorithms.tryGetItem(i);
    if (!algorithm) {
      continue;
    }

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

export type OperationType = "decrypt" | "sign";

/**
 * Checks and calls `onAlwaysAuthenticate` method
 * @param key Crypto key
 * @param container Crypto container
 * @param operation Operation type
 * @throws Throws CryptoError if `alwaysAuthenticate` is enabled for the key and `onAlwaysAuthenticate` method of the container is undefined
 */
export async function alwaysAuthenticate(
  key: CryptoKey,
  container: ISessionContainer,
  operation: OperationType,
): Promise<void> {
  if (key.key instanceof graphene.PrivateKey && key.key.alwaysAuthenticate) {
    if (!container.onAlwaysAuthenticate) {
      throw new core.CryptoError("Crypto key requires re-authentication, but Crypto doesn't have 'onAlwaysAuthenticate' method");
    }

    const pin = await container.onAlwaysAuthenticate(key, container, operation);
    if (pin) {
      container.session.login(pin, graphene.UserType.CONTEXT_SPECIFIC);
    }
  }
}