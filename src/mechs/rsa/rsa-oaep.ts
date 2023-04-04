import * as crypto from "crypto";
import * as graphene from "graphene-pk11";
import * as core from "webcrypto-core";

import { CryptoKey } from "../../key";
import * as types from "../../types";
import { alwaysAuthenticate } from "../../utils";
import { ShaCrypto } from "../sha/crypto";

import { RsaCrypto } from "./crypto";
import { RsaCryptoKey } from "./key";

export class RsaOaepProvider extends core.RsaOaepProvider implements types.IContainer {

  public override usages: core.ProviderKeyPairUsage = {
    privateKey: ["sign", "decrypt", "unwrapKey"],
    publicKey: ["verify", "encrypt", "wrapKey"],
  };
  public crypto: RsaCrypto;

  constructor(public container: types.ISessionContainer) {
    super();

    this.crypto = new RsaCrypto(container);
  }

  public async onGenerateKey(algorithm: types.Pkcs11RsaHashedKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    const key = await this.crypto.generateKey(
      { ...algorithm, name: this.name },
      extractable,
      keyUsages);

    return key;
  }

  /**
   * Checks if the token supports the RSA_PKCS mechanism.
   * @returns True if the RSA_PKCS mechanism is supported, false otherwise.
   */
  protected hasRsaPkcsMechanism(): boolean {
    const mechanisms = this.container.session.slot.getMechanisms();

    for (let i = 0; i < mechanisms.length; i++) {
      const mechanism = mechanisms.tryGetItem(i);
      if (mechanism && (mechanism.type === graphene.MechanismEnum.RSA_X_509)) {
        return true;
      }
    }

    return false;
  }

  public async onEncrypt(algorithm: RsaOaepParams, key: RsaCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    if (this.hasRsaPkcsMechanism()) {
      return this.onEncryptRsaX509(algorithm, key, data);
    }

    return this.onEncryptRsaOAEP(algorithm, key, data);
  }

  /**
   * Performs RSA-OAEP encryption with the specified algorithm, key, and data.
   * @param algorithm The algorithm to use for encryption.
   * @param key The key to use for encryption.
   * @param data The data to encrypt.
   * @returns A Promise that resolves to the encrypted data as an ArrayBuffer.
   */
  protected async onEncryptRsaOAEP(algorithm: RsaOaepParams, key: RsaCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      // Convert data to a Buffer
      const buf = Buffer.from(data);

      // Get the RSA-OAEP mechanism for the specified algorithm and key algorithm
      const mechanism = this.wc2pk11(algorithm, key.algorithm);

      // Create a context buffer for the cipher
      const context = Buffer.alloc((key.algorithm).modulusLength >> 3);

      // Create a cipher using the RSA-OAEP mechanism and the key
      this.container.session.createCipher(mechanism, key.key).once(buf, context, (err, data2) => {
        if (err) {
          reject(err);
        } else {
          // Convert the encrypted data to an ArrayBuffer and resolve the Promise
          resolve(new Uint8Array(data2).buffer);
        }
      });
    });
  }


  /**
   * Performs RSA-OAEP encryption with the specified algorithm, key, and data.
   * @param algorithm The algorithm to use for encryption.
   * @param key The key to use for encryption.
   * @param data The data to encrypt.
   * @returns A Promise that resolves to the encrypted data as an ArrayBuffer.
   * @throws An error if the data is too large to encrypt with the given key.
   */
  protected async onEncryptRsaX509(algorithm: RsaOaepParams, key: RsaCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    // Convert data to a Uint8Array
    const dataView = new Uint8Array(data);

    // Calculate key, hash, and data sizes
    const keySize = Math.ceil(key.algorithm.modulusLength >> 3);
    const hashSize = ShaCrypto.size(key.algorithm.hash) >> 3;
    const dataLength = dataView.byteLength;
    const psLength = keySize - dataLength - 2 * hashSize - 2;

    // Check if data is too large for the key
    if (dataLength > keySize - 2 * hashSize - 2) {
      throw new Error("Data too large");
    }

    // Create message array
    const message = new Uint8Array(keySize);

    // Generate random seed
    const seed = message.subarray(1, hashSize + 1);
    crypto.randomFillSync(seed);

    // Create data block
    const dataBlock = message.subarray(hashSize + 1);
    const labelHash = crypto.createHash(key.algorithm.hash.name.replace("-", ""))
      .update(core.BufferSourceConverter.toUint8Array(algorithm.label || new Uint8Array(0)))
      .digest();
    dataBlock.set(labelHash, 0);
    dataBlock[hashSize + psLength] = 1;
    dataBlock.set(dataView, hashSize + psLength + 1);

    // Apply data block mask
    const dataBlockMask = this.mgf1(key.algorithm.hash, seed, dataBlock.length);
    for (let i = 0; i < dataBlock.length; i++) {
      dataBlock[i] ^= dataBlockMask[i];
    }

    // Apply seed mask
    const seedMask = this.mgf1(key.algorithm.hash, dataBlock, seed.length);
    for (let i = 0; i < seed.length; i++) {
      seed[i] ^= seedMask[i];
    }

    // Encrypt the data using the key and RSA_PKCS cipher
    return new Promise<ArrayBuffer>((resolve, reject) => {
      const buf = Buffer.from(message);
      const context = Buffer.alloc((key.algorithm).modulusLength >> 3);
      this.container.session.createCipher(graphene.MechanismEnum.RSA_X_509, key.key)
        .once(buf, context, (err, data2) => {
          if (err) {
            reject(err);
          } else {
            resolve(core.BufferSourceConverter.toArrayBuffer(data2));
          }
        });
    });
  }

  public async onDecrypt(algorithm: RsaOaepParams, key: RsaCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    if (this.hasRsaPkcsMechanism()) {
      return this.onDecryptRsaX509(algorithm, key, data);
    }

    return this.onDecryptRsaOAEP(algorithm, key, data);
  }

  protected async onDecryptRsaOAEP(algorithm: RsaOaepParams, key: RsaCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    const buf = Buffer.from(data);
    const mechanism = this.wc2pk11(algorithm, key.algorithm);
    const context = Buffer.alloc((key.algorithm).modulusLength >> 3);

    const decipher = this.container.session.createDecipher(mechanism, key.key);
    try {
      await alwaysAuthenticate(key, this.container);
    } catch (e) {
      try {
        // call C_SignFinal to close the active state
        decipher.once(buf, context);
      } catch {
        // nothing
      }
      throw e;
    }

    return new Promise<ArrayBuffer>((resolve, reject) => {
      decipher.once(buf, context, (err, data2) => {
        if (err) {
          reject(err);
        } else {
          resolve(new Uint8Array(data2).buffer);
        }
      });
    });
  }

  /**
   * Performs RSA-OAEP decryption with the specified algorithm, key, and data.
   * @param algorithm The algorithm to use for decryption.
   * @param key The key to use for decryption.
   * @param data The data to decrypt.
   * @returns A Promise that resolves to the decrypted data as an ArrayBuffer.
   * @throws An error if the data is too large to decrypt with the given key.
   */
  protected async onDecryptRsaX509(algorithm: RsaOaepParams, key: RsaCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    // Calculate key, hash, and data sizes
    const keySize = Math.ceil(key.algorithm.modulusLength >> 3);
    const hashSize = ShaCrypto.size(key.algorithm.hash) >> 3;

    // Check if data is too large for the key
    if (data.byteLength > keySize || keySize < 2 * hashSize + 2) {
      throw new Error("Data too large");
    }


    // Decrypt the data using the key and RSA_PKCS cipher
    const buf = Buffer.from(data);
    const context = Buffer.alloc((key.algorithm).modulusLength >> 3);
    const decipher = this.container.session.createDecipher(graphene.MechanismEnum.RSA_X_509, key.key);

    try {
      await alwaysAuthenticate(key, this.container);
    } catch (e) {
      try {
        // call C_SignFinal to close the active state
        decipher.once(buf, context);
      } catch {
        // nothing
      }
      throw e;
    }

    const pkcs0 = await new Promise<Buffer>((resolve, reject) => {
      decipher.once(buf, context, (err, data2) => {
        if (err) {
          reject(err);
        } else {
          resolve(data2);
        }
      });
    });

    const z = pkcs0[0];
    const seed = pkcs0.subarray(1, hashSize + 1);
    const dataBlock = pkcs0.subarray(hashSize + 1);

    if (z !== 0) {
      throw new Error("Decryption failed");
    }

    const seedMask = this.mgf1(key.algorithm.hash, dataBlock, seed.length);
    for (let i = 0; i < seed.length; i++) {
      seed[i] ^= seedMask[i];
    }

    const dataBlockMask = this.mgf1(key.algorithm.hash, seed, dataBlock.length);
    for (let i = 0; i < dataBlock.length; i++) {
      dataBlock[i] ^= dataBlockMask[i];
    }

    const labelHash = crypto.createHash(key.algorithm.hash.name.replace("-", ""))
      .update(core.BufferSourceConverter.toUint8Array(algorithm.label || new Uint8Array(0)))
      .digest();
    const expectedLabelHash = dataBlock.subarray(0, hashSize);
    if (!core.BufferSourceConverter.isEqual(expectedLabelHash, labelHash)) {
      throw new Error("Label hash mismatch");
    }

    // Remove padding and return the decrypted data
    let index = hashSize + 1;
    while (dataBlock[index] === 0) {
      index++;
    }
    if (dataBlock[index++] !== 1) {
      throw new Error("Invalid padding");
    }

    return core.BufferSourceConverter.toArrayBuffer(dataBlock.subarray(index));
  }

  public async onExportKey(format: KeyFormat, key: RsaCryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    return this.crypto.exportKey(format, key);
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: types.Pkcs11RsaHashedImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    const key = await this.crypto.importKey(format, keyData, { ...algorithm, name: this.name }, extractable, keyUsages);
    return key;
  }

  public override checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage): void {
    super.checkCryptoKey(key, keyUsage);
    if (!(key instanceof RsaCryptoKey)) {
      throw new TypeError("key: Is not PKCS11 CryptoKey");
    }
  }

  protected wc2pk11(alg: RsaOaepParams, keyAlg: types.Pkcs11RsaHashedKeyAlgorithm): graphene.IAlgorithm {
    let params: graphene.RsaOaepParams;
    const sourceData = alg.label ? Buffer.from((alg as RsaOaepParams).label as Uint8Array) : undefined;
    switch (keyAlg.hash.name.toUpperCase()) {
      case "SHA-1":
        params = new graphene.RsaOaepParams(graphene.MechanismEnum.SHA1, graphene.RsaMgf.MGF1_SHA1, sourceData);
        break;
      case "SHA-224":
        params = new graphene.RsaOaepParams(graphene.MechanismEnum.SHA224, graphene.RsaMgf.MGF1_SHA224, sourceData);
        break;
      case "SHA-256":
        params = new graphene.RsaOaepParams(graphene.MechanismEnum.SHA256, graphene.RsaMgf.MGF1_SHA256, sourceData);
        break;
      case "SHA-384":
        params = new graphene.RsaOaepParams(graphene.MechanismEnum.SHA384, graphene.RsaMgf.MGF1_SHA384, sourceData);
        break;
      case "SHA-512":
        params = new graphene.RsaOaepParams(graphene.MechanismEnum.SHA512, graphene.RsaMgf.MGF1_SHA512, sourceData);
        break;
      default:
        throw new core.OperationError(`Cannot create PKCS11 mechanism from algorithm '${keyAlg.hash.name}'`);
    }
    const res = { name: "RSA_PKCS_OAEP", params };
    return res;
  }

  /**
   * RSA MGF1
   * @param algorithm Hash algorithm
   * @param seed Seed
   * @param length Length of mask
   */
  protected mgf1(algorithm: Algorithm, seed: Uint8Array, length = 0): Uint8Array {
    const hashSize = ShaCrypto.size(algorithm) >> 3;
    const mask = new Uint8Array(length);
    const counter = new Uint8Array(4);
    const chunks = Math.ceil(length / hashSize);
    for (let i = 0; i < chunks; i++) {
      counter[0] = i >>> 24;
      counter[1] = (i >>> 16) & 255;
      counter[2] = (i >>> 8) & 255;
      counter[3] = i & 255;

      const subMask = mask.subarray(i * hashSize);

      let chunk = crypto.createHash(algorithm.name.replace("-", ""))
        .update(seed)
        .update(counter)
        .digest() as Uint8Array;
      if (chunk.length > subMask.length) {
        chunk = chunk.subarray(0, subMask.length);
      }

      subMask.set(chunk);
    }

    return mask;
  }

}
