import * as core from "webcrypto-core";

import { CryptoKey } from "../../key";
import * as types from "../../types";

import { RsaCrypto } from "./crypto";
import { RsaCryptoKey } from "./key";
import { alwaysAuthenticate } from "../../utils";

export class RsaEsProvider extends core.RsaProvider implements types.IContainer {

  public override name = "RSAES-PKCS1-v1_5";

  public override usages: core.ProviderKeyPairUsage = {
    privateKey: ["decrypt", "unwrapKey"],
    publicKey: ["encrypt", "wrapKey"],
  };
  public crypto: RsaCrypto;

  constructor(public container: types.ISessionContainer) {
    super();
    this.crypto = new RsaCrypto(container);
  }

  public async onGenerateKey(algorithm: RsaHashedKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    return this.crypto.generateKey(algorithm, extractable, keyUsages);
  }

  public async onExportKey(format: KeyFormat, key: RsaCryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    return this.crypto.exportKey(format, key);
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: RsaHashedImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    return this.crypto.importKey(format, keyData, algorithm, extractable, keyUsages);
  }

  public override async onEncrypt(algorithm: Algorithm, key: RsaCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return this.cryptOperation('encrypt', key, data);
  }

  public override async onDecrypt(algorithm: Algorithm, key: RsaCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return this.cryptOperation('decrypt', key, data);
  }

  private async cryptOperation(type: 'encrypt' | 'decrypt', key: RsaCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    const mechanism = { name: "RSA_PKCS", params: null };
    const buf = Buffer.from(data);
    const context = Buffer.alloc((key.algorithm).modulusLength >> 3);


    return new Promise((resolve, reject) => {
      const operation = type === 'encrypt'
        ? this.container.session.createCipher(mechanism, key.key)
        : this.container.session.createDecipher(mechanism, key.key);

      let rejected = false;
      alwaysAuthenticate(key, this.container, "sign")
        .catch((e) => {
          // call final to close the active state
          try {
            operation.once(buf, context);
          } catch {
            // nothing
          }
          reject(e);
          rejected = true;
        })
        .then(() => {
          if (rejected) {
            return;
          }

          operation.once(buf, context, (err, data) => {
            if (err) {
              reject(err);
            } else {
              resolve(data);
            }
          });
        });
    });
  }

  override checkGenerateKeyParams(algorithm: RsaHashedKeyGenParams): void {
    return super.checkGenerateKeyParams({
      ...algorithm,
      hash: { name: "SHA-256" }, // hack standard implementation to skip hash check
    });
  }

  override checkImportParams(algorithm: RsaHashedImportParams): void {
    return super.checkImportParams({
      ...algorithm,
      hash: { name: "SHA-256" }, // hack standard implementation to skip hash check
    });
  }

}
