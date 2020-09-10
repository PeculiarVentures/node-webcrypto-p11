import * as graphene from "graphene-pk11";
import { Convert } from "pvtsutils";
import * as core from "webcrypto-core";
import { Crypto } from "../../crypto";
import * as utils from "../../utils";
import { HmacCryptoKey } from "./key";

export class HmacProvider extends core.HmacProvider {

  constructor(private crypto: Crypto) {
    super();
  }

  public async onGenerateKey(algorithm: HmacKeyGenParams, extractable: boolean, keyUsages: KeyUsage[], attrs: Partial<Pkcs11KeyAttributes> = {}): Promise<CryptoKey> {
    return new Promise<CryptoKey>((resolve, reject) => {
      Crypto.assertSession(this.crypto.session);

      const length = (algorithm.length || this.getDefaultLength((algorithm.hash as Algorithm).name)) >> 3 << 3;
      algorithm = { ...algorithm, name: this.name, length };

      const template = this.createTemplate(this.crypto.session, algorithm, extractable, keyUsages, attrs);
      template.valueLen = length >> 3;

      // PKCS11 generation
      this.crypto.session.generateKey(graphene.KeyGenMechanism.GENERIC_SECRET, template, (err, aesKey) => {
        try {
          if (err) {
            reject(new core.CryptoError(`HMAC: Cannot generate new key\n${err.message}`));
          } else {
            resolve(new HmacCryptoKey(aesKey, algorithm));
          }
        } catch (e) {
          reject(e);
        }
      });
    });
  }

  public async onSign(algorithm: Algorithm, key: HmacCryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    return new Promise<ArrayBuffer>((resolve, reject) => {
      Crypto.assertSession(this.crypto.session);

      const mechanism = this.wc2pk11(algorithm, key.algorithm);
      this.crypto.session.createSign(mechanism, key.key).once(Buffer.from(data), (err, data2) => {
        if (err) {
          reject(err);
        } else {
          resolve(new Uint8Array(data2).buffer);
        }
      });
    });
  }

  public async onVerify(algorithm: Algorithm, key: HmacCryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    return new Promise<boolean>((resolve, reject) => {
      Crypto.assertSession(this.crypto.session);

      const mechanism = this.wc2pk11(algorithm, key.algorithm);
      this.crypto.session.createVerify(mechanism, key.key).once(Buffer.from(data), Buffer.from(signature), (err, ok) => {
        if (err) {
          reject(err);
        } else {
          resolve(ok);
        }
      });
    });
  }

  public async onImportKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: HmacImportParams, extractable: boolean, keyUsages: KeyUsage[], attrs: Partial<Pkcs11KeyAttributes> = {}): Promise<CryptoKey> {
    Crypto.assertSession(this.crypto.session);

    // get key value
    let value: ArrayBuffer;

    switch (format.toLowerCase()) {
      case "jwk":
        const jwk = keyData as JsonWebKey;
        if (!jwk.k) {
          throw new core.OperationError("jwk.k: Cannot get required property");
        }
        keyData = Convert.FromBase64Url(jwk.k);
      case "raw":
        value = keyData as ArrayBuffer;
        break;
      default:
        throw new core.OperationError("format: Must be 'jwk' or 'raw'");
    }
    // prepare key algorithm
    const preparedAlg = utils.prepareAlgorithm(algorithm);
    const hmacAlg = {
      ...preparedAlg,
      name: this.name,
      length: value.byteLength * 8 || this.getDefaultLength((algorithm as any).hash.name),
    } as HmacKeyAlgorithm;
    const template: graphene.ITemplate = this.createTemplate(this.crypto.session, hmacAlg, extractable, keyUsages, attrs);
    template.value = Buffer.from(value);

    // create session object
    const sessionObject = this.crypto.session.create(template);
    const key = new HmacCryptoKey(sessionObject.toType<graphene.SecretKey>(), hmacAlg);
    return key;
  }

  public async onExportKey(format: KeyFormat, key: HmacCryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    const template = key.key.getAttribute({ value: null });
    switch (format.toLowerCase()) {
      case "jwk":
        const jwk: JsonWebKey = {
          kty: "oct",
          k: Convert.ToBase64Url(template.value!),
          alg: `HS${key.algorithm.hash.name.replace("SHA-", "")}`,
          ext: true,
          key_ops: key.usages,
        };
        return jwk;
      case "raw":
        return new Uint8Array(template.value!).buffer;
        break;
      default:
        throw new core.OperationError("format: Must be 'jwk' or 'raw'");
    }
  }

  public checkCryptoKey(key: CryptoKey, keyUsage?: KeyUsage) {
    super.checkCryptoKey(key, keyUsage);
    if (!(key instanceof HmacCryptoKey)) {
      throw new TypeError("key: Is not HMAC CryptoKey");
    }
  }

  protected createTemplate(session: graphene.Session, alg: HmacKeyGenParams, extractable: boolean, keyUsages: KeyUsage[], attrs: Partial<Pkcs11KeyAttributes>): graphene.ITemplate {
    Crypto.assertSession(this.crypto.session);

    alg = { ...HmacCryptoKey.defaultKeyAlgorithm(), ...alg };
    const label = attrs.label || `HMAC-${alg.length}`;
    const token = !!(attrs.token);
    const sensitive = !!(attrs.sensitive);
    const id = utils.GUID(session);
    return {
      id,
      label,
      token,
      sensitive,
      extractable,
      class: graphene.ObjectClass.SECRET_KEY,
      keyType: graphene.KeyType.GENERIC_SECRET,
      derive: false,
      sign: keyUsages.indexOf("sign") !== -1,
      verify: keyUsages.indexOf("verify") !== -1,
      encrypt: keyUsages.indexOf("encrypt") !== -1 || keyUsages.indexOf("wrapKey") !== -1,
      decrypt: keyUsages.indexOf("decrypt") !== -1 || keyUsages.indexOf("unwrapKey") !== -1,
      wrap: keyUsages.indexOf("wrapKey") !== -1,
      unwrap: keyUsages.indexOf("unwrapKey") !== -1,
    };
  }

  protected wc2pk11(alg: Algorithm, keyAlg: HmacKeyAlgorithm): graphene.IAlgorithm {
    let res: string;
    switch (keyAlg.hash.name.toUpperCase()) {
      case "SHA-1":
        res = "SHA_1_HMAC";
        break;
      case "SHA-224":
        res = "SHA224_HMAC";
        break;
      case "SHA-256":
        res = "SHA256_HMAC";
        break;
      case "SHA-384":
        res = "SHA384_HMAC";
        break;
      case "SHA-512":
        res = "SHA512_HMAC";
        break;
      default:
        throw new core.OperationError(`Cannot create PKCS11 mechanism from algorithm '${keyAlg.hash.name}'`);
    }
    return { name: res, params: null };
  }

}
