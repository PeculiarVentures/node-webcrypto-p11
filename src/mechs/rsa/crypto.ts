import * as asnSchema from "@peculiar/asn1-schema";
import * as jsonSchema from "@peculiar/json-schema";
import * as graphene from "graphene-pk11";
import * as pvtsutils from "pvtsutils";
import * as core from "webcrypto-core";

import { CryptoKey } from "../../key";
import * as types from "../../types";
import * as utils from "../../utils";

import { RsaCryptoKey } from "./key";

const HASH_PREFIXES: { [alg: string]: Buffer; } = {
  "sha-1": Buffer.from([0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14]),
  "sha-256": Buffer.from([0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]),
  "sha-384": Buffer.from([0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30]),
  "sha-512": Buffer.from([0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40]),
};

export class RsaCrypto implements types.IContainer {

  public publicKeyUsages = ["verify", "encrypt", "wrapKey"];
  public privateKeyUsages = ["sign", "decrypt", "unwrapKey"];

  public constructor(public container: types.ISessionContainer) { }

  public async generateKey(algorithm: types.Pkcs11RsaHashedKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    const size = algorithm.modulusLength;
    const exp = Buffer.from(algorithm.publicExponent);

    // Create PKCS#11 templates
    const attrs: types.Pkcs11Attributes = {
      id: utils.GUID(),
      label: algorithm.label,
      token: algorithm.token,
      sensitive: algorithm.sensitive,
      extractable,
      usages: keyUsages,
    };
    if (algorithm.alwaysAuthenticate) {
      attrs.alwaysAuthenticate = true;
    }

    const privateTemplate = this.createTemplate({
      action: "generate",
      type: "private",
      attributes: attrs,
    });
    const publicTemplate = this.createTemplate({
      action: "generate",
      type: "public",
      attributes: attrs,
    });

    // Set RSA params
    publicTemplate.publicExponent = exp;
    publicTemplate.modulusBits = size;

    // PKCS11 generation
    return new Promise<CryptoKeyPair>((resolve, reject) => {
      this.container.session.generateKeyPair(graphene.KeyGenMechanism.RSA, publicTemplate, privateTemplate, (err, keys) => {
        try {
          if (err) {
            reject(new core.CryptoError(`Rsa: Can not generate new key\n${err.message}`));
          } else {
            if (!keys) {
              throw new Error("Cannot get keys from callback function");
            }
            const wcKeyPair = {
              privateKey: new RsaCryptoKey(keys.privateKey, algorithm),
              publicKey: new RsaCryptoKey(keys.publicKey, algorithm),
            };
            resolve(wcKeyPair);
          }
        } catch (e) {
          reject(e);
        }
      });
    });
  }

  public async exportKey(format: KeyFormat, key: RsaCryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    switch (format.toLowerCase()) {
      case "jwk":
        if (key.type === "private") {
          return this.exportJwkPrivateKey(key);
        } else {
          return this.exportJwkPublicKey(key);
        }
      case "pkcs8": {
        const jwk = await this.exportJwkPrivateKey(key);
        return this.jwk2pkcs(jwk);
      }
      case "spki": {
        const jwk = await this.exportJwkPublicKey(key);
        return this.jwk2spki(jwk);
      }
      case "raw": {
        const jwk = await this.exportJwkPublicKey(key);
        const spki = this.jwk2spki(jwk);
        const asn = asnSchema.AsnConvert.parse(spki, core.asn1.PublicKeyInfo);
        return asn.publicKey;
      }
      default:
        throw new core.OperationError("format: Must be 'raw', 'jwk', 'pkcs8' or 'spki'");
    }
  }

  public async importKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: RsaHashedImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    switch (format.toLowerCase()) {
      case "jwk": {
        const jwk = keyData as JsonWebKey;
        if (jwk.d) {
          return this.importJwkPrivateKey(jwk, algorithm as RsaHashedKeyGenParams, extractable, keyUsages);
        } else {
          return this.importJwkPublicKey(jwk, algorithm as RsaHashedKeyGenParams, extractable, keyUsages);
        }
      }
      case "spki": {
        const raw = new Uint8Array(keyData as Uint8Array).buffer as ArrayBuffer;
        const jwk = this.spki2jwk(raw);
        return this.importJwkPublicKey(jwk, algorithm as RsaHashedKeyGenParams, extractable, keyUsages);
      }
      case "pkcs8": {
        const raw = new Uint8Array(keyData as Uint8Array).buffer as ArrayBuffer;
        const jwk = this.pkcs2jwk(raw);
        return this.importJwkPrivateKey(jwk, algorithm as RsaHashedKeyGenParams, extractable, keyUsages);
      }
      default:
        throw new core.OperationError("format: Must be 'jwk', 'pkcs8' or 'spki'");
    }
  }

  public getAlgorithm(wcAlgorithmName: string, p11AlgorithmName: string): string {
    const DEFAULT_RSA = wcAlgorithmName === "RSASSA-PKCS1-v1_5" ? "RSA_PKCS"
      : wcAlgorithmName === "RSA-PSS" ? "RSA_PKCS_PSS"
        : wcAlgorithmName === "RSA-OAEP" ? "RSA_PKCS_OAEP" : "RSA_PKCS";

    const mechanisms = this.container.session.slot.getMechanisms();
    let RSA: string | undefined;
    for (let i = 0; i < mechanisms.length; i++) {
      const mechanism = mechanisms.tryGetItem(i);
      if (mechanism && (mechanism.name === p11AlgorithmName || mechanism.name === DEFAULT_RSA)) {
        RSA = mechanism.name;
      }
    }
    if (!RSA) {
      throw new Error(`Cannot get PKCS11 RSA mechanism by name '${p11AlgorithmName}'`);
    }
    return RSA;
  }

  public prepareData(hashAlgorithm: string, data: Buffer): Buffer {
    // use nodejs crypto for digest calculating
    const hash = utils.digest(hashAlgorithm.replace("-", ""), data);

    // enveloping hash
    const hashPrefix = HASH_PREFIXES[hashAlgorithm.toLowerCase()];
    if (!hashPrefix) {
      throw new Error(`Cannot get prefix for hash '${hashAlgorithm}'`);
    }
    return Buffer.concat([hashPrefix, hash]);
  }

  protected jwkAlgName(algorithm: RsaHashedKeyAlgorithm): string {
    switch (algorithm.name.toUpperCase()) {
      case "RSA-OAEP": {
        const mdSize = /(\d+)$/.exec(algorithm.hash.name)![1];
        return `RSA-OAEP${mdSize !== "1" ? `-${mdSize}` : ""}`;
      }
      case "RSASSA-PKCS1-V1_5":
        return `RS${/(\d+)$/.exec(algorithm.hash.name)![1]}`;
      case "RSA-PSS":
        return `PS${/(\d+)$/.exec(algorithm.hash.name)![1]}`;
      case "RSAES-PKCS1-V1_5":
        return `RSA`;
      default:
        throw new core.OperationError("algorithm: Is not recognized");
    }
  }

  protected async exportJwkPublicKey(key: RsaCryptoKey): Promise<JsonWebKey> {
    const pkey: graphene.ITemplate = key.key.getAttribute({
      publicExponent: null,
      modulus: null,
    });

    // Remove padding
    pkey.publicExponent = pkey.publicExponent!.length > 3
      ? pkey.publicExponent!.slice(pkey.publicExponent!.length - 3)
      : pkey.publicExponent;

    const alg = this.jwkAlgName(key.algorithm as RsaHashedKeyAlgorithm);
    const jwk: JsonWebKey = {
      kty: "RSA",
      alg,
      ext: true,
      key_ops: key.usages,
      e: pvtsutils.Convert.ToBase64Url(pkey.publicExponent!),
      n: pvtsutils.Convert.ToBase64Url(pkey.modulus!),
    };

    return jwk;
  }

  protected async exportJwkPrivateKey(key: RsaCryptoKey): Promise<JsonWebKey> {
    const pkey: graphene.ITemplate = key.key.getAttribute({
      publicExponent: null,
      modulus: null,
      privateExponent: null,
      prime1: null,
      prime2: null,
      exp1: null,
      exp2: null,
      coefficient: null,
    });

    // Remove padding
    pkey.publicExponent = pkey.publicExponent!.length > 3
      ? pkey.publicExponent!.slice(pkey.publicExponent!.length - 3)
      : pkey.publicExponent;

    const alg = this.jwkAlgName(key.algorithm as RsaHashedKeyAlgorithm);
    const jwk: JsonWebKey = {
      kty: "RSA",
      alg,
      ext: true,
      key_ops: key.usages,
      e: pvtsutils.Convert.ToBase64Url(pkey.publicExponent!),
      n: pvtsutils.Convert.ToBase64Url(pkey.modulus!),
      d: pvtsutils.Convert.ToBase64Url(pkey.privateExponent!),
      p: pvtsutils.Convert.ToBase64Url(pkey.prime1!),
      q: pvtsutils.Convert.ToBase64Url(pkey.prime2!),
      dp: pvtsutils.Convert.ToBase64Url(pkey.exp1!),
      dq: pvtsutils.Convert.ToBase64Url(pkey.exp2!),
      qi: pvtsutils.Convert.ToBase64Url(pkey.coefficient!),
    };

    return jwk;
  }

  protected importJwkPrivateKey(jwk: JsonWebKey, algorithm: types.Pkcs11RsaHashedKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): RsaCryptoKey {
    const template = this.createTemplate({
      action: "import",
      type: "private",
      attributes: {
        id: utils.GUID(),
        token: algorithm.token,
        sensitive: algorithm.sensitive,
        label: algorithm.label,
        extractable,
        alwaysAuthenticate: algorithm.alwaysAuthenticate,
        usages: keyUsages
      },
    });

    // Set RSA private key attributes
    template.publicExponent = utils.b64UrlDecode(jwk.e!);
    template.modulus = utils.b64UrlDecode(jwk.n!);
    template.privateExponent = utils.b64UrlDecode(jwk.d!);
    template.prime1 = utils.b64UrlDecode(jwk.p!);
    template.prime2 = utils.b64UrlDecode(jwk.q!);
    template.exp1 = utils.b64UrlDecode(jwk.dp!);
    template.exp2 = utils.b64UrlDecode(jwk.dq!);
    template.coefficient = utils.b64UrlDecode(jwk.qi!);

    const p11key = this.container.session.create(template).toType<graphene.PrivateKey>();

    return new RsaCryptoKey(p11key, algorithm);
  }

  protected importJwkPublicKey(jwk: JsonWebKey, algorithm: types.Pkcs11RsaHashedImportParams, extractable: boolean, keyUsages: KeyUsage[]): RsaCryptoKey {
    const template = this.createTemplate({
      action: "import",
      type: "public",
      attributes: {
        id: utils.GUID(),
        token: algorithm.token,
        label: algorithm.label,
        extractable,
        usages: keyUsages
      },
    });

    // Set RSA public key attributes
    template.publicExponent = utils.b64UrlDecode(jwk.e!);
    template.modulus = utils.b64UrlDecode(jwk.n!);

    const p11key = this.container.session.create(template).toType<graphene.PublicKey>();

    return new RsaCryptoKey(p11key, algorithm);
  }

  /**
   * Creates PKCS11 template
   * @param params
   */
  protected createTemplate(params: types.ITemplateBuildParameters): types.ITemplate {
    const template = this.container.templateBuilder.build({
      ...params,
      attributes: {
        ...params.attributes,
        label: params.attributes.label || "RSA",
      }
    });

    template.keyType = graphene.KeyType.RSA;

    return template;
  }

  protected jwk2spki(jwk: JsonWebKey): ArrayBuffer {
    const key = jsonSchema.JsonParser.fromJSON(jwk, { targetSchema: core.asn1.RsaPublicKey });

    const keyInfo = new core.asn1.PublicKeyInfo();
    keyInfo.publicKeyAlgorithm.algorithm = "1.2.840.113549.1.1.1";
    keyInfo.publicKeyAlgorithm.parameters = null;

    keyInfo.publicKey = asnSchema.AsnSerializer.serialize(key);

    return asnSchema.AsnSerializer.serialize(keyInfo);
  }

  protected jwk2pkcs(jwk: JsonWebKey): ArrayBuffer {
    const key = jsonSchema.JsonParser.fromJSON(jwk, { targetSchema: core.asn1.RsaPrivateKey });

    const keyInfo = new core.asn1.PrivateKeyInfo();
    keyInfo.privateKeyAlgorithm.algorithm = "1.2.840.113549.1.1.1";
    keyInfo.privateKeyAlgorithm.parameters = null;

    keyInfo.privateKey = asnSchema.AsnSerializer.serialize(key);

    return asnSchema.AsnSerializer.serialize(keyInfo);
  }

  protected pkcs2jwk(raw: ArrayBuffer): JsonWebKey {
    const keyInfo = asnSchema.AsnParser.parse(raw, core.asn1.PrivateKeyInfo);

    if (keyInfo.privateKeyAlgorithm.algorithm !== "1.2.840.113549.1.1.1") {
      throw new Error("PKCS8 is not RSA private key");
    }

    const key = asnSchema.AsnParser.parse(keyInfo.privateKey, core.asn1.RsaPrivateKey);
    const json = jsonSchema.JsonSerializer.toJSON(key);

    return {
      kty: "RSA",
      ...json,
    };
  }

  protected spki2jwk(raw: ArrayBuffer): JsonWebKey {
    const keyInfo = asnSchema.AsnParser.parse(raw, core.asn1.PublicKeyInfo);

    if (keyInfo.publicKeyAlgorithm.algorithm !== "1.2.840.113549.1.1.1") {
      throw new Error("PKCS8 is not RSA private key");
    }

    const key = asnSchema.AsnParser.parse(keyInfo.publicKey, core.asn1.RsaPublicKey);
    const json = jsonSchema.JsonSerializer.toJSON(key);

    return {
      kty: "RSA",
      ...json,
    };
  }

}
