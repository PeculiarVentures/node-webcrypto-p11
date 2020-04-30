import * as graphene from "graphene-pk11";
import { ITemplate, KeyGenMechanism, KeyType, ObjectClass, PrivateKey, PublicKey } from "graphene-pk11";
import { Convert } from "pvtsutils";
import * as core from "webcrypto-core";
import { CryptoKey, ITemplatePair } from "../../key";
import * as utils from "../../utils";
import { RsaCryptoKey } from "./key";

const asn1js = require("asn1js");
const { PrivateKeyInfo, PublicKeyInfo } = require("pkijs");

const HASH_PREFIXES: { [alg: string]: Buffer } = {
  "sha-1": Buffer.from([0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14]),
  "sha-256": Buffer.from([0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]),
  "sha-384": Buffer.from([0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30]),
  "sha-512": Buffer.from([0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40]),
};

export class RsaCrypto {

  public static publicKeyUsages = ["verify", "encrypt", "wrapKey"];
  public static privateKeyUsages = ["sign", "decrypt", "unwrapKey"];

  public static async generateKey(session: graphene.Session, algorithm: Pkcs11RsaHashedKeyGenParams, extractable: boolean, keyUsages: string[]): Promise<CryptoKeyPair> {
    const size = algorithm.modulusLength;
    const exp = Buffer.from(algorithm.publicExponent);

    const template = this.createTemplate(session, algorithm, extractable, keyUsages);

    // RSA params
    template.publicKey.publicExponent = exp;
    template.publicKey.modulusBits = size;

    // PKCS11 generation
    return new Promise<CryptoKeyPair>((resolve, reject) => {
      session.generateKeyPair(KeyGenMechanism.RSA, template.publicKey, template.privateKey, (err, keys) => {
        try {
          if (err) {
            reject(new core.CryptoError(`Rsa: Can not generate new key\n${err.message}`));
          } else {
            const wcKeyPair = {
              privateKey: new RsaCryptoKey(keys.privateKey, algorithm),
              publicKey: new RsaCryptoKey(keys.publicKey, algorithm),
            };
            resolve(wcKeyPair as any);
          }
        } catch (e) {
          reject(e);
        }
      });
    });
  }

  public static async exportKey(session: graphene.Session, format: KeyFormat, key: RsaCryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    switch (format.toLowerCase()) {
      case "jwk":
        if (key.type === "private") {
          return this.exportJwkPrivateKey(key);
        } else {
          return this.exportJwkPublicKey(key);
        }
      case "pkcs8": {
        const jwk = await this.exportJwkPrivateKey(key);
        const privateKey = new PrivateKeyInfo();
        privateKey.fromJSON(jwk);
        return privateKey.toSchema(true).toBER(false);
      }
      case "spki": {
        const jwk = await this.exportJwkPublicKey(key);
        const publicKey = new PublicKeyInfo();
        publicKey.fromJSON(jwk);
        return publicKey.toSchema(true).toBER(false);
      }
      case "raw": {
        // export subjectPublicKey BIT_STRING value
        const jwk = await this.exportJwkPublicKey(key);
        const publicKey = new PublicKeyInfo();
        publicKey.fromJSON(jwk);
        return publicKey.toSchema(true).valueBlock.value[1].valueBlock.valueHex;
      }
      default:
        throw new core.OperationError("format: Must be 'jwk', 'pkcs8' or 'spki'");
    }
  }

  public static async importKey(session: graphene.Session, format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: RsaHashedImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    switch (format.toLowerCase()) {
      case "jwk":
        const jwk: any = keyData;
        if (jwk.d) {
          return this.importJwkPrivateKey(session!, jwk, algorithm as RsaHashedKeyGenParams, extractable, keyUsages);
        } else {
          return this.importJwkPublicKey(session!, jwk, algorithm as RsaHashedKeyGenParams, extractable, keyUsages);
        }
      case "spki": {
        const arBuf = new Uint8Array(keyData as Uint8Array).buffer as ArrayBuffer;
        const asn1 = asn1js.fromBER(arBuf);

        const jwk = new PublicKeyInfo({ schema: asn1.result }).toJSON();
        return this.importJwkPublicKey(session!, jwk, algorithm as RsaHashedKeyGenParams, extractable, keyUsages);
      }
      case "pkcs8": {
        const arBuf = new Uint8Array(keyData as Uint8Array).buffer as ArrayBuffer;
        const asn1 = asn1js.fromBER(arBuf);

        const jwk = new PrivateKeyInfo({ schema: asn1.result }).toJSON();
        return this.importJwkPrivateKey(session!, jwk, algorithm as RsaHashedKeyGenParams, extractable, keyUsages);
      }
      default:
        throw new core.OperationError("format: Must be 'jwk', 'pkcs8' or 'spki'");
    }
  }

  public static getAlgorithm(session: graphene.Session, wcAlgorithmName: string, p11AlgorithmName: string) {
    const DEFAULT_RSA = wcAlgorithmName === "RSASSA-PKCS1-v1_5" ? "RSA_PKCS"
      : wcAlgorithmName === "RSA-PSS" ? "RSA_PKCS_PSS"
        : wcAlgorithmName === "RSA-OAEP" ? "RSA_PKCS_OAEP" : "RSA_PKCS";

    const mechanisms = session.slot.getMechanisms();
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

  public static prepareData(hashAlgorithm: string, data: Buffer) {
    // use nodejs crypto for digest calculating
    const hash = utils.digest(hashAlgorithm.replace("-", ""), data);

    // enveloping hash
    const hashPrefix = HASH_PREFIXES[hashAlgorithm.toLowerCase()];
    if (!hashPrefix) {
      throw new Error(`Cannot get prefix for hash '${hashAlgorithm}'`);
    }
    return Buffer.concat([hashPrefix, hash]);
  }

  protected static jwkAlgName(algorithm: RsaHashedKeyAlgorithm) {
    switch (algorithm.name.toUpperCase()) {
      case "RSA-OAEP":
        const mdSize = /(\d+)$/.exec(algorithm.hash.name)![1];
        return `RSA-OAEP${mdSize !== "1" ? `-${mdSize}` : ""}`;
      case "RSASSA-PKCS1-V1_5":
        return `RS${/(\d+)$/.exec(algorithm.hash.name)![1]}`;
      case "RSA-PSS":
        return `PS${/(\d+)$/.exec(algorithm.hash.name)![1]}`;
      default:
        throw new core.OperationError("algorithm: Is not recognized");
    }
  }

  protected static async exportJwkPublicKey(key: RsaCryptoKey) {
    const pkey: ITemplate = key.key.getAttribute({
      publicExponent: null,
      modulus: null,
    });
    const alg = this.jwkAlgName(key.algorithm as RsaHashedKeyAlgorithm);
    const jwk: JsonWebKey = {
      kty: "RSA",
      alg,
      ext: true,
      key_ops: key.usages,
      e: Convert.ToBase64Url(pkey.publicExponent!),
      n: Convert.ToBase64Url(pkey.modulus!),
    };
    return jwk;
  }

  protected static async exportJwkPrivateKey(key: RsaCryptoKey) {
    const pkey: ITemplate = key.key.getAttribute({
      publicExponent: null,
      modulus: null,
      privateExponent: null,
      prime1: null,
      prime2: null,
      exp1: null,
      exp2: null,
      coefficient: null,
    });
    const alg = this.jwkAlgName(key.algorithm as RsaHashedKeyAlgorithm);
    const jwk: JsonWebKey = {
      kty: "RSA",
      alg,
      ext: true,
      key_ops: key.usages,
      e: Convert.ToBase64Url(pkey.publicExponent as Uint8Array),
      n: Convert.ToBase64Url(pkey.modulus as Uint8Array),
      d: Convert.ToBase64Url(pkey.privateExponent as Uint8Array),
      p: Convert.ToBase64Url(pkey.prime1 as Uint8Array),
      q: Convert.ToBase64Url(pkey.prime2 as Uint8Array),
      dp: Convert.ToBase64Url(pkey.exp1 as Uint8Array),
      dq: Convert.ToBase64Url(pkey.exp2 as Uint8Array),
      qi: Convert.ToBase64Url(pkey.coefficient as Uint8Array),
    };
    return jwk;
  }

  protected static importJwkPrivateKey(session: graphene.Session, jwk: JsonWebKey, algorithm: RsaHashedKeyGenParams, extractable: boolean, keyUsages: string[]) {
    // TODO: Fix key label. It ha s `RSA-undefined` for imported key
    const template = this.createTemplate(session, algorithm, extractable, keyUsages).privateKey;
    template.publicExponent = utils.b64UrlDecode(jwk.e!);
    template.modulus = utils.b64UrlDecode(jwk.n!);
    template.privateExponent = utils.b64UrlDecode(jwk.d!);
    template.prime1 = utils.b64UrlDecode(jwk.p!);
    template.prime2 = utils.b64UrlDecode(jwk.q!);
    template.exp1 = utils.b64UrlDecode(jwk.dp!);
    template.exp2 = utils.b64UrlDecode(jwk.dq!);
    template.coefficient = utils.b64UrlDecode(jwk.qi!);
    const p11key = session.create(template).toType<PrivateKey>();
    return new RsaCryptoKey(p11key, algorithm);
  }

  protected static importJwkPublicKey(session: graphene.Session, jwk: JsonWebKey, algorithm: Pkcs11RsaHashedImportParams, extractable: boolean, keyUsages: string[]) {
    const template = this.createTemplate(session, algorithm as any, extractable, keyUsages).publicKey;
    template.publicExponent = utils.b64UrlDecode(jwk.e!);
    template.modulus = utils.b64UrlDecode(jwk.n!);
    const p11key = session.create(template).toType<PublicKey>();
    return new RsaCryptoKey(p11key, algorithm);
  }

  protected static createTemplate(session: graphene.Session, alg: Pkcs11RsaHashedKeyGenParams, extractable: boolean, keyUsages: string[]): ITemplatePair {
    alg = { ...RsaCryptoKey.defaultKeyAlgorithm(), ...alg };
    const label = alg.label || `RSA-${alg.modulusLength}`;
    const idKey = utils.GUID(session);
    return {
      privateKey: {
        token: !!(alg.token ?? process.env.WEBCRYPTO_PKCS11_TOKEN),
        sensitive: !!(alg.sensitive ?? process.env.WEBCRYPTO_PKCS11_SENSITIVE),
        class: ObjectClass.PRIVATE_KEY,
        keyType: KeyType.RSA,
        private: true,
        label,
        id: idKey,
        extractable,
        derive: false,
        sign: keyUsages.indexOf("sign") > -1,
        decrypt: keyUsages.indexOf("decrypt") > -1,
        unwrap: keyUsages.indexOf("unwrapKey") > -1,
      },
      publicKey: {
        token: !!(alg.token ?? process.env.WEBCRYPTO_PKCS11_TOKEN),
        class: ObjectClass.PUBLIC_KEY,
        keyType: KeyType.RSA,
        private: false,
        label,
        id: idKey,
        verify: keyUsages.indexOf("verify") > -1,
        encrypt: keyUsages.indexOf("encrypt") > -1,
        wrap: keyUsages.indexOf("wrapKey") > -1,
      },
    };
  }

}
