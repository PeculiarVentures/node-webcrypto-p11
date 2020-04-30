import { AsnParser, AsnSerializer } from "@peculiar/asn1-schema";
import { JsonParser, JsonSerializer } from "@peculiar/json-schema";
import * as graphene from "graphene-pk11";
import { Convert } from "pvtsutils";
import * as core from "webcrypto-core";
import { CryptoKey, ITemplatePair } from "../../key";
import * as utils from "../../utils";
import { EcCryptoKey } from "./key";
import { EcUtils } from "./utils";

export class EcCrypto {

  public static publicKeyUsages = ["verify"];
  public static privateKeyUsages = ["sign", "deriveKey", "deriveBits"];

  public static async generateKey(session: graphene.Session, algorithm: Pkcs11EcKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    return new Promise<CryptoKeyPair>((resolve, reject) => {
      const template = this.createTemplate(session!, algorithm, extractable, keyUsages);

      // EC params
      template.publicKey.paramsEC = this.getJsonNamedCurve(algorithm.namedCurve).value;
      // PKCS11 generation
      session.generateKeyPair(graphene.KeyGenMechanism.EC, template.publicKey, template.privateKey, (err, keys) => {
        try {
          if (err) {
            reject(err);
          } else {
            const wcKeyPair = {
              privateKey: new EcCryptoKey(keys.privateKey, algorithm),
              publicKey: new EcCryptoKey(keys.publicKey, algorithm),
            };
            resolve(wcKeyPair as any);
          }
        } catch (e) {
          reject(e);
        }
      });
    });
  }

  public static async exportKey(session: graphene.Session, format: KeyFormat, key: EcCryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    switch (format.toLowerCase()) {
      case "jwk": {
        if (key.type === "private") {
          return this.exportJwkPrivateKey(key);
        } else {
          return this.exportJwkPublicKey(key);
        }
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
        // export subjectPublicKey BIT_STRING value
        const jwk = await this.exportJwkPublicKey(key);
        if ((key.algorithm as EcKeyGenParams).namedCurve === "X25519") {
          return Convert.FromBase64Url(jwk.x!);
        } else {
          const publicKey = JsonParser.fromJSON(jwk, { targetSchema: core.asn1.EcPublicKey });
          return publicKey.value;
        }
      }
      default:
        throw new core.OperationError("format: Must be 'jwk', 'raw', pkcs8' or 'spki'");
    }
  }

  public static async importKey(session: graphene.Session, format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: Pkcs11EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    switch (format.toLowerCase()) {
      case "jwk": {
        const jwk: any = keyData;
        if (jwk.d) {
          return this.importJwkPrivateKey(session, jwk, algorithm, extractable, keyUsages);
        } else {
          return this.importJwkPublicKey(session!, jwk, algorithm, extractable, keyUsages);
        }
      }
      case "spki": {
        const jwk = this.spki2jwk(keyData as ArrayBuffer);
        return this.importJwkPublicKey(session!, jwk, algorithm, extractable, keyUsages);
      }
      case "pkcs8": {
        const jwk = this.pkcs2jwk(keyData as ArrayBuffer);
        return this.importJwkPrivateKey(session!, jwk, algorithm, extractable, keyUsages);
      }
      case "raw": {
        const curve = this.getJsonNamedCurve(algorithm.namedCurve);
        const ecPoint = EcUtils.decodePoint(Buffer.from(keyData as Uint8Array), curve, false);
        const jwk: JsonWebKey = {
          kty: "EC",
          crv: algorithm.namedCurve,
          x: Convert.ToBase64Url(ecPoint.x),
        };
        if (ecPoint.y) {
          jwk.y = Convert.ToBase64Url(ecPoint.y);
        }
        return this.importJwkPublicKey(session, jwk, algorithm, extractable, keyUsages);
      }
      default:
        throw new core.OperationError("format: Must be 'jwk', 'raw', 'pkcs8' or 'spki'");
    }
  }

  public static getAlgorithm(session: graphene.Session, p11AlgorithmName: string) {
    const mechanisms = session.slot.getMechanisms();
    let EC: string | undefined;
    for (let i = 0; i < mechanisms.length; i++) {
      const mechanism = mechanisms.tryGetItem(i);
      if (mechanism && (mechanism.name === p11AlgorithmName || mechanism.name === "ECDSA")) {
        EC = mechanism.name;
      }
    }
    if (!EC) {
      throw new Error(`Cannot get PKCS11 EC mechanism by name '${p11AlgorithmName}'`);
    }
    return EC;
  }

  public static prepareData(hashAlgorithm: string, data: Buffer) {
    // use nodejs crypto for digest calculating
    return utils.digest(hashAlgorithm.replace("-", ""), data);
  }

  public static getJsonNamedCurve(name: string): graphene.INamedCurve {
    let namedCurve: string;
    switch (name) {
      case "P-192":
        namedCurve = "secp192r1";
        break;
      case "K-256":
        const p256 = graphene.NamedCurve.getByName("secp256r1");
        return {
          name: "secp256k1",
          oid: "1.3.132.0.10",
          value: Buffer.from("06052b8104000A", "hex"),
          size: p256.size,
        };
      case "P-256":
        namedCurve = "secp256r1";
        break;
      case "P-384":
        namedCurve = "secp384r1";
        break;
      case "P-521":
        namedCurve = "secp521r1";
        break;
      case "X25519":
        namedCurve = "curve25519";
        break;
      default:
        throw new Error(`Unsupported namedCurve in use ${name}`);
    }
    return graphene.NamedCurve.getByName(namedCurve);
  }

  protected static importJwkPrivateKey(session: graphene.Session, jwk: JsonWebKey, algorithm: Pkcs11EcKeyImportParams, extractable: boolean, keyUsages: string[]) {
    const namedCurve = this.getJsonNamedCurve(algorithm.namedCurve);
    const template = this.createTemplate(session, algorithm, extractable, keyUsages).privateKey;
    template.paramsEC = namedCurve.value;
    template.value = utils.b64UrlDecode(jwk.d!);
    const p11key = session.create(template).toType<graphene.Key>();
    return new EcCryptoKey(p11key, algorithm);
  }

  protected static importJwkPublicKey(session: graphene.Session, jwk: JsonWebKey, algorithm: Pkcs11EcKeyImportParams, extractable: boolean, keyUsages: string[]) {
    const namedCurve = this.getJsonNamedCurve(algorithm.namedCurve);
    const template = this.createTemplate(session, algorithm, extractable, keyUsages).publicKey;
    template.paramsEC = namedCurve.value;
    let pointEc: Buffer;
    if (namedCurve.name === "curve25519") {
      pointEc = utils.b64UrlDecode(jwk.x!);
    } else {
      pointEc = EcUtils.encodePoint({ x: utils.b64UrlDecode(jwk.x!), y: utils.b64UrlDecode(jwk.y!) }, namedCurve);
    }
    template.pointEC = pointEc;
    const p11key = session.create(template).toType<graphene.Key>();
    return new EcCryptoKey(p11key, algorithm);
  }

  protected static exportJwkPublicKey(key: EcCryptoKey) {
    const pkey: graphene.ITemplate = key.key.getAttribute({
      pointEC: null,
    });
    // TODO: lib.dom.d.ts has typedCurve
    const curve = this.getJsonNamedCurve((key.algorithm as EcKeyGenParams).namedCurve);
    const ecPoint = EcUtils.decodePoint(pkey.pointEC!, curve, true);
    const jwk: JsonWebKey = {
      kty: "EC",
      crv: (key.algorithm as EcKeyGenParams).namedCurve,
      ext: true,
      key_ops: key.usages,
      x: Convert.ToBase64Url(ecPoint.x),
    };
    if (curve.name !== "curve25519") {
      jwk.y = Convert.ToBase64Url(ecPoint.y!);
    }
    return jwk;
  }

  protected static async exportJwkPrivateKey(key: EcCryptoKey) {
    const pkey: graphene.ITemplate = key.key.getAttribute({
      value: null,
    });
    const jwk: JsonWebKey = {
      kty: "EC",
      crv: (key.algorithm as EcKeyGenParams).namedCurve,
      ext: true,
      key_ops: key.usages,
      d: Convert.ToBase64Url(pkey.value!),
    };
    return jwk;
  }

  protected static createTemplate(session: graphene.Session, alg: Pkcs11EcKeyGenParams, extractable: boolean, keyUsages: string[]): ITemplatePair {
    alg = { ...EcCryptoKey.defaultKeyAlgorithm(), ...alg };
    const label = alg.label || `EC-${alg.namedCurve}`;
    const idKey = utils.GUID(session);
    const keyType = graphene.KeyType.ECDSA;

    return {
      privateKey: {
        token: !!(alg.token ?? process.env.WEBCRYPTO_PKCS11_TOKEN),
        sensitive: !!(alg.sensitive ?? process.env.WEBCRYPTO_PKCS11_SENSITIVE),
        class: graphene.ObjectClass.PRIVATE_KEY,
        keyType,
        private: true,
        label,
        id: idKey,
        extractable,
        derive: keyUsages.indexOf("deriveKey") !== -1 || keyUsages.indexOf("deriveBits") !== -1,
        sign: keyUsages.indexOf("sign") !== -1,
        decrypt: keyUsages.indexOf("decrypt") !== -1,
        unwrap: keyUsages.indexOf("unwrapKey") !== -1,
      },
      publicKey: {
        token: !!(alg.token ?? process.env.WEBCRYPTO_PKCS11_TOKEN),
        class: graphene.ObjectClass.PUBLIC_KEY,
        keyType,
        private: false,
        label,
        id: idKey,
        derive: keyUsages.indexOf("deriveKey") !== -1 || keyUsages.indexOf("deriveBits") !== -1,
        verify: keyUsages.indexOf("verify") !== -1,
        encrypt: keyUsages.indexOf("encrypt") !== -1,
        wrap: keyUsages.indexOf("wrapKey") !== -1,
      },
    };
  }

  protected static spki2jwk(raw: ArrayBuffer): JsonWebKey {
    const keyInfo = AsnParser.parse(raw, core.asn1.PublicKeyInfo);

    if (keyInfo.publicKeyAlgorithm.algorithm !== "1.2.840.10045.2.1") {
      throw new Error("SPKI is not EC public key");
    }

    const namedCurve = this.getNamedCurveByOid(AsnParser.parse(keyInfo.publicKeyAlgorithm.parameters!, core.asn1.ObjectIdentifier));

    const ecPublicKey = new core.asn1.EcPublicKey(keyInfo.publicKey);
    const json = JsonSerializer.toJSON(ecPublicKey);

    return {
      kty: "EC",
      crv: namedCurve,
      ...json,
    };
  }

  protected static jwk2pkcs(jwk: JsonWebKey): ArrayBuffer {
    if (!jwk.crv) {
      throw new Error("Absent mandatory parameter \"crv\"");
    }
    const namedCurveId = EcCrypto.getNamedCurveId(jwk.crv);

    const ecPrivateKey = JsonParser.fromJSON(jwk, { targetSchema: core.asn1.EcPrivateKey });

    const keyInfo = new core.asn1.PrivateKeyInfo();
    keyInfo.privateKeyAlgorithm = new core.asn1.AlgorithmIdentifier();
    keyInfo.privateKeyAlgorithm.algorithm = "1.2.840.10045.2.1";
    keyInfo.privateKeyAlgorithm.parameters = AsnSerializer.serialize(namedCurveId);
    keyInfo.privateKey = AsnSerializer.serialize(ecPrivateKey);

    return AsnSerializer.serialize(keyInfo);
  }

  private static getNamedCurveId(namedCurve: string) {
    const namedCurveId = new core.asn1.ObjectIdentifier();
    switch (namedCurve.toUpperCase()) {
      case "K-256":
        namedCurveId.value = "1.3.132.0.10";
        break;
      case "P-256":
        namedCurveId.value = "1.2.840.10045.3.1.7";
        break;
      case "P-384":
        namedCurveId.value = "1.3.132.0.34";
        break;
      case "P-521":
        namedCurveId.value = "1.3.132.0.35";
        break;
      default:
        throw new Error(`Unsupported EC named curve '${namedCurve}'`);
    }
    return namedCurveId;
  }

  protected static getCoordinate(b64: string, coordinateLength: number) {
    const buf = Convert.FromBase64Url(b64);
    const offset = coordinateLength - buf.byteLength;
    const res = new Uint8Array(coordinateLength);
    res.set(new Uint8Array(buf), offset);

    return res.buffer as ArrayBuffer;
  }

  protected static jwk2spki(jwk: JsonWebKey) {
    if (!jwk.crv) {
      throw new Error("Absent mandatory parameter \"crv\"");
    }
    const namedCurveId = EcCrypto.getNamedCurveId(jwk.crv);

    const ecPublicKey = JsonParser.fromJSON(jwk, { targetSchema: core.asn1.EcPublicKey });

    const keyInfo = new core.asn1.PublicKeyInfo();
    keyInfo.publicKeyAlgorithm.algorithm = "1.2.840.10045.2.1";
    keyInfo.publicKeyAlgorithm.parameters = AsnSerializer.serialize(namedCurveId);
    keyInfo.publicKey = ecPublicKey.value;
    return AsnSerializer.serialize(keyInfo);
  }

  protected static pkcs2jwk(raw: ArrayBuffer): JsonWebKey {
    const keyInfo = AsnParser.parse(raw, core.asn1.PrivateKeyInfo);

    if (keyInfo.privateKeyAlgorithm.algorithm !== "1.2.840.10045.2.1") {
      throw new Error("PKCS8 is not EC private key");
    }

    const namedCurve = this.getNamedCurveByOid(AsnParser.parse(keyInfo.privateKeyAlgorithm.parameters!, core.asn1.ObjectIdentifier));

    const ecPrivateKey = AsnParser.parse(keyInfo.privateKey, core.asn1.EcPrivateKey);
    const json = JsonSerializer.toJSON(ecPrivateKey);

    return {
      kty: "EC",
      crv: namedCurve,
      ...json,
    };
  }

  private static getNamedCurveByOid(id: core.asn1.ObjectIdentifier) {
    switch (id.value) {
      case "1.3.132.0.10": // K-256
        return "K-256";
      case "1.2.840.10045.3.1.7": // P-256
        return "P-256";
      case "1.3.132.0.34": // P-384
        return "P-384";
      case "1.3.132.0.35": // P-521
        return "P-521";
      default:
        throw new Error(`Unsupported EC named curve '${id.value}'`);
    }
  }

}
