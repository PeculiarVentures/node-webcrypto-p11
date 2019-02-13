import * as graphene from "graphene-pk11";
import { Convert } from "pvtsutils";
import * as core from "webcrypto-core";
import { CryptoKey, CryptoKeyPair, ITemplatePair } from "../../key";
import { P11Session } from "../../p11_session";
import * as utils from "../../utils";
import { EcCryptoKey } from "./key";
import { EcUtils } from "./utils";

const Asn1Js = require("asn1js");
const pkijs = require("pkijs");

export class EcCrypto {

  public static publicKeyUsages = ["verify"];
  public static privateKeyUsages = ["sign", "deriveKey", "deriveBits"];

  public static async generateKey(session: P11Session, algorithm: EcKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    return new Promise<CryptoKeyPair>((resolve, reject) => {
      const template = this.createTemplate(session!, algorithm, extractable, keyUsages);

      // EC params
      template.publicKey.paramsEC = this.getNamedCurve(algorithm.namedCurve).value;
      // PKCS11 generation
      session.value.generateKeyPair(graphene.KeyGenMechanism.EC, template.publicKey, template.privateKey, (err, keys) => {
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

  public static async exportKey(session: P11Session, format: KeyFormat, key: EcCryptoKey): Promise<JsonWebKey | ArrayBuffer> {
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
          return Convert.FromBase64Url(jwk.x);
        } else {
          const publicKey = new pkijs.PublicKeyInfo();
          publicKey.fromJSON(jwk);
          return publicKey.toSchema(true).valueBlock.value[1].valueBlock.valueHex;
        }
      }
      default:
        throw new core.OperationError("format: Must be 'jwk', 'raw', pkcs8' or 'spki'");
    }
  }

  public static async importKey(session: P11Session, format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    switch (format.toLowerCase()) {
      case "jwk": {
        const jwk: any = keyData;
        if (jwk.d) {
          return this.importJwkPrivateKey(session, jwk, algorithm as EcKeyGenParams, extractable, keyUsages);
        } else {
          return this.importJwkPublicKey(session!, jwk, algorithm as EcKeyGenParams, extractable, keyUsages);
        }
      }
      case "spki": {
        const jwk = this.spki2jwk(keyData as ArrayBuffer);
        return this.importJwkPublicKey(session!, jwk, algorithm as EcKeyGenParams, extractable, keyUsages);
      }
      case "pkcs8": {
        const jwk = this.pkcs2jwk(keyData as ArrayBuffer);
        return this.importJwkPrivateKey(session!, jwk, algorithm as EcKeyGenParams, extractable, keyUsages);
      }
      case "raw": {
        const curve = this.getNamedCurve(algorithm.namedCurve);
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

  public static getAlgorithm(session: P11Session, p11AlgorithmName: string) {
    const mechanisms = session.slot.getMechanisms();
    let EC: string;
    for (let i = 0; i < mechanisms.length; i++) {
      const mechanism = mechanisms.items(i);
      if (mechanism.name === p11AlgorithmName || mechanism.name === "ECDSA") {
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

  public static getNamedCurve(name: string): graphene.INamedCurve {
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

  protected static importJwkPrivateKey(session: P11Session, jwk: JsonWebKey, algorithm: EcKeyGenParams, extractable: boolean, keyUsages: string[]) {
    const namedCurve = this.getNamedCurve(algorithm.namedCurve);
    const template = this.createTemplate(session, algorithm, extractable, keyUsages).privateKey;
    template.paramsEC = namedCurve.value;
    template.value = utils.b64UrlDecode(jwk.d!);
    const p11key = session.value.create(template).toType();
    return new EcCryptoKey(p11key as any, algorithm);
  }

  protected static importJwkPublicKey(session: P11Session, jwk: JsonWebKey, algorithm: EcKeyImportParams, extractable: boolean, keyUsages: string[]) {
    const namedCurve = this.getNamedCurve(algorithm.namedCurve);
    const template = this.createTemplate(session, algorithm, extractable, keyUsages).publicKey;
    template.paramsEC = namedCurve.value;
    let pointEc: Buffer;
    if (namedCurve.name === "curve25519") {
      pointEc = utils.b64UrlDecode(jwk.x!);
    } else {
      pointEc = EcUtils.encodePoint({ x: utils.b64UrlDecode(jwk.x!), y: utils.b64UrlDecode(jwk.y!) }, namedCurve);
    }
    template.pointEC = pointEc;
    const p11key = session.value.create(template).toType();
    return new EcCryptoKey(p11key as any, algorithm);
  }

  protected static exportJwkPublicKey(key: EcCryptoKey) {
    const pkey: graphene.ITemplate = key.key.getAttribute({
      pointEC: null,
    });
    // TODO: lib.dom.d.ts has typedCurve
    const curve = this.getNamedCurve((key.algorithm as EcKeyGenParams).namedCurve);
    const ecPoint = EcUtils.decodePoint(pkey.pointEC!, curve, true);
    const jwk: JsonWebKey = {
      kty: "EC",
      crv: (key.algorithm as EcKeyGenParams).namedCurve,
      ext: true,
      key_ops: key.usages,
      x: Convert.ToBase64Url(ecPoint.x),
    };
    if (curve.name !== "curve25519") {
      jwk.y = Convert.ToBase64Url(ecPoint.y);
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

  protected static createTemplate(session: P11Session, alg: EcKeyGenParams, extractable: boolean, keyUsages: string[]): ITemplatePair {
    const label = `EC-${alg.namedCurve}`;
    const idKey = utils.GUID(session.value);
    const keyType = graphene.KeyType.ECDSA;
    return {
      privateKey: {
        token: !!process.env.WEBCRYPTO_PKCS11_TOKEN,
        sensitive: !!process.env.WEBCRYPTO_PKCS11_SENSITIVE,
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
        token: !!process.env.WEBCRYPTO_PKCS11_TOKEN,
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
    const asn1Spki = Asn1Js.fromBER(raw);
    const spki = new pkijs.PublicKeyInfo({ schema: asn1Spki.result });

    if (spki.algorithm.algorithmId !== "1.2.840.10045.2.1") {
      throw new Error("SPKI is not EC public key");
    }

    const algId = spki.algorithm.algorithmParams.valueBlock.toString();
    let crvName = algId;

    switch (crvName) {
      case "1.3.132.0.10": // K-256
        crvName = "K-256";
        break;
      case "1.2.840.10045.3.1.7": // P-256
        crvName = "P-256";
        break;
      case "1.3.132.0.34": // P-384
        crvName = "P-384";
        break;
      case "1.3.132.0.35": // P-521
        crvName = "P-521";
        break;
      default:
        throw new Error(`Unsupported EC named curve '${crvName}'`);
    }

    const parsedKey = new pkijs.ECPublicKey({
      namedCurve: algId === "1.3.132.0.10" ? "1.2.840.10045.3.1.7" : algId,
      schema: spki.subjectPublicKey.valueBlock.valueHex,
    });

    return {
      kty: "EC",
      crv: crvName,
      x: Convert.ToBase64Url(parsedKey.x),
      y: Convert.ToBase64Url(parsedKey.y),
    };
  }

  protected static jwk2pkcs(jwk: JsonWebKey): ArrayBuffer {
    const parsedKey = new pkijs.ECPrivateKey();
    let coordinateLength = 0;

    if ("crv" in jwk) {
      switch (jwk.crv.toUpperCase()) {
        case "K-256":
          parsedKey.namedCurve = "1.3.132.0.10";
          coordinateLength = 32;
          break;
        case "P-256":
          parsedKey.namedCurve = "1.2.840.10045.3.1.7";
          coordinateLength = 32;
          break;
        case "P-384":
          parsedKey.namedCurve = "1.3.132.0.34";
          coordinateLength = 48;
          break;
        case "P-521":
          parsedKey.namedCurve = "1.3.132.0.35";
          coordinateLength = 66;
          break;
        default:
      }
    } else {
      throw new Error("Absent mandatory parameter \"crv\"");
    }

    ["d"].forEach((name) => {
      if (name in jwk) {
        parsedKey.privateKey = new Asn1Js.OctetString({ valueHex: this.getCoordinate((jwk as any)[name], coordinateLength) });
      } else {
        throw new Error(`Absent mandatory parameter '${name}'`);
      }
    });

    const pkcs8 = new pkijs.PrivateKeyInfo();
    pkcs8.privateKeyAlgorithm = new pkijs.AlgorithmIdentifier({
      algorithmId: "1.2.840.10045.2.1",
      algorithmParams: new Asn1Js.ObjectIdentifier({ value: parsedKey.namedCurve }),
    });
    pkcs8.privateKey = new Asn1Js.OctetString({ valueHex: parsedKey.toSchema().toBER(false) });

    return pkcs8.toSchema().toBER(false);
  }

  protected static getCoordinate(b64: string, coordinateLength: number) {
    const buf = Convert.FromBase64Url(b64);
    const offset = coordinateLength - buf.byteLength;
    const res = new Uint8Array(coordinateLength);
    res.set(new Uint8Array(buf), offset);

    return res.buffer as ArrayBuffer;
  }

  protected static jwk2spki(jwk: JsonWebKey) {
    const parsedKey = new pkijs.ECPublicKey();
    let coordinateLength = 0;

    if ("crv" in jwk) {
      switch (jwk.crv.toUpperCase()) {
        case "K-256":
          parsedKey.namedCurve = "1.3.132.0.10";
          coordinateLength = 32;
          break;
        case "P-256":
          parsedKey.namedCurve = "1.2.840.10045.3.1.7";
          coordinateLength = 32;
          break;
        case "P-384":
          parsedKey.namedCurve = "1.3.132.0.34";
          coordinateLength = 48;
          break;
        case "P-521":
          parsedKey.namedCurve = "1.3.132.0.35";
          coordinateLength = 66;
          break;
        default:
      }
    } else {
      throw new Error("Absent mandatory parameter \"crv\"");
    }

    ["x", "y"].forEach((name) => {
      if (name in jwk) {
        parsedKey[name] = this.getCoordinate((jwk as any)[name], coordinateLength);
      } else {
        throw new Error(`Absent mandatory parameter '${name}'`);
      }
    });

    const spki = new pkijs.PublicKeyInfo();
    spki.algorithm = new pkijs.AlgorithmIdentifier({
      algorithmId: "1.2.840.10045.2.1",
      algorithmParams: new Asn1Js.ObjectIdentifier({ value: parsedKey.namedCurve }),
    });
    spki.subjectPublicKey = new Asn1Js.BitString({ valueHex: parsedKey.toSchema().toBER(false) });

    return spki.toSchema().toBER(false);
  }

  protected static pkcs2jwk(raw: ArrayBuffer): JsonWebKey {
    const asn1Pkcs8 = Asn1Js.fromBER(raw);
    const pkcs8 = new pkijs.PrivateKeyInfo({ schema: asn1Pkcs8.result });

    if (pkcs8.privateKeyAlgorithm.algorithmId !== "1.2.840.10045.2.1") {
      throw new Error("PKCS8 is not EC private key");
    }

    const algId = pkcs8.privateKeyAlgorithm.algorithmParams.valueBlock.toString();
    let crvName = algId;

    switch (crvName) {
      case "1.3.132.0.10": // K-256
        crvName = "K-256";
        break;
      case "1.2.840.10045.3.1.7": // P-256
        crvName = "P-256";
        break;
      case "1.3.132.0.34": // P-384
        crvName = "P-384";
        break;
      case "1.3.132.0.35": // P-521
        crvName = "P-521";
        break;
      default:
        throw new Error(`Unsupported EC named curve '${crvName}'`);
    }

    const asn1PrvKey = Asn1Js.fromBER(pkcs8.privateKey.valueBlock.valueHex);

    const parsedKey = new pkijs.ECPrivateKey({
      namedCurve: algId === "1.3.132.0.10" ? "1.2.840.10045.3.1.7" : algId,
      schema: asn1PrvKey.result,
    });

    return {
      kty: "EC",
      crv: crvName,
      d: Convert.ToBase64Url(parsedKey.privateKey.valueBlock.valueHex),
    };
  }

}
