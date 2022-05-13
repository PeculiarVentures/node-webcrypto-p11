import { AsnConvert, AsnParser, AsnSerializer, OctetString } from "@peculiar/asn1-schema";
import { JsonParser, JsonSerializer } from "@peculiar/json-schema";
import * as graphene from "graphene-pk11";
import { Convert } from "pvtsutils";
import * as core from "webcrypto-core";

import { Assert } from "../../assert";
import { CryptoKey } from "../../key";
import * as types from "../../types";
import * as utils from "../../utils";

import { EcCryptoKey } from "./key";

// tslint:disable-next-line: variable-name
const id_ecPublicKey = "1.2.840.10045.2.1";

export class EcCrypto implements types.IContainer {

  public publicKeyUsages = ["verify"];
  public privateKeyUsages = ["sign", "deriveKey", "deriveBits"];

  public constructor(public container: types.ISessionContainer) {
  }

  public async generateKey(algorithm: Pkcs11EcKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    return new Promise<CryptoKeyPair>((resolve, reject) => {
      // Create PKCS#11 templates
      const attrs: types.Pkcs11Attributes = {
        id: utils.GUID(),
        label: algorithm.label,
        token: algorithm.token,
        sensitive: algorithm.sensitive,
        extractable,
        usages: keyUsages,
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

      // EC params
      publicTemplate.paramsEC = Buffer.from(core.EcCurves.get(algorithm.namedCurve).raw);

      // PKCS11 generation
      this.container.session.generateKeyPair(graphene.KeyGenMechanism.EC, publicTemplate, privateTemplate, (err, keys) => {
        try {
          if (err) {
            reject(err);
          } else {
            if (!keys) {
              throw new Error("Cannot get keys from callback function");
            }
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

  public async exportKey(format: KeyFormat, key: EcCryptoKey): Promise<JsonWebKey | ArrayBuffer> {
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

  public async importKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: Pkcs11EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    switch (format.toLowerCase()) {
      case "jwk": {
        const jwk: any = keyData;
        if (jwk.d) {
          return this.importJwkPrivateKey(jwk, algorithm, extractable, keyUsages);
        } else {
          return this.importJwkPublicKey(jwk, algorithm, extractable, keyUsages);
        }
      }
      case "spki": {
        const jwk = this.spki2jwk(keyData as ArrayBuffer);
        return this.importJwkPublicKey(jwk, algorithm, extractable, keyUsages);
      }
      case "pkcs8": {
        const jwk = this.pkcs2jwk(keyData as ArrayBuffer);
        return this.importJwkPrivateKey(jwk, algorithm, extractable, keyUsages);
      }
      case "raw": {
        const curve = core.EcCurves.get(algorithm.namedCurve);
        const ecPoint = core.EcUtils.decodePoint(keyData as Uint8Array, curve.size);
        const jwk: JsonWebKey = {
          kty: "EC",
          crv: algorithm.namedCurve,
          x: Convert.ToBase64Url(ecPoint.x),
        };
        if (ecPoint.y) {
          jwk.y = Convert.ToBase64Url(ecPoint.y);
        }
        return this.importJwkPublicKey(jwk, algorithm, extractable, keyUsages);
      }
      default:
        throw new core.OperationError("format: Must be 'jwk', 'raw', 'pkcs8' or 'spki'");
    }
  }

  public getAlgorithm(p11AlgorithmName: string | number) {
    const mechanisms = this.container.session.slot.getMechanisms();
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

  public prepareData(hashAlgorithm: string, data: Buffer) {
    // use nodejs crypto for digest calculating
    return utils.digest(hashAlgorithm.replace("-", ""), data);
  }

  protected importJwkPrivateKey(jwk: JsonWebKey, algorithm: Pkcs11EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[]) {
    const template = this.createTemplate({
      action: "import",
      type: "private",
      attributes: {
        id: utils.GUID(),
        token: algorithm.token,
        sensitive: algorithm.sensitive,
        label: algorithm.label,
        extractable,
        usages: keyUsages,
      },
    });

    // Set EC private key attributes
    template.paramsEC = Buffer.from(core.EcCurves.get(algorithm.namedCurve).raw);
    template.value = utils.b64UrlDecode(jwk.d!);

    const p11key = this.container.session.create(template).toType<graphene.Key>();

    return new EcCryptoKey(p11key, algorithm);
  }

  protected importJwkPublicKey(jwk: JsonWebKey, algorithm: Pkcs11EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[]) {
    const namedCurve = core.EcCurves.get(algorithm.namedCurve);
    const template = this.createTemplate({
      action: "import",
      type: "public",
      attributes: {
        id: utils.GUID(),
        token: algorithm.token,
        label: algorithm.label,
        extractable,
        usages: keyUsages,
      }
    });

    // Set EC public key attributes
    template.paramsEC = Buffer.from(namedCurve.raw);;
    let pointEc: Buffer;
    if (namedCurve.name === "curve25519") {
      pointEc = utils.b64UrlDecode(jwk.x!);
    } else {
      const point = core.EcUtils.encodePoint({ x: utils.b64UrlDecode(jwk.x!), y: utils.b64UrlDecode(jwk.y!) }, namedCurve.size)
      const derPoint = AsnConvert.serialize(new OctetString(point))
      pointEc = Buffer.from(derPoint);
    }
    template.pointEC = pointEc;

    const p11key = this.container.session.create(template).toType<graphene.Key>();

    return new EcCryptoKey(p11key, algorithm);
  }

  protected exportJwkPublicKey(key: EcCryptoKey) {
    const pkey: graphene.ITemplate = key.key.getAttribute({
      pointEC: null,
    });
    const curve = core.EcCurves.get(key.algorithm.namedCurve);
    // Parse DER-encoded of ANSI X9.62 ECPoint value ''Q''
    const p11PointEC = pkey.pointEC;
    if (!p11PointEC) {
      throw new Error("Cannot get required ECPoint attribute");
    }
    const derEcPoint = AsnConvert.parse(p11PointEC, OctetString);
    const ecPoint = core.EcUtils.decodePoint(derEcPoint, curve.size);
    const jwk: JsonWebKey = {
      kty: "EC",
      crv: key.algorithm.namedCurve,
      ext: true,
      key_ops: key.usages,
      x: Convert.ToBase64Url(ecPoint.x),
    };
    if (curve.name !== "curve25519") {
      jwk.y = Convert.ToBase64Url(ecPoint.y!);
    }
    return jwk;
  }

  protected async exportJwkPrivateKey(key: EcCryptoKey) {
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

  /**
   * Creates PKCS11 template
   * @param params
   */
  protected createTemplate(params: types.ITemplateBuildParameters): types.ITemplate {
    const template = this.container.templateBuilder.build({
      ...params,
      attributes: {
        ...params.attributes,
        label: params.attributes.label || "EC",
      },
    });

    template.keyType = graphene.KeyType.EC;

    return template;
  }

  protected spki2jwk(raw: ArrayBuffer): JsonWebKey {
    const keyInfo = AsnParser.parse(raw, core.asn1.PublicKeyInfo);

    if (keyInfo.publicKeyAlgorithm.algorithm !== id_ecPublicKey) {
      throw new Error("SPKI is not EC public key");
    }

    const namedCurveId = AsnParser.parse(keyInfo.publicKeyAlgorithm.parameters!, core.asn1.ObjectIdentifier);
    const namedCurve = core.EcCurves.get(namedCurveId.value);

    const ecPublicKey = new core.asn1.EcPublicKey(keyInfo.publicKey);
    const json = JsonSerializer.toJSON(ecPublicKey);

    return {
      kty: "EC",
      crv: namedCurve.name,
      ...json,
    };
  }

  protected jwk2pkcs(jwk: JsonWebKey): ArrayBuffer {
    Assert.requiredParameter(jwk.crv, "crv");
    const namedCurve = core.EcCurves.get(jwk.crv);

    const ecPrivateKey = JsonParser.fromJSON(jwk, { targetSchema: core.asn1.EcPrivateKey });

    const keyInfo = new core.asn1.PrivateKeyInfo();
    keyInfo.privateKeyAlgorithm = new core.asn1.AlgorithmIdentifier();
    keyInfo.privateKeyAlgorithm.algorithm = id_ecPublicKey;
    keyInfo.privateKeyAlgorithm.parameters = namedCurve.raw;
    keyInfo.privateKey = AsnSerializer.serialize(ecPrivateKey);

    return AsnSerializer.serialize(keyInfo);
  }

  protected getCoordinate(b64: string, coordinateLength: number) {
    const buf = Convert.FromBase64Url(b64);
    const offset = coordinateLength - buf.byteLength;
    const res = new Uint8Array(coordinateLength);
    res.set(new Uint8Array(buf), offset);

    return res.buffer as ArrayBuffer;
  }

  protected jwk2spki(jwk: JsonWebKey) {
    if (!jwk.crv) {
      throw new Error("Absent mandatory parameter \"crv\"");
    }
    const namedCurve = core.EcCurves.get(jwk.crv);

    const ecPublicKey = JsonParser.fromJSON(jwk, { targetSchema: core.asn1.EcPublicKey });

    const keyInfo = new core.asn1.PublicKeyInfo();
    keyInfo.publicKeyAlgorithm.algorithm = id_ecPublicKey;
    keyInfo.publicKeyAlgorithm.parameters = namedCurve.raw;
    keyInfo.publicKey = ecPublicKey.value;
    return AsnSerializer.serialize(keyInfo);
  }

  protected pkcs2jwk(raw: ArrayBuffer): JsonWebKey {
    const keyInfo = AsnParser.parse(raw, core.asn1.PrivateKeyInfo);

    if (keyInfo.privateKeyAlgorithm.algorithm !== id_ecPublicKey) {
      throw new Error("PKCS8 is not EC private key");
    }

    if (!keyInfo.privateKeyAlgorithm.parameters) {
      throw new Error("Cannot get required Named curve parameters from ASN.1 PrivateKeyInfo structure");
    }

    const namedCurveId = AsnParser.parse(keyInfo.privateKeyAlgorithm.parameters!, core.asn1.ObjectIdentifier);
    const namedCurve = core.EcCurves.get(namedCurveId.value);

    const ecPrivateKey = AsnParser.parse(keyInfo.privateKey, core.asn1.EcPrivateKey);
    const json = JsonSerializer.toJSON(ecPrivateKey);

    return {
      kty: "EC",
      crv: namedCurve.name,
      ...json,
    };
  }

}
