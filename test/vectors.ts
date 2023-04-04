import * as assert from "node:assert";
import { WebcryptoTest, vectors } from "@peculiar/webcrypto-test";
import { ITestImportAction } from "@peculiar/webcrypto-test/build/types/types";
import * as graphene from "graphene-pk11";
import { Convert } from "pvtsutils";

import { Crypto } from "../src";
import * as config from "./config";
import { isNSS } from "./helper";

function fixEcImport(item: ITestImportAction): void {
  if (item.name?.startsWith("JWK private key")) {
    const jwk = item.data as JsonWebKey;
    delete jwk.x;
    delete jwk.y;
  }
  if (item.name?.startsWith("PKCS8 P-256")) {
    item.data = Buffer.from("3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420895118e4e168dc9ee0d419d2c3f5845b2918fda96b84d9a91012f2ffb70d9ee1", "hex");
  }
  if (item.name?.startsWith("PKCS8 P-384")) {
    item.data = Buffer.from("304e020100301006072a8648ce3d020106052b8104002204373035020101043098d7c6a318f0a02efe1a17552492884c11a079314d4cc9f92e1504905436072d61539fc7fd73371eeda4c80e3902c743", "hex");
  }
  if (item.name?.startsWith("PKCS8 P-521")) {
    item.data = Buffer.from("3060020100301006072a8648ce3d020106052b81040023044930470201010442006c71a419f8a4e6ad25f99308ef475ba5319678acb5f9cde61bdf301e69e953e7766c0adc603397728aa0e4873fa679ad1efc6693e125df7bb75e880638d28f968b", "hex");
  }
}

// Fix EC import tests.
// PKCS#11 doesn't return public key from private key
vectors.ECDSA.actions.import?.forEach(fixEcImport);
vectors.ECDH.actions.import?.forEach(fixEcImport);
vectors.ECDH.actions.deriveKey?.forEach((item) => {
  if (item.name === "P-521 256") {
    // module doesn't support AES-CTR
    item.derivedKeyType.name = "AES-CBC";
  }
});

// WebcryptoTest.check(config.crypto as Crypto, [
//   vectors.AES128CBC,
// ]);
WebcryptoTest.check(config.crypto as Crypto, {
  AES128KW: true,
  AES192KW: true,
  AES256KW: true,
  PBKDF2: true,
  HKDF: true,
  DESCBC: true,
  DESEDE3CBC: true,
  RSAESPKCS1: true,
  AES128CMAC: true,
  AES192CMAC: true,
  AES256CMAC: true,
  AES128CTR: true,
  AES192CTR: true,
  AES256CTR: true,
});

context("RSA-OAEP", () => {

  const CKM_RSA_OAEP = graphene.MechanismEnum.RSA_X_509;

  before(() => {
    // @ts-ignore Change mechanism to skip CKM_RSA_X_509 usage
    graphene.MechanismEnum.RSA_X_509 = graphene.MechanismEnum.VENDOR_DEFINED | graphene.MechanismEnum.RSA_X_509;
  });

  after(() => {
    // @ts-ignore Restore mechanism
    graphene.MechanismEnum.RSA_X_509 = CKM_RSA_OAEP;
  });

  const test = isNSS("RSA-OAEP-SHA1 throws CKR_DEVICE_ERROR") ? it.skip : it;

  test("Use standard CKM_RSA_OAEP instead of CKM_RSA_X_509", async () => {
    const data = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const encData = Buffer.from("MAKiRseL08AlR8Fmn1uVz/lDDdrDiRyI6KUW3mcE/0kxwW7/VizQJP+jiTSWyHexhQ+Sp0ugm6Doa/jahajuVf0aFkqJCcEKlSeMGvu4QdDc9tJzeNJVqSbPovFy60Criyjei4ganw2RQM2Umav//HfQEyqGTcyftMxXzkDDBQU=", "base64");

    // import keys
    const jwkPublicKey = {
      alg: "RSA-OAEP",
      e: "AQAB",
      ext: true,
      key_ops: ["encrypt"],
      kty: "RSA",
      n: "vqpvdxuyZ6rKYnWTj_ZzDBFZAAAlpe5hpoiYHqa2j5kK7v8U5EaPY2bLib9m4B40j-n3FV9xUCGiplWdqMJJKT-4PjGO5E3S4N9kjFhu57noYT7z7302J0sJXeoFbXxlgE-4G55Oxlm52ID2_RJesP5nzcGTriQwoRbrJP5OEt0",
    };
    const jwkPrivateKey = {
      alg: "RSA-OAEP",
      d: "AkeIWJywp9OfYsj0ECsKmhDVBw55ZL_yU-rbIrashQ_31P6gsc_0I-SVN1rd8Hz79OJ_rTY8ZRBZ4PIyFdPoyvuo5apHdAHH6riJKxDHWPxhE-ReNVEPSTiF1ry8DSe5zC7w9BLnH_QM8bkN4cOnvgqrg7EbrGWomAGJVvoRwOM",
      dp: "pOolqL7HwnmWLn7GDX8zGkm0Q1IAj-ouBL7ZZbaTm3wETLtwu-dGsQheEdzP_mfL_CTiCAwGuQBcSItimD0DdQ",
      dq: "FTSY59AnkgmB7TsErWNBE3xlVB_pMpE2xWyCBCz96gyDOUOFDz8vlSV-clhjawJeRd1n30nZOPSBtOHozhwZmQ",
      e: "AQAB",
      ext: true,
      key_ops: ["decrypt"],
      kty: "RSA",
      n: "vqpvdxuyZ6rKYnWTj_ZzDBFZAAAlpe5hpoiYHqa2j5kK7v8U5EaPY2bLib9m4B40j-n3FV9xUCGiplWdqMJJKT-4PjGO5E3S4N9kjFhu57noYT7z7302J0sJXeoFbXxlgE-4G55Oxlm52ID2_RJesP5nzcGTriQwoRbrJP5OEt0",
      p: "6jFtmBJJQFIlQUXXZYIgvH70Y9a03oWKjNuF2veb5Zf09EtLNE86NpnIm463OnoHJPW0m8wHFXZZfcYVTIPR_w",
      q: "0GttDMl1kIzSV2rNzGXpOS8tUqr5Lz0EtVZwIb9GJPMmJ0P3gZ801zEgZZ4-esU7cLUf-BSZEAmfnKA80G2jIw",
      qi: "FByTxX4G2eXkk1xe0IuiEv7I5NS-CnFyp8iB4XLG0rabnfcIZFKpf__X0sNyVOAVo5-jJMuUYjCRTdaXNAWhkg",
    };
    const alg = { name: "RSA-OAEP", hash: "SHA-1" };
    const keys = {
      publicKey: await config.crypto.subtle.importKey("jwk", jwkPublicKey, alg, true, ["encrypt"]),
      privateKey: await config.crypto.subtle.importKey("jwk", jwkPrivateKey, alg, true, ["decrypt"]),
    };
    const encKey = keys.publicKey;
    const decKey = keys.privateKey;

    // encrypt
    const enc = await config.crypto.subtle.encrypt(alg, encKey, data);

    // decrypt
    let dec = await config.crypto.subtle.decrypt(alg, decKey, enc);
    assert.equal(Convert.ToHex(dec), Convert.ToHex(data));

    dec = await config.crypto.subtle.decrypt(alg, decKey, encData);
    assert.equal(Convert.ToHex(dec), Convert.ToHex(data));
  });

});

it("custom", async () => {
  const pem = [
    `-----BEGIN CERTIFICATE-----\nMIIINzCCBh+gAwIBAgIDAID8MA0GCSqGSIb3DQEBCwUAMIGpMQswCQYDVQQGEwJJ\nVDEcMBoGA1UECgwTSW5mb0NhbWVyZSBTLkMucC5BLjEpMCcGA1UECwwgUXVhbGlm\naWVkIFRydXN0IFNlcnZpY2UgUHJvdmlkZXIxGjAYBgNVBGEMEVZBVElULTAyMzEz\nODIxMDA3MTUwMwYDVQQDDCxJbmZvQ2FtZXJlIFF1YWxpZmllZCBFbGVjdHJvbmlj\nIFNpZ25hdHVyZSBDQTAeFw0yMDEyMTUxNDEwNTNaFw0yMzEyMTUwMDAwMDBaMIGB\nMQswCQYDVQQGEwJJVDEOMAwGA1UEBAwFQ09TRVIxHzAdBgNVBAUTFlRJTklULUNT\nUlJOVDY2QjE3TDM3OE8xFTATBgNVBAMMDENPU0VSIFJFTkFUTzEZMBcGA1UELhMQ\nU0lHMDAwMDAwNDEwMzc4MzEPMA0GA1UEKgwGUkVOQVRPMIIBIjANBgkqhkiG9w0B\nAQEFAAOCAQ8AMIIBCgKCAQEAtXwB8ZLBiEUCLUBUqUWyQGpf0Yg612mdFOMGgkxQ\n9OdxKbrpDbibpjllOmmiN12Xu4eesRJyzgkKE0muyFIUdm6vQeoQll6LB/UxvyC+\nyBKnBk7vf61AxQ5DEWjIXMW9QQtkoFMcy7lvSUDvmGYiFXaonTjasyxurNndDAkO\no3RIj40ZyT0fzjyTwwup/uU6Boa/f+qXFRBYMR3FYRdL6dirBaOMYwyVwazgxgFq\nCeDS8PaXQ7/04ZYCYM7jTJioo4KT2RelCRUaTeSFWMCDhBdcC2EmLBb+lA5P8T0C\n2TYqw24gSx8JxdqJHA2CRDF8cvlTIHBLtq7RfR/e9lzitQIDAQABo4IDjDCCA4gw\nCQYDVR0TBAIwADCB5gYDVR0gBIHeMIHbMAkGBwQAi+xAAQIwVwYGK0wOAQEeME0w\nSwYIKwYBBQUHAgEWP2h0dHBzOi8vaWQuaW5mb2NhbWVyZS5pdC9kaWdpdGFsLWlk\nL2Zpcm1hLWRpZ2l0YWxlL21hbnVhbGkuaHRtbDB1BgQrTBAGMG0wawYIKwYBBQUH\nAgIwXwxdUXVlc3RvIGNlcnRpZmljYXRvIHJpc3BldHRhIGxlIHJhY2NvbWFuZGF6\naW9uaSBwcmV2aXN0ZSBkYWxsYSBEZXRlcm1pbmF6aW9uZSBBZ2lkIE4uIDEyMS8y\nMDE5MIG/BggrBgEFBQcBAwSBsjCBrzAIBgYEAI5GAQEwCAYGBACORgEEMAsGBgQA\njkYBAwIBFDATBgYEAI5GAQYwCQYHBACORgEGATB3BgYEAI5GAQUwbTBrFmVodHRw\nczovL2lkLmluZm9jYW1lcmUuaXQvZGlnaXRhbC1pZC9maXJtYS1kaWdpdGFsZS9t\nYW51YWxpL3Bkcy1zZXJ2aXppLXF1YWxpZmljYXRpLWNlcnRpZmljYXppb25lLnBk\nZhMCZW4wcgYIKwYBBQUHAQEEZjBkMCsGCCsGAQUFBzABhh9odHRwOi8vb2NzcC5x\nYy5jYS5pbmZvY2FtZXJlLml0MDUGCCsGAQUFBzAChilodHRwOi8vY2VydC5jYS5p\nbmZvY2FtZXJlLml0L2NhL3FjL0NBLmNydDCCAQoGA1UdHwSCAQEwgf4wgfuggfig\ngfWGK2h0dHA6Ly9jcmwuY2EuaW5mb2NhbWVyZS5pdC9jYS9xYy9DUkwwMS5jcmyG\ngcVsZGFwOi8vbGRhcC5jYS5pbmZvY2FtZXJlLml0L2NuJTNESW5mb0NhbWVyZSUy\nMFF1YWxpZmllZCUyMEVsZWN0cm9uaWMlMjBTaWduYXR1cmUlMjBDQSUyMENSTDAx\nLG91JTNEUXVhbGlmaWVkJTIwVHJ1c3QlMjBTZXJ2aWNlJTIwUHJvdmlkZXIsbyUz\nREluZm9DYW1lcmUlMjBTLkMucC5BLixjJTNESVQ/Y2VydGlmaWNhdGVSZXZvY2F0\naW9uTGlzdDAOBgNVHQ8BAf8EBAMCBkAwHwYDVR0jBBgwFoAUeoBobdP8eWLU3W3L\nwqPsK83q/sEwHQYDVR0OBBYEFAHo+DpXx7/yhicBYlyShr+AXsbWMA0GCSqGSIb3\nDQEBCwUAA4ICAQB5vDs75W+qelg+zTzjj5dOLOUgO4O3ILOOgrkRR3nSRzl6h8go\nq81knMmVHCnkde2uzBXw1hBv6XKuEIrwgA03/elS09H/KIDN1lNCFSisv15igvrt\n/T4DbpfTnX1n891h5UdlHO3dbPhV4FLfvrhTiSYGJNEU4SqRyEYtykyhtmGaCMot\nvadXFVvnmota64w1uJuGpUT2YmCY4sTc2HefdMZUxU/n2PxlDc/TFc4avgBOjmhA\nMTXsUe6yYcEaWk3qfy70RqxBcF9aBKz4lnpoIOzjpWhLl2gZBf/ukbDEw39fqY5v\nkhHD3LvqWgk3YThVBY812+V2g5DOhFtWPCHummmBikc8ECMX4XxQ33A2dSOrsIYW\nxAPK0fp/AWOTo8PGwWDRh+gA2wTwKT/OqwthBvPJ3DcqUkBKyO/KHprkGcIfzS15\np/FX3wgtHcLVlsHwX/msJSwtGSExgIG5sK+4qeNl1sNAk1Xuqs5LIlzj7Vmxkg10\nyzSxwv5hQZsQhIhrUX8d9dJs1tDeuA4pD2jEwCJJAjtyjI0GRrAo+5eTOiISKjUk\nBkaSecikisA/Rz0fuDBXtfRjsq/YaEJguZb02B79Vc/Qz9pI4frIvTCdyAAgk5lV\nh0xr+hTueDUJLjuKFrcUKrhhIEgzWTt8UnhAfmIKannXlNegrs8J79fqxQ==\n-----END CERTIFICATE-----`,
    `-----BEGIN CERTIFICATE-----\nMIIFnDCCBISgAwIBAgIQXiLl2Y8He0o6EDaiiiW53DANBgkqhkiG9w0BAQsFADBs\nMQswCQYDVQQGEwJJVDEYMBYGA1UECgwPQXJ1YmFQRUMgUy5wLkEuMSEwHwYDVQQL\nDBhDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eUMxIDAeBgNVBAMMF0FydWJhUEVDIFMu\ncC5BLiBORyBDQSAzMB4XDTIwMDYwOTAwMDAwMFoXDTIzMDYwOTIzNTk1OVowdzEL\nMAkGA1UEBhMCSVQxFDASBgNVBAMMC0JFUlRJIE1JUktPMR8wHQYDVQQFExZUSU5J\nVC1CUlRNUks3NFAyOEIwMDZUMQ4wDAYDVQQqDAVNSVJLTzEOMAwGA1UEBAwFQkVS\nVEkxETAPBgNVBC4TCDIxNDAzODkxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\nCgKCAQEAuhcbGseJ6TGP1HW+ys8zuztEEfG/LjGgeg+C5hhE7CmIr2fSKXn5NTfV\nIqR9sRkAoaLt0asZHZPfqlYXqCfpnC35zn5oP9g1gDq0Cp7FDFuW16tdFRFjyaW5\nJMT4O82Cf861OswyYSHos9nAeqhWg/NeARI4aaGTtDH5Jd/ebhMr+n9YXNQsW0uH\nm2Q+YcV5QdiOAA+dHff2Edgcz+cRaryB9ma3EZmKnKQKCmuck1lkxRX64fV4Dc3e\nSHTm6Fcmfbe7OHl2fuvxk5H15cZdxSF9VM1mcaKxarTpR5zLkKxqQJKQ/YAkgeA1\n1pMlejJ45YM/xmAasZUV/STSf6XBbwIDAQABo4ICLTCCAikwDgYDVR0PAQH/BAQD\nAgZAMB0GA1UdDgQWBBTc/tOHIIBJZ+XYUm8PVfBZSu/S6jBPBgNVHSAESDBGMDwG\nCysGAQQBgegtAQEBMC0wKwYIKwYBBQUHAgEWH2h0dHBzOi8vY2EuYXJ1YmFwZWMu\naXQvY3BzLmh0bWwwBgYEK0wQBjBYBgNVHR8EUTBPME2gS6BJhkdodHRwOi8vY3Js\nLmFydWJhcGVjLml0L0FydWJhUEVDU3BBQ2VydGlmaWNhdGlvbkF1dGhvcml0eUMv\nTGF0ZXN0Q1JMLmNybDCBvwYIKwYBBQUHAQMEgbIwga8wCAYGBACORgEBMAsGBgQA\njkYBAwIBFDAIBgYEAI5GAQQwgYsGBgQAjkYBBTCBgDA+FjhodHRwczovL3d3dy5w\nZWMuaXQvcmVwb3NpdG9yeS9hcnViYXBlYy1xdWFsaWYtcGRzLWVuLnBkZhMCZW4w\nPhY4aHR0cHM6Ly93d3cucGVjLml0L3JlcG9zaXRvcnkvYXJ1YmFwZWMtcXVhbGlm\nLXBkcy1pdC5wZGYTAml0MB8GA1UdIwQYMBaAFPDARbG2NbTqXyn6gwNK3C/1s33o\nMGoGCCsGAQUFBwEBBF4wXDA1BggrBgEFBQcwAoYpaHR0cDovL2NhY2VydC5wZWMu\naXQvY2VydHMvQVBfTkdfQ0FfMy5jZXIwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3Nw\nLmFydWJhcGVjLml0MA0GCSqGSIb3DQEBCwUAA4IBAQBa1xYtYVvHqIS076oNItYW\n8f/cUZmrtSuzz4DR9vgnh8Nnl4UZOjtNLa6EEWg8N2Qe6CQKRDkNre/Imm+BsLkT\nxzGcVTTUX04ERL9NLe/jave3s+SXrOz8Dcr9CSeswa6Ky+/8WBZeqDi9pJWTL0bD\nwLofLlWNP6iTvezMq/5WBAtOCnVMLvKcMzrFacoDrbBiOummNoJ2u0+/DXgtmmcx\nQNgW1j6lDRWanthAmyXtmqn49T6EWn11q27UbLSDfuQkRTHBgUpRmYtn8vw7PYMo\nC+2O5/OOiDrW2MGwLYZ7zwJA7r4TdLD0AltBl6h6HnDPMu23xngj2wi3pda2bC7I\n-----END CERTIFICATE-----`,
  ];
  for (const item of pem) {
    const cert = await config.crypto.certStorage.importCert("pem", item, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, ["verify"]);
    await config.crypto.certStorage.setItem(cert);
  }
});
