import { AsnConvert } from "@peculiar/asn1-schema";
import * as core from "webcrypto-core";
import { CryptoKey } from "../../key";

export class EcCryptoKey extends CryptoKey<Pkcs11EcKeyAlgorithm> {

  protected onAssign() {
    if (!this.algorithm.namedCurve) {
      try {
        const paramsECDSA = AsnConvert.parse(this.key.get("paramsECDSA"), core.asn1.ObjectIdentifier);
        try {
          const pointEC = core.EcCurves.get(paramsECDSA.value);
          this.algorithm.namedCurve = pointEC.name;
        } catch {
          this.algorithm.namedCurve = paramsECDSA.value;
        }
      } catch { /*nothing*/ }
    }
  }

}
