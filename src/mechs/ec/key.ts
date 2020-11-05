import { NamedCurve } from "graphene-pk11";

import { CryptoKey } from "../../key";

export class EcCryptoKey extends CryptoKey<Pkcs11EcKeyAlgorithm> {

  protected onAssign() {
    if (!this.algorithm.namedCurve) {
      this.algorithm.namedCurve = "";
      try {
        const paramsECDSA = this.key.get("paramsECDSA");
        try {
          const pointEC = NamedCurve.getByBuffer(paramsECDSA!);
          switch (pointEC.name) {
            case "secp192r1":
              this.algorithm.namedCurve = "P-192";
              break;
            case "secp256r1":
              this.algorithm.namedCurve = "P-256";
              break;
            case "secp384r1":
              this.algorithm.namedCurve = "P-384";
              break;
            case "secp521r1":
              this.algorithm.namedCurve = "P-521";
              break;
            default:
              this.algorithm.namedCurve = pointEC.name;
          }
        } catch {
          this.algorithm.namedCurve = paramsECDSA.toString("hex");
        }
      } catch { /*nothing*/ }
    }
  }

}
