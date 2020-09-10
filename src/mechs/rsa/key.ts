import { CryptoKey } from "../../key";

export class RsaCryptoKey extends CryptoKey<RsaHashedKeyAlgorithm> {

  protected onAssign() {
    if (!this.algorithm.modulusLength) {
      this.algorithm.modulusLength = 0;
      try {
        this.algorithm.modulusLength = this.key.get("modulus").length << 3;
      } catch { /*nothing*/ }
    }

    if (!this.algorithm.publicExponent) {
      this.algorithm.publicExponent = new Uint8Array(0);
      try {
        this.algorithm.publicExponent = new Uint8Array(this.key.get("publicExponent"));
      } catch { /*nothing*/ }
    }
  }

}
