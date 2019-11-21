import { CryptoKey } from "../../key";

export class RsaCryptoKey extends CryptoKey<Pkcs11RsaHashedKeyAlgorithm> {

  protected onAssign() {
    this.algorithm.modulusLength = this.key.get("modulus").length << 3;
    this.algorithm.publicExponent = new Uint8Array(this.key.get("publicExponent"));
  }

}
