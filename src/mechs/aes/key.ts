import { CryptoKey } from "../../key";

export class AesCryptoKey extends CryptoKey<Pkcs11AesKeyAlgorithm> {

  protected override onAssign() {
    this.algorithm.length = this.key.get("valueLen") << 3;
  }

}
