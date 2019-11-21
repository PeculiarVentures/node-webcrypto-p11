import { CryptoKey } from "../../key";

export class AesCryptoKey extends CryptoKey<Pkcs11AesKeyAlgorithm> {

  protected onAssign() {
    this.algorithm.length = this.key.get("valueLen") << 3;
  }

}
