import { CryptoKey } from "../../key";

export class AesCryptoKey extends CryptoKey<AesKeyAlgorithm> {

  protected onAssign() {
    this.algorithm.length = this.key.get("valueLen") << 3;
  }

}
