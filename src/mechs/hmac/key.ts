import { CryptoKey } from "../../key";

export class HmacCryptoKey extends CryptoKey<Pkcs11HmacKeyAlgorithm> {

    protected override onAssign() {
      this.algorithm.length = this.key.get("valueLen") << 3;
    }

}
