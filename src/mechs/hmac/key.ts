import { CryptoKey } from "../../key";

export class HmacCryptoKey extends CryptoKey<Pkcs11HmacKeyAlgorithm> {

    protected onAssign() {
      this.algorithm.length = this.key.get("valueLen") << 3;
    }

}
