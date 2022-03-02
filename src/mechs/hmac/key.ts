import { CryptoKey } from "../../key";
import { Pkcs11HmacKeyAlgorithm } from "../../types";

export class HmacCryptoKey extends CryptoKey<Pkcs11HmacKeyAlgorithm> {

    protected onAssign() {
      this.algorithm.length = this.key.get("valueLen") << 3;
    }

}
