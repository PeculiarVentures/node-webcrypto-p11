import * as graphene from "graphene-pk11";

export class Pkcs11Object {

  public static assertStorage(obj: graphene.Storage | undefined): asserts obj is graphene.Storage {
    if (!obj) {
      throw new TypeError("PKCS#11 object is empty");
    }
  }

  public p11Object?: graphene.Storage;

  constructor(object?: graphene.Storage) {
    this.p11Object = object;
  }

}
