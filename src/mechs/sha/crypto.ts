import type * as graphene from "graphene-pk11";

import * as types from "../../types";

export class ShaCrypto implements types.IContainer {

  /**
   * Returns size of the hash algorithm in bits
   * @param algorithm Hash algorithm
   * @throws Throws Error if an unrecognized name
   */
  public static size(algorithm: Algorithm): number {
    switch (algorithm.name.toUpperCase()) {
      case "SHA-1":
        return 160;
      case "SHA-256":
      case "SHA3-256":
        return 256;
      case "SHA-384":
      case "SHA3-384":
        return 384;
      case "SHA-512":
      case "SHA3-512":
        return 512;
      default:
        throw new Error("Unrecognized name");
    }
  }

  public constructor(public container: types.ISessionContainer) { }

  public async digest(algorithm: Algorithm, data: ArrayBuffer): Promise<ArrayBuffer> {
    const p11Mech: graphene.IAlgorithm = {
      name: algorithm.name.toUpperCase().replace("-", ""),
      params: null,
    };

    return new Promise<ArrayBuffer>((resolve, reject) => {
      this.container.session.createDigest(p11Mech).once(Buffer.from(data), (err, data) => {
        if (err) {
          reject(err);
        } else {
          resolve(new Uint8Array(data).buffer);
        }
      });
    });
  }

}
