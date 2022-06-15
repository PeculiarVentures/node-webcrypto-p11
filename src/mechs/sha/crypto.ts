import type * as graphene from "graphene-pk11";

import * as types from "../../types";

export class ShaCrypto implements types.IContainer {

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
