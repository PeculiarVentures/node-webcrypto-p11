import { IAlgorithm, Session } from "graphene-pk11";

export class ShaCrypto {

  public static async digest(session: Session, algorithm: Algorithm, data: ArrayBuffer) {
    const p11Mech: IAlgorithm = {
      name: algorithm.name.toUpperCase().replace("-", ""),
      params: null,
    };

    return new Promise<ArrayBuffer>((resolve, reject) => {
      session.createDigest(p11Mech).once(Buffer.from(data), (err, data) => {
        if (err) {
          reject(err);
        } else {
          resolve(new Uint8Array(data).buffer);
        }
      });
    });
  }

}
