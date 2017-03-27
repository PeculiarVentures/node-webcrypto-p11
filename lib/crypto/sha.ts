import { BaseCrypto } from "../base";

import {
    IAlgorithm,
    Session,
} from "graphene-pk11";

export class ShaCrypto extends BaseCrypto {

    public static digest(algorithm: Algorithm, data: Buffer, session?: Session): PromiseLike<ArrayBuffer> {
        return super.digest.apply(this, arguments)
            .then(() => {
                return new Promise((resolve, reject) => {
                    session!.createDigest(this.wc2pk11(algorithm)).once(data, (err, data) => {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(data.buffer);
                        }
                    });
                });
            });
    }

    protected static wc2pk11(alg: Algorithm): IAlgorithm {
        const res = alg.name.toUpperCase().replace("-", "");
        return { name: res, params: null };
    }
}
