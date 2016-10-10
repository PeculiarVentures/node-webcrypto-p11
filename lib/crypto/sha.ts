import { BaseCrypto } from "../base";

import {
    Session,
    IAlgorithm,
} from "graphene-pk11";

export class ShaCrypto extends BaseCrypto {

    static digest(algorithm: Algorithm, data: Buffer, session?: Session): PromiseLike<ArrayBuffer> {
        return super.digest.apply(this, arguments)
            .then(() => {
                return new Promise((resolve, reject) => {
                    session!.createDigest(this.wc2pk11(algorithm)).once(data, (err, data) => {
                        if (err) reject(err); else resolve(data.buffer);
                    });
                });
            });
    }

    static wc2pk11(alg: Algorithm): IAlgorithm {
        let res = alg.name.toUpperCase().replace("-", "");
        return { name: res, params: null };
    }
}