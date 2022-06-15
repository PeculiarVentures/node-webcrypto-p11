import * as crypto from "crypto";
import * as pvtsutils from "pvtsutils";
import * as core from "webcrypto-core";

export class ShakeCrypto {

  public static digest(algorithm: Required<core.ShakeParams>, data: ArrayBuffer): ArrayBuffer {
    const hash = crypto.createHash(algorithm.name.toLowerCase(), { outputLength: algorithm.length })
      .update(Buffer.from(data)).digest();

    return pvtsutils.BufferSourceConverter.toArrayBuffer(hash);
  }

}
