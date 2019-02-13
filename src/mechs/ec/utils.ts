import * as graphene from "graphene-pk11";

interface IEcPoint {
  x: Buffer;
  y?: Buffer;
}

export class EcUtils {

  public static getData(data: Buffer): Buffer {
    let octet = false;
    for (let i = 0; i < data.length; i++) {
      if (data[i] === 4) {
        if (octet) {
          return data.slice(i);
        } else {
          octet = true;
        }
      }
    }
    throw new Error("Wrong data");
  }

  // Used by SunPKCS11 and SunJSSE.
  public static decodePoint(data: Buffer, curve: graphene.INamedCurve, prepare = false): IEcPoint {
    if (curve.name === "curve25519") {
      return {
        x: data,
      };
    }

    if (prepare) {
      data = this.getData(data);
    }

    if ((data.length === 0) || (data[0] !== 4)) {
      throw new Error("Only uncompressed point format supported");
    }
    // Per ANSI X9.62, an encoded point is a 1 byte type followed by
    // ceiling(log base 2 field-size / 8) bytes of x and the same of y.
    const n = (data.length - 1) / 2;
    if (n !== (Math.ceil(curve.size / 8))) {
      throw new Error("Point does not match field size");
    }

    const xb: Buffer = data.slice(1, 1 + n);
    const yb: Buffer = data.slice(n + 1, n + 1 + n);

    return { x: xb, y: yb };
  }

  public static encodePoint(point: IEcPoint, curve: graphene.INamedCurve): Buffer {
    // get field size in bytes (rounding up)
    const n = Math.ceil(curve.size / 8);
    // const xb = this.trimZeroes(point.x);
    // const yb = this.trimZeroes(point.y);
    const xb = this.padZeroes(point.x, n);
    const yb = this.padZeroes(point.y, n);
    if ((xb.length > n) || (yb.length > n)) {
      throw new Error("Point coordinates do not match field size");
    }
    const b = Buffer.concat([Buffer.from([4]), xb, yb]);

    // ASN1 encode OCTET_STRING
    const octet = Buffer.concat([Buffer.from([4]), this.encodeAsn1Length(b.length), b]);
    return octet;
  }

  public static trimZeroes(b: Buffer): Buffer {
    let i = 0;
    while ((i < b.length - 1) && (b[i] === 0)) {
      i++;
    }
    if (i === 0) {
      return b;
    }

    return b.slice(i, b.length);
  }

  public static padZeroes(b: Buffer, size: number): Buffer {
    const pad = Buffer.alloc(size - b.length);
    pad.fill(0, 0, pad.length);
    return Buffer.concat([pad, b]);
  }

  public static encodeAsn1Length(length: number): Buffer {
    const enc: number[] = [];
    if (length !== (length & 0x7F)) {
      let code = length.toString(16);
      const len = Math.round(code.length / 2);
      enc[0] = len | 0x80;
      if (Math.floor(code.length % 2) > 0) {
        code = "0" + code;
      }
      for (let i = 0; i < code.length; i = i + 2) {
        enc[1 + (i / 2)] = parseInt(code.substring(i, i + 2), 16);
      }
    } else {
      enc[0] = length;
    }
    return Buffer.from(enc);
  }
}
