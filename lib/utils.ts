import * as crypto from "crypto";
import { Session } from "graphene-pk11";
import * as webcrypto from "webcrypto-core";

export function GUID(session: Session): string {
    const buf = crypto.randomBytes(10);
    // buf to string
    let bufStr = "";
    // tslint:disable-next-line:prefer-for-of
    for (let i = 0; i < buf.length; i++) {
        let str = buf[i].toString(32);
        if (str.length === 1) {
            str = "0" + str;
        }
        // some chars to Upper case
        let newStr = "";
        for (let j = 0; j < str.length; j++) {
            const isUpper = +Math.random().toString().slice(2, 3) % 2;
            if (isUpper) {
                newStr += str.charAt(j).toUpperCase();
            } else {
                newStr += str.charAt(j);
            }
        }
        bufStr += newStr;
    }
    // split chars to 4 groups
    const res: string[] = [];
    for (let i = 0; i < 4; i++) {
        const str = bufStr.slice(i * 5, (i + 1) * 5);
        // to upper case
        res.push(str);
    }
    return res.join("-");
}

export function b64_decode(b64url: string): Buffer {
    return new Buffer(webcrypto.Base64Url.decode(b64url));
}

/**
 * Prepare array of data before it's using
 * @param data Array which must be prepared
 */
export function PrepareData(data: NodeBufferSource): Buffer {
    return ab2b(data);
}

/**
 * Converts ArrayBuffer to Buffer
 * @param ab ArrayBuffer value which must be converted to Buffer
 */
function ab2b(ab: NodeBufferSource) {
    return new Buffer(ab as any);
}
