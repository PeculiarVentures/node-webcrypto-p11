import {Session} from "graphene-pk11";

export function GUID(session: Session): string {
    let buf = session.generateRandom(10);
    // buf to string
    let bufStr = "";
    for (let i = 0; i < buf.length; i++) {
        let str = buf[i].toString(32);
        if (str.length === 1) {
            str = "0" + str;
        }
        // some chars to Upper case
        let newStr = "";
        for (let j = 0; j < str.length; j++) {
            let isUpper = +Math.random().toString().slice(2, 3) % 2;
            if (isUpper)
                newStr += str.charAt(j).toUpperCase();
            else
                newStr += str.charAt(j);
        }
        bufStr += newStr;
    }
    // split chars to 4 groups
    let res: string[] = [];
    for (let i = 0; i < 4; i++) {
        let str = bufStr.slice(i * 5, (i + 1) * 5);
        // to upper case
        res.push(str);
    }
    return res.join("-");
}