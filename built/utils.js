"use strict";
function GUID(session) {
    var buf = session.generateRandom(10);
    var bufStr = "";
    for (var i = 0; i < buf.length; i++) {
        var str = buf[i].toString(32);
        if (str.length === 1) {
            str = "0" + str;
        }
        var newStr = "";
        for (var j = 0; j < str.length; j++) {
            var isUpper = +Math.random().toString().slice(2, 3) % 2;
            if (isUpper)
                newStr += str.charAt(j).toUpperCase();
            else
                newStr += str.charAt(j);
        }
        bufStr += newStr;
    }
    var res = [];
    for (var i = 0; i < 4; i++) {
        var str = bufStr.slice(i * 5, (i + 1) * 5);
        res.push(str);
    }
    return res.join("-");
}
exports.GUID = GUID;
