var test = "My text %1 messagge %10 with some %2 params %1 and %%100";
function template() {
    var t = arguments[0];
    var regFind = /[^%](%\d+)/g;
    var f = null, m = [];
    while (f = regFind.exec(t)) {
        console.log(f);
        m.push({ arg: f[1], index: f.index });
    }

    for (var i = m.length - 1; i >= 0; i--) {
        var item = m[i];
        var a = item.arg.substring(1);
        var index = item.index + 1;
        t = t.substring(0, index)+ arguments[a] + t.substring(index + 1 + a.length);
    }

    t = t.replace("%%", "%");
    return t;
}

// console.log(template(test, "FIST"));
console.log(template(test, "FIST", "SECOND"));