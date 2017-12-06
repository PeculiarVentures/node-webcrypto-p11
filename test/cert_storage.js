var assert = require('assert');
var crypto = require('./config').crypto;
var isSoftHSM = require('./config').isSoftHSM;

const X509_RAW = new Buffer("308203A830820290A003020102020900FEDCE3010FC948FF300D06092A864886F70D01010505003034310B300906035504061302465231123010060355040A0C094468696D796F7469733111300F06035504030C084365727469676E61301E170D3037303632393135313330355A170D3237303632393135313330355A3034310B300906035504061302465231123010060355040A0C094468696D796F7469733111300F06035504030C084365727469676E6130820122300D06092A864886F70D01010105000382010F003082010A0282010100C868F1C9D6D6B3347526821EECB4BEEA5CE126ED114761E1A27C16784021E4609E5AC863E1C4B19692FF186D6923E12B62F7DDE2362F9107B948CF0EEC79B62CE7344B700825A33C871B19F281070F389019D311FE86B4F2D15E1E1E96CD806CCE3B3193B6F2A0D0A995127DA59ACC6BC884568A33A9E722155316F0CC17EC575FE9A20A9809DEE35F9C6FDC48E3850B155AA6BA9FAC48E309B2F7F432DE5E34BE1C785D425BCE0E228F4D90D77D3218B30B2C6ABF8E3F141189200E7714B53D940887F7251ED5B26000EC6F2A28256E2A3E186317253F3E442016F626C825AE054AB4E7632CF38C16537E5CFB111A08C146629F22B8F1C28D69DCFA3A5806DF0203010001A381BC3081B9300F0603551D130101FF040530030101FF301D0603551D0E041604141AEDFE413990B42459BE01F252D545F65A39DC1130640603551D23045D305B80141AEDFE413990B42459BE01F252D545F65A39DC11A138A4363034310B300906035504061302465231123010060355040A0C094468696D796F7469733111300F06035504030C084365727469676E61820900FEDCE3010FC948FF300E0603551D0F0101FF040403020106301106096086480186F8420101040403020007300D06092A864886F70D0101050500038201010085031E9271F642AFE1A3619EEBF3C00FF2A5D4DA95E6D6BE68363D7E6E1F4C8AEFD10F216D5EA55263CE12F8EF2ADA6FEB37FE1302C7CB3B3E226BDA612E7FD4723DDD30E11E4C40198C0FD79CD183307B9859DC7DC6B90C294CA133A2EB673A6584D396E2ED7645708FB52BDEF923D6496E3C14B5C69F351E50D0C18F6A70440262CBAE1D6841A7AA57E853AA07D206F6D514060B9103752C6C72B561959A0D8BB90DE7F5DF54CDDEE6D8D609089763E5C12EB0B74426C026C0AF55309E3BD5362A1904F45C1EFFCF2CB7FFD0FD874011D51123BB48C021A9A4282DFD15F8B04E2BF4305B21FC119134BE41EF7B9D9775FF9795C096582FEABB46D7BBE4D92E", "hex");

const X509_REQUEST_RAW = new Buffer("308202BC308201A402003078310B3009060355040613025553311430120603550403130B6D792D737974652E6E6574311430120603550407130B53756E20416E746F6E696F311D301B060355040A13144D7920686F6D65206F7267616E697A6174696F6E310F300D06035504081306546573786173310D300B060355040B13044E6F6E6530820122300D06092A864886F70D01010105000382010F003082010A028201010092323A4560FF7FB0C022B6A9B72FE2F29F544AB8AAA4CFD1A1A71D9D0EB7B89CE85505DE15AC11785EDC5FFE45BC6B39E0688B7680FE1AFA42E36C50070AB52F01C1E86B139D10C9A0729CECDBF3CDF6FF538B6C2AE80498D6EAD5C90AC46131FD542C9EF0F400FCDA341E6CB61BA3C612D17A6CACB6415FBCFBF912E16BDCC3689C8C95BBE0C118884FC8A0F9597CB734B4C84A451FCB511BE6C7FDE0F45FE5B386CD32C675249012C3E2A0F18AB8DC880A960831943747E8C92F1972DDF8C18C59E07D59E98609B62B94FF88172D928D3B14FB8D66B4A6DE8B6DAE3AB6552F5CC8BFD1CF97DFB252EB551DBE2AF33826B3E26190ED48646556068196369DBB0203010001A000300D06092A864886F70D01010B050003820101001EBF4FF997C237C6001D4170BB8FCF64E3B3137D7746F4E08A3F884A127F235665EBBBB497FF8691AED2E1268728FFFF902ED577C86BDA86A59DFED036FEEAF7DE7B766F5AF1F7A08A7432C3B6F99C7223D0B76067A8D789B168F28E8FDEBD8D5F7EFFFE1F38EAAA0DB5BB1F861E9463B1299CC00E5329D24D8D0F049E650FEC4D62143651EBEDFF10795F0B1BC325EAC01951E2344FFD8850BF6A3FC1304FD4C4136CF27FE443A69B39F92F07A7F48BC8AC2AF3C9F3FD8236424DB838806F884677CCD122DE815C400E726A24B8A9E4D50FF75EFBCC2F8DCED7E88C4E727B1BAD84E0FA0F65A91D1D7FF54AF7279A33043ECAF205CDFACD05511E7E0641A970", "hex");

const PRIVATE_KEY_RAW = new Buffer("308204BD020100300D06092A864886F70D0101010500048204A7308204A3020100028201010092323A4560FF7FB0C022B6A9B72FE2F29F544AB8AAA4CFD1A1A71D9D0EB7B89CE85505DE15AC11785EDC5FFE45BC6B39E0688B7680FE1AFA42E36C50070AB52F01C1E86B139D10C9A0729CECDBF3CDF6FF538B6C2AE80498D6EAD5C90AC46131FD542C9EF0F400FCDA341E6CB61BA3C612D17A6CACB6415FBCFBF912E16BDCC3689C8C95BBE0C118884FC8A0F9597CB734B4C84A451FCB511BE6C7FDE0F45FE5B386CD32C675249012C3E2A0F18AB8DC880A960831943747E8C92F1972DDF8C18C59E07D59E98609B62B94FF88172D928D3B14FB8D66B4A6DE8B6DAE3AB6552F5CC8BFD1CF97DFB252EB551DBE2AF33826B3E26190ED48646556068196369DBB0203010001028201001ADE8A6127F3AD7741C8DF838FBC885C893607C9AAEB419AC8B81B343B793EBFEFDF788599BC1735E551617F2D37F5091D1A79CF5CE3D6F77A05AC6984F1CDDD06D8A9ABCC5E08B0D6015AA019C8D468FA0253D49C8A2A162121E60ADE24BBAC615FF0178237865AF28BB3AFCD448534294F40CDEA6C50D594B946CCD68B6976658DDE8933C6DFDB227EA2706B8D6320E36C16BCF047B28E3D503F71D5BEAD9718DCBBDC17AE3870B4A2275F5A25168391F5F989126A86A50F85953769E49C3547DD99C7D749EC3B1CEA4025A62663BAB459E2531ADC2087AB96ED66956E2EB0B09E6D3E4C9CA78BE9D7A4F451B65D0A49A9E4AD63C4FFDDC7DEDE7D210A9CD102818100C1D20B651596664F4CCE73259D08759FB527F22D746B20DDD958D59782AE148464711F3D5BEDBCBADFADDC5FBB844604A410B6D486D51BEFE2A21229DBC91C2566A0A7DAE2DAF251AB405D0E8D9289738F922165A3A17D8C47D86706052ED3311327461FB0AFBC70CB26F4127119843D0E4C71A246C75CC4BE3945DF3DD1658902818100C118EDBB16CE384FFE888FC217C713C0CB0042EE3A16C6AD285C11DA7E7BF3E7AA2E6CB6B4D8A268CDF16780273E9BA2E5279961F55AF559E40C5C3AB2BB61BEB9B70F95A05B96D23959AC1DA5BC8FDD45DE075A09AAC9E8319AB64945D0885F42E981C1B9562F874C394CB48790996916D3D3A2657E478CDEC30312B3B4DC23028181009F0E5657900DAACC2D05C72CF8DF7657A7FCAE1B6B4C76DE587D345B6FDC97EDC5D7A7815D2D8E11F579E23D95CF08FEC9FD056D07715FC9CEBC9E1747CC949284D416ABE43B355C9C22E7BB07A757B14402F1F14D053BD8A1250FF6BACE20764777956E703AE773D0E398AC81B024FB4DFEA1CA40375F03FDEF564DCB9749B1028180524D2ABE6C28F72D7942816B6BB109454A00D186323214FA26D29F356E65AC7E98357356A85C1154F43A29302109F95203B3CE1747793E4BD2FC45AF2B10DCC76AE69078E8C140D65765560BC8E146BC3C143733F41CDC33E0389DEB3B1B77948AB375FFB8DBF82405A402828BA96109BE96088516172DADE8205C45F35C69DB02818073471C7A2C5B71DE76CFC9AE538512F8B22DB3B644E93EC353E5C2D1EE65C970E3FA248D345CF8CE47C45BD1B7D395AFE1897F73AE4E58C3601279C01B11C8E3F7DBA13E8A01EF27830E20145DEF2EF48BADABD8E2F8DA702FAB0D767DEABFC503EB756730F1561390D4470463DE31AACE6B11D25592C4FB825CF7E319B53DE3", "hex");

context("Certificate storage", () => {

    beforeEach((done) => {
        Promise.resolve()
        .then(() => {
            return crypto.certStorage.keys()
        })
        .then((keys) => {
            if (keys.length) {
                return Promise.resolve().then(() => {
                    return crypto.certStorage.clear()
                })
                .then(() => {
                    return crypto.certStorage.keys()
                })
                .then((keys) => {
                    assert.equal(keys.length, 0);
                })
            }
        })
        .then(done, done);
    })

    context("indexOf", () => {
        ["x509", "request"].forEach((type) => {
            it(type, (done) => {
                crypto.certStorage.importCert(type, type === "x509" ? X509_RAW : X509_REQUEST_RAW, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, ["verify"])
                    .then((cert) => {
                        return crypto.certStorage.setItem(cert)
                            .then((index) => {
                                return crypto.certStorage.indexOf(cert)
                                    .then((found) => {
                                        assert.equal(found, null);
                                    })
                                    .then(() => {
                                        return crypto.certStorage.getItem(index, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, ["verify"]);
                                    })
                                    .then((cert) => {
                                        assert.equal(!!cert, true, "Cannot get cert item from storage");
                                        return crypto.certStorage.indexOf(cert);
                                    })
                                    .then((found) => {
                                        assert.equal(index, found);
                                    })
                            })
                    })
                    .then(done, done);
            });
        });
    });

    context("importCert", () => {

        it("x509", (done) => {
            crypto.certStorage.importCert("x509", X509_RAW, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, ["verify"])
                .then((item) => {
                    const json = item.toJSON();
                    assert.equal(json.publicKey.algorithm.name, "RSASSA-PKCS1-v1_5");
                    assert.equal(json.publicKey.algorithm.hash.name, "SHA-256");
                    assert.equal(json.notBefore.toISOString(), "2007-06-29T15:13:05.000Z");
                    assert.equal(json.notAfter.toISOString(), "2027-06-29T15:13:05.000Z");
                    assert.equal(json.subjectName, "C=FR, O=Dhimyotis, CN=Certigna");
                    assert.equal(json.issuerName, "C=FR, O=Dhimyotis, CN=Certigna");
                    assert.equal(json.serialNumber, "00fedce3010fc948ff");
                    assert.equal(json.type, "x509");
                })
                .then(done, done);
        });

        it("request", (done) => {
            crypto.certStorage.importCert("request", X509_REQUEST_RAW, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" }, ["verify"])
                .then((item) => {
                    const json = item.toJSON();
                    assert.equal(json.publicKey.algorithm.name, "RSASSA-PKCS1-v1_5");
                    assert.equal(json.publicKey.algorithm.hash.name, "SHA-384");
                    assert.equal(json.subjectName, "C=US, CN=my-syte.net, L=Sun Antonio, O=My home organization, ST=Tesxas, OU=None");
                    assert.equal(json.type, "request");
                })
                .then(done, done);
        });

        it("wrong type throws error", (done) => {
            crypto.certStorage.importCert("wrong", X509_REQUEST_RAW, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" }, ["verify"])
                .then(() => {
                    return 0;
                })
                .catch(() => {
                    return 1;
                })
                .then((ok) => {
                    assert.equal(ok, 1, "Must be error");
                })
                .then(done, done);

        })

    });

    context("set/get item", (done) => {

        it("x509", (done) => {
            crypto.certStorage.importCert("x509", X509_RAW, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, ["verify"])
                .then((x509) => {
                    return crypto.certStorage.setItem(x509);
                })
                .then((index) => {
                    return crypto.certStorage.getItem(index);
                })
                .then((x509) => {
                    assert.equal(!!x509, true);
                })
                .then(done, done);
        });

        it("request", (done) => {
            crypto.certStorage.importCert("request", X509_REQUEST_RAW, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, ["verify"])
                .then((request) => {
                    return crypto.certStorage.setItem(request);
                })
                .then((index) => {
                    return crypto.certStorage.getItem(index, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, ["verify"]);
                })
                .then((request) => {
                    assert.equal(!!request, true);
                })
                .then(done, done);
        });

        it("null", (done) => {
            crypto.certStorage.getItem("not exist")
                .then((item) => {
                    assert.equal(item, null);
                })
                .then(done, done);
        })

        it("set wrong object", (done) => {
            crypto.certStorage.setItem({})
                .then(() => 0)
                .catch(() => 1)
                .then((ok) => {
                    assert.equal(ok, 1, "Must be error");
                })
                .then(done, done);
        })
    });

    it("removeItem", (done) => {
        crypto.certStorage.keys()
            .then((indexes) => {
                assert.equal(indexes.length, 0);
                return crypto.certStorage.importCert("request", X509_REQUEST_RAW, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, ["verify"])
                    .then((item) => {
                        return crypto.certStorage.setItem(item);
                    })
            })
            .then(() => {
                return crypto.certStorage.importCert("x509", X509_RAW, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, ["verify"])
                    .then((item) => {
                        return crypto.certStorage.setItem(item);
                    })
            })
            .then((index) => {
                return crypto.certStorage.keys()
                    .then((indexes) => {
                        assert.equal(indexes.length, 2);
                        return crypto.certStorage.removeItem(index)
                    })
            })
            .then(() => {
                return crypto.certStorage.keys();
            })
            .then((indexes) => {
                assert.equal(indexes.length, 1);
            })
            .then(done, done);
    });

    it("exportCert", (done) => {
        crypto.certStorage.importCert("x509", X509_RAW, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, ["verify"])
            .then((x509) => {
                return crypto.certStorage.exportCert("raw", x509);
            })
            .then((raw) => {
                assert.equal(new Buffer(raw).equals(X509_RAW), true);
            })
            .then(done, done);
    })

});