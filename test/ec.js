var assert = require('assert');
var config = require('./config');
var crypto = require("../built/webcrypto.js");
var WebCrypto = crypto.WebCrypto;
webcrypto = new WebCrypto(config);

var session = webcrypto.session;

session.generateKey(graphene.KeyGenMechanism.AES, {
            keyType: graphene.KeyType.AES,
            valueLen: size / 8,
            encrypt: true,
            decrypt: true,
            sign: true,
            verify: true,
            wrap: true,
            unwrap: true,
            token: false
        });
        
session.