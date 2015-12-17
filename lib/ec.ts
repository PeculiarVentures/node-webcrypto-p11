import * as graphene from "graphene-pk11"
var ECDSA = graphene.ECDSA;
var Enums = graphene.Enums;

import * as alg from "./alg"
import * as iwc from "./iwebcrypto"
import {CryptoKey} from "./key"

let ALG_NAME_ECDH = "ECDH";
let ALG_NAME_ECDSA = "ECDSA";

let HASH_ALGS = ["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"];

export class Ec extends alg.AlgorithmBase {
	static generateKey(session: graphene.Session, alg: IEcKeyGenParams, extractable: boolean, keyUsages: string[], label?: string): iwc.ICryptoKeyPair {
		this.checkAlgorithmIdentifier(alg);
		this.checkKeyGenParams(alg);

		var _namedCurve = "";
		switch (alg.namedCurve) {
			case "P-192":
				_namedCurve = "secp192r1"
				break;
			case "P-256":
				_namedCurve = "secp256r1"
				break;
			case "P-384":
				_namedCurve = "secp384r1"
				break;
			case "P-521":
				_namedCurve = "secp521r1"
				break;
			default:
				throw new Error("Unsupported namedCurve in use");
		}

		var _key = ECDSA.Ecdsa.generate(session, null, {
			"label": label,
			"namedCurve": _namedCurve,
			"token": true,
			"extractable": extractable,
			"keyUsages": keyUsages,
		});

		return {
			"privateKey": new EcKey(_key.privateKey, alg),
			"publicKey": new EcKey(_key.publicKey, alg)
		};
	}

	static checkKeyGenParams(alg: IEcKeyGenParams) {
		if (!alg.namedCurve)
			throw new TypeError("EcKeyGenParams: namedCurve: Missing required property");
		switch (alg.namedCurve.toUpperCase()) {
			case "P-192":
			case "P-256":
			case "P-384":
			case "P-521":
				break;
			default:
				throw new TypeError("EcKeyGenParams: namedCurve: Wrong value. Can be P-256, P-384, or P-521");
		}
		alg.namedCurve = alg.namedCurve.toUpperCase();
	}

	static checkAlgorithmHashedParams(alg: iwc.IAlgorithmIdentifier) {
		super.checkAlgorithmHashedParams(alg);
		var _alg = alg.hash;
		_alg.name = _alg.name.toUpperCase();
		if (HASH_ALGS.indexOf(_alg.name) == -1)
			throw new Error("AlgorithmHashedParams: Unknow hash algorithm in use");
	}

	static checkAlgorithmParams(alg: IEcAlgorithmParams) {
		this.checkAlgorithmIdentifier(alg);
	}

	static wc2pk11(alg: IEcAlgorithmParams) {
		throw new Error("Not realized");
	}
}

export interface IEcKeyGenParams extends iwc.IAlgorithmIdentifier {
	namedCurve: string;
}

export interface IEcAlgorithmParams extends iwc.IAlgorithmIdentifier {
}

export interface IEcdsaAlgorithmParams extends IEcAlgorithmParams {
	hash: {
		name: string;
	};
}

export class EcKey extends CryptoKey {
	namedCurve: string;

	constructor(key, alg: IEcKeyGenParams) {
		super(key, alg);
		this.namedCurve = alg.namedCurve;
		//TODO: get params from key if alg params is empty
	}
}

export class Ecdsa extends Ec {
	static ALGORITHM_NAME: string = ALG_NAME_ECDSA;

	static wc2pk11(alg: IEcdsaAlgorithmParams) {
		var _alg = null;
		switch (alg.hash.name.toUpperCase()) {
			case "SHA-1":
				_alg = "ECDSA_SHA1";
				break;
			case "SHA-224":
				_alg = "ECDSA_SHA224";
				break;
			case "SHA-256":
				_alg = "ECDSA_SHA256";
				break;
			case "SHA-384":
				_alg = "ECDSA_SHA384";
				break;
			case "SHA-512":
				_alg = "ECDSA_SHA512";
				break;
			default:
				throw new TypeError("Unknown Hash agorithm name in use");
		}
		return _alg;
	}

	static sign(session: graphene.Session, alg: IEcdsaAlgorithmParams, key: CryptoKey, data: Buffer) {
		this.checkAlgorithmIdentifier(alg);
		this.checkAlgorithmHashedParams(alg);
		this.checkPrivateKey(key);
		var _alg = this.wc2pk11(alg);

		var signer = session.createSign(_alg, key.key);
		signer.update(data);
		var signature = signer.final();

		return signature;
	}

	static verify(session: graphene.Session, alg: IEcdsaAlgorithmParams, key: CryptoKey, signature: Buffer, data: Buffer): boolean {
		this.checkAlgorithmIdentifier(alg);
		this.checkAlgorithmHashedParams(alg);
		this.checkPublicKey(key);
		var _alg = this.wc2pk11(alg);

		var signer = session.createVerify(_alg, key.key);
		signer.update(data);
		var res = signer.final(signature);

		return res;
	}
}

export class Ecdh extends Ec {
	static ALGORITHM_NAME: string = ALG_NAME_ECDH;
}