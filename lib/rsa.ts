import {Session} from "graphene-pk11"
import {AlgorithmBase} from "./alg"
import * as iwc from "./iwebcrypto"
import {CryptoKey} from "./key"

let ALG_NAME_RSA_PKCS1 = "RSASSA-PKCS1-v1_5";
let ALG_NAME_RSA_PSS = "RSA-PSS";
let ALG_NAME_RSA_OAEP = "RSA-OAEP";

let HASH_ALGS = ["SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"];

export class Rsa extends AlgorithmBase {
	static ALGORITHM_NAME: string = ""
	static generateKey(session: Session, alg: any, extractable: boolean, keyUsages: string[], label?: string): iwc.ICryptoKeyPair {
		var size = alg.modulusLength;
		var exp = new Buffer(alg.publicExponent);
		var _key = session.generate("RSA", null, {
			"label": label,
			"token": true,
			"extractable": extractable,
			"keyUsages": keyUsages,
			"modulusLength": size,
			"publicExponent": exp
		});

		return {
			privateKey: new RsaKey(_key.privateKey, alg),
			publicKey: new RsaKey(_key.publicKey, alg)
		};
	}

	static checkRsaGenParams(alg: IRsaKeyGenParams) {
		if (alg.name.toLowerCase() !== this.ALGORITHM_NAME.toLowerCase())
			throw new Error("RsaKeyGenParams: Wrong algrotiyhm name. Must be RSASSA_PKCS1_v1_5");
		if (!alg.modulusLength)
			throw new TypeError("RsaKeyGenParams: modulusLength: Missing required property");
		if (alg.modulusLength < 256 || alg.modulusLength > 16384)
			throw new TypeError("RsaKeyGenParams: The modulus length must be a multiple of 8 bits and >= 256 and <= 16384");
		if (!(alg.publicExponent && alg.publicExponent instanceof Uint8Array))
			throw new TypeError("RsaKeyGenParams: publicExponent: Missing or not a Uint8Array");
	}

	static checkAlgorithmHashedParams(alg: IRsaKeyGenParams) {
		super.checkAlgorithmHashedParams(alg);
		var _alg = alg.hash;
		_alg.name = _alg.name.toUpperCase();
		if (HASH_ALGS.indexOf(_alg.name) == -1)
			throw new Error("AlgorithmHashedParams: Unknow hash algorithm in use");
	}
}

export interface IRsaKeyGenParams extends iwc.IAlgorithmIdentifier {
	modulusLength: number;
	publicExponent: Uint8Array;
}

export class RsaKey extends CryptoKey {
	modulusLength: number;
	publicExponent: Uint8Array;

	constructor(key, alg: IRsaKeyGenParams) {
		super(key, alg);
		this.modulusLength = alg.modulusLength;
		this.publicExponent = alg.publicExponent;
		//TODO: get params from key if alg params is empty
	}
}

export class RsaPKCS1 extends Rsa {
	static ALGORITHM_NAME: string = ALG_NAME_RSA_PKCS1;

	static generateKey(session: Session, alg: IRsaKeyGenParams, extractable: boolean, keyUsages: string[], label?: string): iwc.ICryptoKeyPair {
		this.checkAlgorithmIdentifier(alg);
		this.checkRsaGenParams(alg);
		this.checkAlgorithmHashedParams(alg);

		var keyPair: iwc.ICryptoKeyPair = super.generateKey.apply(this, arguments);
		return keyPair;
	}

}

export class RsaPSS extends Rsa {
	static ALGORITHM_NAME: string = ALG_NAME_RSA_PSS;

	static generateKey(session: Session, alg: IRsaKeyGenParams, extractable: boolean, keyUsages: string[], label?: string): iwc.ICryptoKeyPair {
		throw new Error("not realized in this implementation");
	}
}

export class RsaOAEP extends Rsa {
	static ALGORITHM_NAME: string = ALG_NAME_RSA_OAEP;

	static generateKey(session: Session, alg: IRsaKeyGenParams, extractable: boolean, keyUsages: string[], label?: string): iwc.ICryptoKeyPair {
		this.checkAlgorithmIdentifier(alg);
		this.checkRsaGenParams(alg);
		this.checkAlgorithmHashedParams(alg);

		var keyPair: iwc.ICryptoKeyPair = super.generateKey.apply(arguments);
		return keyPair;
	}
}