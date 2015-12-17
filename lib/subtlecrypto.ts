/// <reference path="./promise.ts" />

import * as graphene from "graphene-pk11"
import {CryptoKey} from "./key"

import * as alg from "./alg"
import * as rsa from "./rsa"
import * as aes from "./aes"
import * as ec from "./ec"

import * as iwc from "./iwebcrypto"

function prepare_algorithm(alg: iwc.AlgorithmType): iwc.IAlgorithmIdentifier {
	var _alg: iwc.IAlgorithmIdentifier = { name: "" };
	if (alg instanceof String) {
		_alg = { name: alg };
	}
	else {
		_alg = <iwc.IAlgorithmIdentifier>alg;
	}
	return _alg
}

export class P11SubtleCrypto implements iwc.ISubtleCrypto {
	protected session: graphene.Session;

	constructor(session: graphene.Session) {
		this.session = session;
	}

	generateKey(algorithm: iwc.AlgorithmType, extractable: boolean, keyUsages: string[]): Promise {
		var that = this;
		return new Promise(function(resolve, reject) {
			var _alg = prepare_algorithm(algorithm);

			var algClass: alg.IAlgorithmBase = null;
			switch (_alg.name.toLowerCase()) {
				case rsa.RsaPKCS1.ALGORITHM_NAME.toLowerCase():
					algClass = rsa.RsaPKCS1;
					break;
				case rsa.RsaPSS.ALGORITHM_NAME.toLowerCase():
					algClass = rsa.RsaPSS;
					break;
				case rsa.RsaOAEP.ALGORITHM_NAME.toLowerCase():
					algClass = rsa.RsaOAEP;
					break;
				case aes.AesGCM.ALGORITHM_NAME.toLowerCase():
					algClass = aes.AesGCM;
					break;
				case ec.Ecdsa.ALGORITHM_NAME.toLowerCase():
					algClass = ec.Ecdsa;
					break;
				case ec.Ecdh.ALGORITHM_NAME.toLowerCase():
					algClass = ec.Ecdh;
					break;
				default:
					throw new TypeError("Unsupported algorithm in use");
			}
			var key = algClass.generateKey(that.session, _alg, extractable, keyUsages);
			resolve(key);
		})
	}

	sign(algorithm: iwc.AlgorithmType, key: CryptoKey, data: Buffer): Promise {
		var that = this;
		return new Promise(function(resolve, reject) {
			var _alg = prepare_algorithm(algorithm);

			var algClass: alg.IAlgorithmBase = null;
			switch (_alg.name.toLowerCase()) {
				case rsa.RsaPKCS1.ALGORITHM_NAME.toLowerCase():
					algClass = rsa.RsaPKCS1
					break;
				case rsa.RsaPSS.ALGORITHM_NAME.toLowerCase():
					algClass = rsa.RsaPSS
					break;
				case ec.Ecdsa.ALGORITHM_NAME.toLowerCase():
					algClass = ec.Ecdsa
					break;
				default:
					throw new TypeError("Unsupported algorithm in use");
			}
			var signature = algClass.sign(that.session, _alg, key, data);
			resolve(signature);
		})
	}

	verify(algorithm: iwc.AlgorithmType, key: CryptoKey, signature: Buffer, data: Buffer): Promise {
		var that = this;
		return new Promise(function(resolve, reject) {
			var _alg = prepare_algorithm(algorithm);

			var algClass: alg.IAlgorithmBase = null;
			switch (_alg.name.toLowerCase()) {
				case rsa.RsaPKCS1.ALGORITHM_NAME.toLowerCase():
					algClass = rsa.RsaPKCS1
					break;
				case rsa.RsaPSS.ALGORITHM_NAME.toLowerCase():
					algClass = rsa.RsaPSS
					break;
				case ec.Ecdsa.ALGORITHM_NAME.toLowerCase():
					algClass = ec.Ecdsa
					break;
				default:
					throw new TypeError("Unsupported algorithm in use");
			}
			var valid = algClass.verify(that.session, _alg, key, signature, data);
			resolve(valid);
		})
	}

	encrypt(algorithm: iwc.AlgorithmType, key: CryptoKey, data: Buffer): Promise {
		var that = this;
		return new Promise(function(resolve, reject) {
			var _alg = prepare_algorithm(algorithm);

			var algClass: alg.IAlgorithmBase = null;
			switch (_alg.name.toLowerCase()) {
				case rsa.RsaOAEP.ALGORITHM_NAME.toLowerCase():
					algClass = rsa.RsaOAEP
					break;
				case aes.AesGCM.ALGORITHM_NAME.toLowerCase():
					algClass = aes.AesGCM
					break;
				default:
					throw new TypeError("Unsupported algorithm in use");
			}
			var msg = algClass.encrypt(that.session, _alg, key, data);
			resolve(msg);
		})
	}

	decrypt(algorithm: iwc.AlgorithmType, key: CryptoKey, data: Buffer): Promise {
		var that = this;
		return new Promise(function(resolve, reject) {
			var _alg = prepare_algorithm(algorithm);

			var algClass: alg.IAlgorithmBase = null;
			switch (_alg.name.toLowerCase()) {
				case rsa.RsaOAEP.ALGORITHM_NAME.toLowerCase():
					algClass = rsa.RsaOAEP
					break;
				case aes.AesGCM.ALGORITHM_NAME.toLowerCase():
					algClass = aes.AesGCM
					break;
				default:
					throw new TypeError("Unsupported algorithm in use");
			}
			var msg = algClass.decrypt(that.session, _alg, key, data);
			resolve(msg);
		})
	}

	wrapKey(format: string, key: CryptoKey, wrappingKey: CryptoKey, algorithm: iwc.IAlgorithmIdentifier): Promise {
		var that = this;
		return new Promise(function(resolve, reject) {
			var _alg = prepare_algorithm(algorithm);

			var algClass: alg.IAlgorithmBase = null;
			switch (_alg.name.toLowerCase()) {
				case rsa.RsaOAEP.ALGORITHM_NAME.toLowerCase():
					algClass = rsa.RsaOAEP
					break;
				case aes.AesGCM.ALGORITHM_NAME.toLowerCase():
					algClass = aes.AesGCM
					break;
				default:
					throw new TypeError("Unsupported algorithm in use");
			}
			var wrappedKey = algClass.wrapKey(that.session, key, wrappingKey, _alg);
			resolve(wrappedKey);
		})
	}

	unwrapKey(format: string, wrappedKey: Buffer, unwrappingKey: CryptoKey, unwrapAlgorithm: iwc.IAlgorithmIdentifier, unwrappedAlgorithm: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[]): Promise {
		var that = this;
		return new Promise(function(resolve, reject) {
			var _alg1 = prepare_algorithm(unwrapAlgorithm);
			var _alg2 = prepare_algorithm(unwrappedAlgorithm);

			var algClass: alg.IAlgorithmBase = null;
			switch (_alg1.name.toLowerCase()) {
				case rsa.RsaOAEP.ALGORITHM_NAME.toLowerCase():
					algClass = rsa.RsaOAEP
					break;
				case aes.AesGCM.ALGORITHM_NAME.toLowerCase():
					algClass = aes.AesGCM
					break;
				default:
					throw new TypeError("Unsupported algorithm in use");
			}
			var unwrappedKey = algClass.unwrapKey(that.session, wrappedKey, unwrappingKey, _alg1, _alg2, extractable, keyUsages);
			resolve(unwrappedKey);
		})
	}

}