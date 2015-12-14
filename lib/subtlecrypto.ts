/// <reference path="./promise.ts" />

import {Session} from "graphene-pk11"
import {CryptoKey} from "./key"

import * as alg from "./alg"
import * as rsa from "./rsa"

import * as iwc from "./iwebcrypto"

export class P11SubtleCrypto implements iwc.ISubtleCrypto {
	protected session: Session;

	constructor(session: Session) {
		this.session = session;
	}

	generateKey(algorithm: iwc.AlgorithmType, extractable: boolean, keyUsages: string[]): Promise {
		var that = this;
		return new Promise(function(resolve, reject) {
			//convert string to IAlgorithmIdentifier
			var _alg: iwc.IAlgorithmIdentifier = { name: "" };
			if (algorithm instanceof String) {
				_alg = { name: algorithm };
			}
			else {
				_alg = <iwc.IAlgorithmIdentifier>algorithm;
			}
			var algClass: alg.IAlgorithmBase = null;
			switch (_alg.name.toLowerCase()) {
				case rsa.RsaPKCS1.ALGORITHM_NAME.toLowerCase():
					algClass = rsa.RsaPKCS1
					break;
				case rsa.RsaPSS.ALGORITHM_NAME.toLowerCase():
					algClass = rsa.RsaOAEP
					break;
				case rsa.RsaOAEP.ALGORITHM_NAME.toLowerCase():
					algClass = rsa.RsaOAEP
					break;
				default:
					throw new TypeError("");
			}
			var key = algClass.generateKey(that.session, _alg, extractable, keyUsages);
			resolve(key);
		})
	}

	sign(algorithm: iwc.AlgorithmType, key: CryptoKey, data: Buffer): Promise {
		return new Promise(function(resolve, reject) {
			//TODO: check algorithm
			var signature: Buffer = key.key.sign(data);
			resolve(signature);
		})
	}

}