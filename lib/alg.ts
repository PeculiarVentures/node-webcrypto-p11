import {Session} from "graphene-pk11"
import * as iwc from "./iwebcrypto"

export interface IAlgorithmBase{
	generateKey(session: Session, alg: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], label?: string): iwc.ICryptoKey | iwc.ICryptoKeyPair;
}

export class AlgorithmBase{
	static generateKey(session: Session, alg: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], label?: string): iwc.ICryptoKey | iwc.ICryptoKeyPair {
		throw new Error("Method is not supported");
	}

	static checkAlgorithmIdentifier(alg) {
		if (typeof alg !== "object")
			throw TypeError("AlgorithmIdentifier: Algorithm must be an Object");
		if (!(alg.name && typeof (alg.name) == "string"))
			throw TypeError("AlgorithmIdentifier: Missing required property name");
	}
	static checkAlgorithmHashedParams(alg) {
		if (!alg.hash)
			throw new TypeError("AlgorithmHashedParams: Missing required property hash");
		this.checkAlgorithmIdentifier(alg.hash);
	}
} 