import {Session} from "graphene-pk11"
import * as iwc from "./iwebcrypto"
import * as key from "./key"

export interface IAlgorithmBase{
	generateKey(session: Session, alg: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], label?: string): iwc.ICryptoKey | iwc.ICryptoKeyPair;
	sign(session: Session, alg: iwc.IAlgorithmIdentifier, key: key.CryptoKey, data: Buffer);
	verify(session: Session, alg: iwc.IAlgorithmIdentifier, key: key.CryptoKey, signature: Buffer, data: Buffer): boolean;
}

export class AlgorithmBase{
	static generateKey(session: Session, alg: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], label?: string): iwc.ICryptoKey | iwc.ICryptoKeyPair {
		throw new Error("Method is not supported");
	}
	
	static sign(session: Session, alg: iwc.IAlgorithmIdentifier, key: iwc.ICryptoKey, data: Buffer) {
		throw new Error("Method is not supported");
	}
	
	static verify(session: Session, alg: iwc.IAlgorithmIdentifier, key: iwc.ICryptoKey, signature: Buffer, data: Buffer): boolean{
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