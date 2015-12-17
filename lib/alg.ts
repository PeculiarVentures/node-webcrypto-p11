import * as graphene from "graphene-pk11"
import * as iwc from "./iwebcrypto"
import * as key from "./key"

export interface IAlgorithmBase {
	generateKey(session: graphene.Session, alg: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], label?: string): iwc.ICryptoKey | iwc.ICryptoKeyPair;
	sign(session: graphene.Session, alg: iwc.IAlgorithmIdentifier, key: key.CryptoKey, data: Buffer);
	verify(session: graphene.Session, alg: iwc.IAlgorithmIdentifier, key: key.CryptoKey, signature: Buffer, data: Buffer): boolean;
	encrypt(session: graphene.Session, alg: iwc.IAlgorithmIdentifier, key: key.CryptoKey, data: Buffer): Buffer;
	decrypt(session: graphene.Session, alg: iwc.IAlgorithmIdentifier, key: key.CryptoKey, data: Buffer): Buffer;
	wrapKey(session: graphene.Session, key: key.CryptoKey, wrappingKey: key.CryptoKey, alg: iwc.IAlgorithmIdentifier): Buffer;
	unwrapKey(session: graphene.Session, wrappedKey: Buffer, unwrappingKey: key.CryptoKey, unwrapAlgorithm: iwc.IAlgorithmIdentifier, unwrappedAlgorithm: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[]): iwc.ICryptoKey;
}

export class AlgorithmBase {
	static ALGORITHM_NAME: string = "";

	static generateKey(session: graphene.Session, alg: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[], label?: string): iwc.ICryptoKey | iwc.ICryptoKeyPair {
		throw new Error("Method is not supported");
	}

	static sign(session: graphene.Session, alg: iwc.IAlgorithmIdentifier, key: iwc.ICryptoKey, data: Buffer) {
		throw new Error("Method is not supported");
	}

	static verify(session: graphene.Session, alg: iwc.IAlgorithmIdentifier, key: iwc.ICryptoKey, signature: Buffer, data: Buffer): boolean {
		throw new Error("Method is not supported");
	}

	static encrypt(session: graphene.Session, alg: iwc.IAlgorithmIdentifier, key: key.CryptoKey, data: Buffer): Buffer {
		throw new Error("Method is not supported");
	}

	static decrypt(session: graphene.Session, alg: iwc.IAlgorithmIdentifier, key: key.CryptoKey, data: Buffer): Buffer {
		throw new Error("Method is not supported");
	}

	static wrapKey(session: graphene.Session, key: key.CryptoKey, wrappingKey: key.CryptoKey, alg: iwc.IAlgorithmIdentifier): Buffer {
		throw new Error("Method is not supported");
	}

	static unwrapKey(session: graphene.Session, wrappedKey: Buffer, unwrappingKey: key.CryptoKey, unwrapAlgorithm: iwc.IAlgorithmIdentifier, unwrappedAlgorithm: iwc.IAlgorithmIdentifier, extractable: boolean, keyUsages: string[]): iwc.ICryptoKey {
		throw new Error("Method is not supported");
	}

	static checkAlgorithmIdentifier(alg) {
		if (typeof alg !== "object")
			throw TypeError("AlgorithmIdentifier: Algorithm must be an Object");
		if (!(alg.name && typeof (alg.name) == "string"))
			throw TypeError("AlgorithmIdentifier: Missing required property name");
		if (alg.name.toLowerCase() !== this.ALGORITHM_NAME.toLowerCase())
			throw new Error("AlgorithmIdentifier: Wrong algorithm name. Must be " + this.ALGORITHM_NAME);
	}

	static checkAlgorithmHashedParams(alg) {
		if (!alg.hash)
			throw new TypeError("AlgorithmHashedParams: Missing required property hash");
		if (typeof alg.hash !== "object")
			throw TypeError("AlgorithmIdentifier: Algorithm must be an Object");
		if (!(alg.hash.name && typeof (alg.hash.name) == "string"))
			throw TypeError("AlgorithmIdentifier: Missing required property name");
	}

	static checkKey(key: iwc.ICryptoKey, type: string) {
		if (!key)
			throw new TypeError("CryptoKey: Key can not be null");
		if (key.type !== type)
			throw new TypeError(`CryptoKey: Wrong key type in use. Must be '${type}'`);
	}

	static checkPrivateKey(key: iwc.ICryptoKey) {
		this.checkKey(key, "private");
	}

	static checkPublicKey(key: iwc.ICryptoKey) {
		this.checkKey(key, "public");
	}

	static checkSecretKey(key: iwc.ICryptoKey) {
		this.checkKey(key, "secret");
	}
} 