/// <reference path="./promise.ts" />

export interface IAlgorithmIdentifier{
	name: string;
	hash?: IAlgorithmIdentifier;
}

export type AlgorithmType = string | IAlgorithmIdentifier;

export interface IWebCrypto {
	subtle: ISubtleCrypto;
	getRandomValues(array: Buffer): Buffer
}

export interface ISubtleCrypto {
	generateKey(algorithm: AlgorithmType, extractable: boolean, keyUsages: string[]): Promise;
	sign(algorithm: AlgorithmType, key: ICryptoKey, data: Buffer): Promise;
	verify(algorithm: AlgorithmType, key: CryptoKey, signature: Buffer, data: Buffer): Promise;
	encrypt(algorithm: AlgorithmType, key: CryptoKey, data: Buffer): Promise;
	decrypt(algorithm: AlgorithmType, key: CryptoKey, data: Buffer): Promise;
	wrapKey(format: string, key: CryptoKey, wrappingKey: CryptoKey, algorithm: IAlgorithmIdentifier): Promise;
	unwrapKey(format: string, wrappedKey: Buffer, unwrappingKey: CryptoKey, unwrapAlgorithm: IAlgorithmIdentifier, unwrappedAlgorithm: IAlgorithmIdentifier, extractable: boolean, keyUsages: string[]): Promise;
}

export var KeyType = ["public", "private", "secret"];

export var KeyUsage = ["encrypt", "decrypt", "sign", "verify", "deriveKey", "deriveBits", "wrapKey", "unwrapKey"];

export interface ICryptoKey {
	type: string;
	extractable: boolean;
	algorithm: any;
	usages: string[];
}

export interface ICryptoKeyPair {
	publicKey: ICryptoKey;
	privateKey: ICryptoKey;
}