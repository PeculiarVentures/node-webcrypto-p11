/// <reference path="./promise.ts" />

export interface IAlgorithmIdentifier{
	name: string;
}

export type AlgorithmType = string | IAlgorithmIdentifier;

export interface IWebCrypto {
	subtle: ISubtleCrypto;
	getRandomValues(array: Buffer): Buffer
}

export interface ISubtleCrypto {
	generateKey(algorithm: AlgorithmType, extractable: boolean, keyUsages: string[]): Promise;
	sign(algorithm: AlgorithmType, key: ICryptoKey, data: Buffer): Promise;
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