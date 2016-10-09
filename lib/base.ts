// Core
import * as webcrypto from "webcrypto-core";
const WebCryptoError = webcrypto.WebCryptoError;
import { Session } from "graphene-pk11";

export class BaseCrypto extends webcrypto.BaseCrypto {

    static checkSession(session: Session) {
        if (!session)
            throw new WebCryptoError("Parameter 'session' is required");
    }

    static generateKey(algorithm: Algorithm, extractable: boolean, keyUsages: string[], session?: Session): PromiseLike<CryptoKey | CryptoKeyPair> {
        return new Promise((resolve, reject) => {
            this.checkSession(session!);
            resolve(undefined);
        });
    }
    static digest(algorithm: Algorithm, data: Buffer, session?: Session): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            this.checkSession(session!);
            resolve(undefined);
        });
    }
    static sign(algorithm: Algorithm, key: CryptoKey, data: Buffer, session?: Session): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            this.checkSession(session!);
            resolve(undefined);
        });
    }
    static verify(algorithm: Algorithm, key: CryptoKey, signature: Buffer, data: Buffer, session?: Session): PromiseLike<boolean> {
        return new Promise((resolve, reject) => {
            this.checkSession(session!);
            resolve(undefined);
        });
    }
    static encrypt(algorithm: Algorithm, key: CryptoKey, data: Buffer, session?: Session): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            this.checkSession(session!);
            resolve(undefined);
        });
    }
    static decrypt(algorithm: Algorithm, key: CryptoKey, data: Buffer, session?: Session): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            this.checkSession(session!);
            resolve(undefined);
        });
    }
    static deriveBits(algorithm: Algorithm, baseKey: CryptoKey, length: number, session?: Session): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            this.checkSession(session!);
            resolve(undefined);
        });
    }
    static deriveKey(algorithm: Algorithm, baseKey: CryptoKey, derivedKeyType: Algorithm, extractable: boolean, keyUsages: string[], session?: Session): PromiseLike<CryptoKey> {
        return new Promise((resolve, reject) => {
            this.checkSession(session!);
            resolve(undefined);
        });
    }
    static exportKey(format: string, key: CryptoKey, session?: Session): PromiseLike<JsonWebKey | ArrayBuffer> {
        return new Promise((resolve, reject) => {
            this.checkSession(session!);
            resolve(undefined);
        });
    }
    static importKey(format: string, keyData: JsonWebKey | BufferSource, algorithm: Algorithm, extractable: boolean, keyUsages: string[], session?: Session): PromiseLike<CryptoKey> {
        return new Promise((resolve, reject) => {
            this.checkSession(session!);
            resolve(undefined);
        });
    }
    static wrapKey(format: string, key: CryptoKey, wrappingKey: CryptoKey, wrapAlgorithm: Algorithm, session?: Session): PromiseLike<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            this.checkSession(session!);
            resolve(undefined);
        });
    }
    static unwrapKey(format: string, wrappedKey: Uint8Array, unwrappingKey: CryptoKey, unwrapAlgorithm: Algorithm, unwrappedKeyAlgorithm: Algorithm, extractable: boolean, keyUsages: string[], session?: Session): PromiseLike<CryptoKey> {
        return new Promise((resolve, reject) => {
            this.checkSession(session!);
            resolve(undefined);
        });
    }
} 