import {Storage} from "graphene-pk11";

export class Pkcs11Object {

    public p11Object: Storage;

    constructor(object?: Storage) {
        this.p11Object = object;
    }

}
