import { Module, Session, Slot, Token } from "graphene-pk11";

export class P11Session {

  public value: Session;
  public slot: Slot;
  public token: Token;
  public module: Module;

}
