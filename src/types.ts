import * as graphene from "graphene-pk11";
import { BufferSource } from "pvtsutils";

export type KeyTemplate = graphene.ITemplate;

export interface KeyPairTemplate {
  private: KeyTemplate;
  public: KeyTemplate;
}

export interface Pkcs11Attributes {
  id?: BufferSource
  token?: boolean;
  sensitive?: boolean;
  label?: string;
  extractable?: boolean;
  usages?: KeyUsage[];
}

/**
 * Interface of PKCS#11 template builder
 */
export interface ITemplateBuilder {
  /**
   * Returns a PKCS#11 template
   * @param type Type of key (private, public, secret)
   * @param attributes PKCS#11 attributes
   */
  build(type: KeyType, attributes: Pkcs11Attributes): KeyTemplate
}

export interface ISessionContainer {
  readonly session: graphene.Session;
  readonly templateBuilder: ITemplateBuilder
}

export interface IContainer {
  readonly container: ISessionContainer;
}
