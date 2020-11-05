import * as graphene from "graphene-pk11";
import { BufferSource } from "pvtsutils";

export type KeyTemplate = graphene.ITemplate;

export interface Pkcs11Attributes {
  id?: BufferSource
  token?: boolean;
  sensitive?: boolean;
  label?: string;
  extractable?: boolean;
  usages?: KeyUsage[];
}

export type TemplateBuilderType = "private" | "public" | "secret" | "x509" | "request";

/**
 * Interface of PKCS#11 template builder
 */
export interface ITemplateBuilder {
  /**
   * Returns a PKCS#11 template
   * @param type Type of key (private, public, secret)
   * @param attributes PKCS#11 attributes
   */
  build(type: TemplateBuilderType, attributes: Pkcs11Attributes): KeyTemplate
}

export interface ISessionContainer {
  readonly session: graphene.Session;
  templateBuilder: ITemplateBuilder
}

export interface IContainer {
  readonly container: ISessionContainer;
}
