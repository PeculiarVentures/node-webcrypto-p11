import * as graphene from "graphene-pk11";
import { BufferSource } from "pvtsutils";

export type ITemplate = graphene.ITemplate;

export interface Pkcs11Attributes {
  id?: BufferSource
  token?: boolean;
  sensitive?: boolean;
  label?: string;
  extractable?: boolean;
  usages?: KeyUsage[];
}

export type TemplateBuildType = "private" | "public" | "secret" | "x509" | "request";

export type TemplateBuildAction = "generate" | "import" | "copy";

export interface ITemplateBuildParameters {
  type: TemplateBuildType;
  action: TemplateBuildAction;
  attributes: Pkcs11Attributes;
}

/**
 * Interface of PKCS#11 template builder
 */
export interface ITemplateBuilder {
  /**
   * Returns a PKCS#11 template
   * @param params Template build parameters
   */
  build(params: ITemplateBuildParameters): ITemplate
}

export interface ISessionContainer {
  readonly session: graphene.Session;
  templateBuilder: ITemplateBuilder
}

export interface IContainer {
  readonly container: ISessionContainer;
}
