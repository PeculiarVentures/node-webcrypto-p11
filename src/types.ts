import * as graphene from "graphene-pk11";
import * as pvtsutils from "pvtsutils";

export type ITemplate = graphene.ITemplate;

export interface Pkcs11Attributes {
  id?: pvtsutils.BufferSource
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

export interface CryptoParams {
  /**
   * Path to library
   */
  library: string;
  /**
   * Name of PKCS11 module
   */
  name?: string;
  /**
   * Index of slot
   */
  slot?: number;
  readWrite?: boolean;
  /**
   * PIN of slot
   */
  pin?: string;
  /**
   * list of vendor json files
   */
  vendors?: string[];
  /**
   * NSS library parameters
   */
  libraryParameters?: string;
}

export interface ProviderInfo {
  id: string;
  name: string;
  reader: string;
  slot: number;
  serialNumber: string;
  algorithms: string[];
  isRemovable: boolean;
  isHardware: boolean;
}

export interface Pkcs11Params {
  token?: boolean;
  sensitive?: boolean;
  label?: string;
}
export interface Pkcs11KeyGenParams extends Algorithm, Pkcs11Params { }

export interface Pkcs11AesKeyGenParams extends AesKeyGenParams, Pkcs11KeyGenParams { }

export interface Pkcs11HmacKeyGenParams extends HmacKeyGenParams, Pkcs11KeyGenParams { }

export interface Pkcs11EcKeyGenParams extends EcKeyGenParams, Pkcs11KeyGenParams { }

export interface Pkcs11RsaHashedKeyGenParams extends RsaHashedKeyGenParams, Pkcs11KeyGenParams { }

export interface Pkcs11KeyImportParams extends Algorithm, Pkcs11Params { }

export interface Pkcs11EcKeyImportParams extends EcKeyImportParams, Pkcs11KeyImportParams { }

export interface Pkcs11RsaHashedImportParams extends RsaHashedImportParams, Pkcs11KeyImportParams { }

export interface Pkcs11HmacKeyImportParams extends HmacImportParams, Pkcs11KeyImportParams { }

export interface Pkcs11AesKeyImportParams extends Algorithm, Pkcs11KeyImportParams { }

export interface Pkcs11KeyAlgorithm extends KeyAlgorithm {
  token: boolean;
  sensitive?: boolean;
  label: string;
}

export interface Pkcs11RsaHashedKeyAlgorithm extends RsaHashedKeyAlgorithm, Pkcs11KeyAlgorithm { }

export interface Pkcs11EcKeyAlgorithm extends EcKeyAlgorithm, Pkcs11KeyAlgorithm { }

export interface Pkcs11AesKeyAlgorithm extends AesKeyAlgorithm, Pkcs11KeyAlgorithm { }

export interface Pkcs11HmacKeyAlgorithm extends HmacKeyAlgorithm, Pkcs11KeyAlgorithm { }
