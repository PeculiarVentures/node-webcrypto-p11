import * as graphene from "graphene-pk11";
import { BufferSourceConverter } from "pvtsutils";
import * as types from "./types";

export class TemplateBuilder implements types.ITemplateBuilder {

  public build(type: string, attributes: types.Pkcs11Attributes): types.KeyTemplate {
    const template: types.KeyTemplate = {
      token: !!attributes.token,
    };

    if (attributes.label) {
      template.label = attributes.label
    }
    if (attributes.id) {
      template.id = Buffer.from(BufferSourceConverter.toArrayBuffer(attributes.id));
    }

    const sign = attributes.usages?.includes("sign");
    const verify = attributes.usages?.includes("verify");
    const wrap = attributes.usages?.includes("wrapKey");
    const unwrap = attributes.usages?.includes("unwrapKey");
    const encrypt = unwrap || attributes.usages?.includes("encrypt");
    const decrypt = wrap || attributes.usages?.includes("decrypt");
    const derive = attributes.usages?.includes("deriveBits") || attributes.usages?.includes("deriveKey");

    switch (type) {
      case "private":
        Object.assign<types.KeyTemplate, types.KeyTemplate>(template, {
          class: graphene.ObjectClass.PRIVATE_KEY,
          sensitive: !!attributes.sensitive,
          private: true,
          extractable: !!attributes.extractable,
          derive,
          sign,
          decrypt,
          unwrap,
        });
        break;
      case "public":
        Object.assign<types.KeyTemplate, types.KeyTemplate>(template, {
          token: !!attributes.token,
          class: graphene.ObjectClass.PUBLIC_KEY,
          private: false,
          derive,
          verify,
          encrypt,
          wrap,
        });
        break;
      case "secret":
        Object.assign<types.KeyTemplate, types.KeyTemplate>(template, {
          class: graphene.ObjectClass.SECRET_KEY,
          sensitive: !!attributes.sensitive,
          extractable: !!attributes.extractable,
          derive,
          sign,
          verify,
          decrypt,
          encrypt,
          unwrap,
          wrap,
        });
        break;
    }

    return template;
  }

}
