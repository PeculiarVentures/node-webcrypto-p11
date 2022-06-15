import * as x509 from "@peculiar/x509";
import * as assert from "assert";
import { ITemplate } from "graphene-pk11";
import { TemplateBuilder, ITemplateBuilder, ITemplateBuildParameters } from "../src";
import { crypto } from "./config";

const certPEM = "-----BEGIN CERTIFICATE-----\nMIIDLjCCAhagAwIBAgIBATANBgkqhkiG9w0BAQsFADA6MRkwFwYDVQQDExBUZXN0\nIGNlcnRpZmljYXRlMR0wGwYJKoZIhvcNAQkBFg5zb21lQGVtYWlsLm5ldDAeFw0y\nMjA2MTMwMDAwMDBaFw0yMjA3MTMwMDAwMDBaMDoxGTAXBgNVBAMTEFRlc3QgY2Vy\ndGlmaWNhdGUxHTAbBgkqhkiG9w0BCQEWDnNvbWVAZW1haWwubmV0MIIBIjANBgkq\nhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5RvVEPxPI1yxwrYN3upTWk6nMFEVldi+\nZUSqvsOaNDdFBQ86WsCHUAgYY0UJKLaVcNkMqR+w35RjZvwCjZZfQYNatZGqH7Rx\n7ap6oHGyxWUSt+a28pgIBbya3HxL/bkNcUP8RiWQ9pLNXJSPkEtlMAKs43PUCFPq\nd83y58nsVQBrm6EYzB6tfIXQQ9zI2jfTAga9JLJmTE/ugTP5cPZb/wwMeLNbR94n\nbdzTrV1NRebNAjR+T7Lih7zJHtq2FBYht+IHPLWdEXoYQnKtHp5liRGp0JQYqeJE\n5T6+D+FfP1CAdEKPn9SrJ+t+xJrFdSrv80DSfkPS3xHyeyJmsOsGzwIDAQABoz8w\nPTAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIGwDAdBgNVHQ4EFgQUyQ4YiMfD\nTpudqRnDxTKDbhuyRj4wDQYJKoZIhvcNAQELBQADggEBAMoP7NcWF6idD/8DDHmp\nIqY5EWI04zlVxvTsVLmvN0oKJ6BwI6ftzbTj1ZppCGSQ2vymHB/cB9tS+eBBcuH7\n207XKUYXEwL+cOCX5X+OF7HXUXEjhZoj9tEn3pF76WtzDMk/4fVWgARBHWKzDMe1\nhWrhKp5tqfa6AC8nhc/Ri8sSeJu7EUXr1Q6+gqm4x0VNsXY1eyl4Nu6R+oLNX0wa\nwOyce2aopgx9HKnXlfq6e+3MB0XMxzuoVi6Ky03mzCy6Oj+ckuS8dfTOWNhMqvC/\nvT0TbBJFMF4gJZnkGwKGS3DN1cIobXWtiM87+T4/KGuROkp6BuIYW7fieQlMw2A2\nnR0=\n-----END CERTIFICATE-----"
const csrPEM = "-----BEGIN CERTIFICATE REQUEST-----\nMIICvzCCAacCAQAwOjEZMBcGA1UEAxMQVGVzdCBjZXJ0aWZpY2F0ZTEdMBsGCSqG\nSIb3DQEJARYOc29tZUBlbWFpbC5uZXQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\nggEKAoIBAQCtZcH9/fTHqS/xsbgHcXyIayW59YHI9mIgkY5CcWT6uvzylEeXmBlM\nqOruYlLNJau8rRaRJjx8BhbLm1uQgvraJx88XWQVNqLdZGt/kEL12lYCM4buq1Jz\nsmfh+8e9ya8/bcfYv8mrNi5pfoB+Gn4mAgcXzdeWJBgbHqfuP38DfcCCSrFejeDI\nmZbD/eIaxY3KQTgmwLe9OypQFMHoRwqBKRyIjkPFCrCXaCBRNzykfJt4yTMBwJvR\nsqiHYS/HTEeMQiHJCVg8GLEZLfqhzx9CQ0gA503m0bbw6CL5sK9x7kyElqrw9z0K\ny2rH7KCtDhjWeikq8/yQ0KkSAA3DAnepAgMBAAGgQDA+BgkqhkiG9w0BCQ4xMTAv\nMA4GA1UdDwEB/wQEAwIGwDAdBgNVHQ4EFgQU8DicWElyhsq6FbDUF+XbSMbX7uow\nDQYJKoZIhvcNAQELBQADggEBAKPBebW8DQXW8HVDWXtskr1ik9I9ZyjKgvNpfU5X\nGmI1hM8Co5DA0Ow/MsrqoezbuRlMGQyPsGEgbGmyybfL9/VvlD0u5RN7P4fHp+V7\nJbd0Jdtj6W4vu+xcprp5enZO7HkJgxE+1rNArCasMUuxMKubnyLxMdzqORDeiffY\nMqoYoUcDQd8c5h98OJOBRv2cqN5HfIfWb4FVKJAM6cO+zZjB8u+9pQQtMKOD4f+E\n6jOnxDxJaOcVBq2vbmq3z05LZzoxJPQMTx7tTkQB8JxxACssI5eMQ0RE6BVhh1uF\n3xCaO8IoLaTSS8Z1rfL3Jli75zLwWkuf9Ki/LF+IDvjss8s=\n-----END CERTIFICATE REQUEST-----"

class TokenTemplateBuilder extends TemplateBuilder implements ITemplateBuilder {
  public override build(params: ITemplateBuildParameters): ITemplate {
    const template = super.build(params);

    switch (params.type) {
      case "x509":
      case "request": {
        switch (params.action) {
          case "import":
            Object.assign<ITemplate, ITemplate>(template, {
              token: true,
            })
            break;
        }
      }
    }

    return template;
  }

}

context("Template builder", () => {

  beforeEach(async () => {
    const keys = await crypto.certStorage.keys();
    if (keys.length) {
      await crypto.certStorage.clear();
    }

    crypto.templateBuilder = new TemplateBuilder();
  });

  context("certStorage", () => {

    context("importCert", () => {

      context("x509", () => {

        it("default", async () => {
          const certX509 = new x509.X509Certificate(certPEM);
          const alg = {
            ...certX509.signatureAlgorithm,
            ...certX509.publicKey.algorithm,
          }
          const cert = await crypto.certStorage.importCert("raw", certX509.rawData, alg, ["verify"]);

          const index = await crypto.certStorage.indexOf(cert);
          assert.strictEqual(index, null);

          const index2 = await crypto.certStorage.setItem(cert);
          assert.strictEqual(typeof index2, "string");
        });

        it("token", async () => {
          crypto.templateBuilder = new TokenTemplateBuilder();

          const certX509 = new x509.X509Certificate(certPEM);
          const alg = {
            ...certX509.signatureAlgorithm,
            ...certX509.publicKey.algorithm,
          }
          const cert = await crypto.certStorage.importCert("pem", certX509.toString("pem"), alg, ["verify"]);

          const index = await crypto.certStorage.indexOf(cert);
          assert.strictEqual(typeof index, "string");

          const index2 = await crypto.certStorage.setItem(cert);
          assert.strictEqual(index2, index);
        });

      });

      context("req", () => {

        it("default", async () => {
          const reqX509 = new x509.Pkcs10CertificateRequest(csrPEM);
          const alg = {
            ...reqX509.signatureAlgorithm,
            ...reqX509.publicKey.algorithm,
          }
          const req = await crypto.certStorage.importCert("raw", reqX509.rawData, alg, ["verify"]);

          const index = await crypto.certStorage.indexOf(req);
          assert.strictEqual(index, null);

          const index2 = await crypto.certStorage.setItem(req);
          assert.strictEqual(typeof index2, "string");
        });

        it("token", async () => {
          crypto.templateBuilder = new TokenTemplateBuilder();

          const reqX509 = new x509.Pkcs10CertificateRequest(csrPEM);
          const alg = {
            ...reqX509.signatureAlgorithm,
            ...reqX509.publicKey.algorithm,
          }
          const req = await crypto.certStorage.importCert("pem", reqX509.toString("pem"), alg, ["verify"]);

          const index = await crypto.certStorage.indexOf(req);
          assert.strictEqual(typeof index, "string");

          const index2 = await crypto.certStorage.setItem(req);
          assert.strictEqual(index2, index);
        });

      });

    });

  });

});
