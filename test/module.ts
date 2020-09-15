import * as assert from "assert";
import { CryptoModule, CryptoModuleInitParams, Crypto } from "../src";

context.only("CryptoModule", () => {

  const config: CryptoModuleInitParams = {
    library: "/usr/local/lib/softhsm/libsofthsm2.so",
    tokenPresent: true,
  };
  const softHsm = new CryptoModule(config);

  it("info", () => {
    const info = softHsm.info();

    assert.strictEqual(info.library, "/usr/local/lib/softhsm/libsofthsm2.so");
    assert.strictEqual(info.manufacturer, "SoftHSM");
    assert(info.versions.cryptoki);
    assert(info.versions.library);
    assert(info.description, "Implementation of PKCS11");
  });

  it("items", () => {
    const softHsm = new CryptoModule(config);

    const items = softHsm.items();
    assert(items.length > 0);

    for (const crypto of softHsm.items()) {
      assert(crypto instanceof Crypto);
    }

  });

  context("getItem", () => {
    
    it("by index", () => {
      const crypto = softHsm.getItem(0);

      assert(crypto instanceof Crypto);
    });

    it("by outrange index", () => {
      const crypto = softHsm.getItem(10);

      assert.strictEqual(crypto, null);
    });

    it("by name", () => {
      const cryptoList = softHsm.items();

      assert(cryptoList.length > 0);

      const desc = cryptoList[0].info().description;
      const crypto = softHsm.getItem(desc);
      assert(crypto instanceof Crypto);
    });

    it("by nonexisting name", () => {
      const crypto = softHsm.getItem("nonexisting name");
      assert.strictEqual(crypto, null);
    });

  });

});
