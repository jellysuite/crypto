import { describe, expect, it } from "vitest";
import { CryptoError, fromUtf8, generateKey, open, openJson, seal, sealJson, utf8 } from "../src/index.ts";

describe("envelope", () => {
  const key = generateKey();
  const ad = utf8("node-1:1");

  it("round-trips plaintext with matching tag and associated data", () => {
    const env = seal(key, "jelly/test@1", utf8("hello"), ad);
    expect(fromUtf8(open(key, "jelly/test@1", env, ad))).toBe("hello");
  });

  it("round-trips JSON", () => {
    const env = sealJson(key, "jelly/test@1", { title: "Plans", n: 3 });
    expect(openJson(key, "jelly/test@1", env)).toEqual({ title: "Plans", n: 3 });
  });

  it("round-trips empty plaintext", () => {
    expect(open(key, "jelly/test@1", seal(key, "jelly/test@1", new Uint8Array())).length).toBe(0);
  });

  it("produces different ciphertext for the same plaintext", () => {
    const a = seal(key, "jelly/test@1", utf8("x"));
    const b = seal(key, "jelly/test@1", utf8("x"));
    expect(a).not.toEqual(b);
  });

  it("rejects the wrong key", () => {
    const env = seal(key, "jelly/test@1", utf8("hello"));
    expect(() => open(generateKey(), "jelly/test@1", env)).toThrow(CryptoError);
  });

  it("rejects a different type tag", () => {
    const env = seal(key, "jelly/test@1", utf8("hello"));
    expect(() => open(key, "jelly/other@1", env)).toThrow(CryptoError);
  });

  it("rejects different associated data", () => {
    const env = seal(key, "jelly/test@1", utf8("hello"), ad);
    expect(() => open(key, "jelly/test@1", env, utf8("node-2:1"))).toThrow(CryptoError);
  });

  it("rejects a flipped ciphertext byte", () => {
    const env = seal(key, "jelly/test@1", utf8("hello"));
    env[env.length - 1] = (env[env.length - 1] ?? 0) ^ 1;
    expect(() => open(key, "jelly/test@1", env)).toThrow(CryptoError);
  });

  it("rejects an unsupported format version", () => {
    const env = seal(key, "jelly/test@1", utf8("hello"));
    env[0] = 2;
    expect(() => open(key, "jelly/test@1", env)).toThrow(CryptoError);
  });

  it("rejects truncated input", () => {
    expect(() => open(key, "jelly/test@1", new Uint8Array([1]))).toThrow(CryptoError);
  });
});
