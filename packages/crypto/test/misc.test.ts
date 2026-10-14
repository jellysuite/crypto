import { describe, expect, it } from "vitest";
import {
  constantTimeEqual,
  derive,
  fromBase64Url,
  generateKey,
  generateSigningKeyPair,
  randomBytes,
  safetyPhrase,
  sha256,
  toBase64Url,
  utf8,
} from "../src/index.ts";

describe("encoding", () => {
  it("round-trips base64url without padding or unsafe characters", () => {
    for (const n of [0, 1, 2, 3, 31, 32, 33, 64]) {
      const b = randomBytes(n);
      const s = toBase64Url(b);
      expect(s).not.toMatch(/[=+/]/);
      expect(fromBase64Url(s)).toEqual(b);
    }
  });
});

describe("derive", () => {
  it("is deterministic per key and context", () => {
    const k = generateKey();
    expect(derive(k, "a")).toEqual(derive(k, "a"));
    expect(derive(k, "a")).not.toEqual(derive(k, "b"));
    expect(derive(k, "a")).toHaveLength(32);
  });

  it("accepts keys longer than 32 bytes", () => {
    expect(derive(randomBytes(64), "a")).toHaveLength(32);
  });
});

describe("hashing", () => {
  it("computes sha256", () => {
    expect(toBase64Url(sha256(utf8("abc")))).toBe("ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0");
  });

  it("compares in constant time", () => {
    expect(constantTimeEqual(utf8("abc"), utf8("abc"))).toBe(true);
    expect(constantTimeEqual(utf8("abc"), utf8("abd"))).toBe(false);
    expect(constantTimeEqual(utf8("abc"), utf8("ab"))).toBe(false);
  });
});

describe("safetyPhrase", () => {
  it("returns twelve stable words per key", () => {
    const kp = generateSigningKeyPair();
    const words = safetyPhrase(kp.publicKey);
    expect(words).toHaveLength(12);
    expect(safetyPhrase(kp.publicKey)).toEqual(words);
    expect(safetyPhrase(generateSigningKeyPair().publicKey)).not.toEqual(words);
  });
});
