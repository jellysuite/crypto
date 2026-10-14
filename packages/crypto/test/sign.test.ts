import { describe, expect, it } from "vitest";
import { generateSigningKeyPair, sign, signingPublicFromPrivate, utf8, verify } from "../src/index.ts";

describe("signatures", () => {
  const kp = generateSigningKeyPair();
  const payload = utf8("grant:node-1");

  it("verifies a signature with the same context", () => {
    expect(verify(kp.publicKey, "grant", payload, sign(kp.privateKey, "grant", payload))).toBe(true);
  });

  it("fails under a different context", () => {
    expect(verify(kp.publicKey, "other", payload, sign(kp.privateKey, "grant", payload))).toBe(false);
  });

  it("fails for a tampered payload", () => {
    expect(verify(kp.publicKey, "grant", utf8("grant:node-2"), sign(kp.privateKey, "grant", payload))).toBe(false);
  });

  it("fails for another signer's key", () => {
    const other = generateSigningKeyPair();
    expect(verify(other.publicKey, "grant", payload, sign(kp.privateKey, "grant", payload))).toBe(false);
  });

  it("returns false for malformed signatures instead of throwing", () => {
    expect(verify(kp.publicKey, "grant", payload, new Uint8Array(3))).toBe(false);
  });
});

describe("signingPublicFromPrivate", () => {
  it("derives the public key from the seed, ignoring the public half stored in the secret key", () => {
    const a = generateSigningKeyPair();
    const b = generateSigningKeyPair();
    expect(signingPublicFromPrivate(a.privateKey)).toEqual(a.publicKey);
    const crafted = Uint8Array.from([...a.privateKey.slice(0, 32), ...b.publicKey]);
    expect(signingPublicFromPrivate(crafted)).toEqual(a.publicKey);
  });
});
