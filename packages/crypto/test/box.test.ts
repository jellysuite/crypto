import { describe, expect, it } from "vitest";
import {
  CryptoError,
  encryptionKeyPairFromSeed,
  encryptionPublicFromPrivate,
  fromUtf8,
  generateEncryptionKeyPair,
  openSealed,
  sealTo,
  utf8,
} from "../src/index.ts";

describe("sealed boxes", () => {
  it("opens with the recipient key pair", () => {
    const bob = generateEncryptionKeyPair();
    expect(fromUtf8(openSealed(bob, sealTo(bob.publicKey, utf8("k"))))).toBe("k");
  });

  it("rejects another key pair", () => {
    const bob = generateEncryptionKeyPair();
    const carol = generateEncryptionKeyPair();
    expect(() => openSealed(carol, sealTo(bob.publicKey, utf8("k")))).toThrow(CryptoError);
  });
});

describe("seeded key pairs", () => {
  it("are deterministic and the public key follows from the private one", () => {
    const seed = new Uint8Array(32).fill(7);
    const a = encryptionKeyPairFromSeed(seed);
    const b = encryptionKeyPairFromSeed(seed);
    expect(a.publicKey).toEqual(b.publicKey);
    expect(encryptionPublicFromPrivate(a.privateKey)).toEqual(a.publicKey);
    expect(fromUtf8(openSealed(a, sealTo(a.publicKey, utf8("k"))))).toBe("k");
  });
});
