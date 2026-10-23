import { describe, expect, it } from "vitest";
import {
  CryptoError,
  newPasswordParams,
  PASSWORD_LIMITS,
  passwordKey,
  recoveryPhrase,
  recoveryPhraseEntropy,
} from "../src/index.ts";

// The real cost (256 MiB) is too slow for unit tests; the minimum is the same function.
const cheap = () => newPasswordParams({ ops: PASSWORD_LIMITS.minOps, mem: PASSWORD_LIMITS.minMem });

describe("passwordKey", () => {
  it("is deterministic per password and salt", () => {
    const p = cheap();
    const k = passwordKey("correct horse", p);
    expect(k).toHaveLength(32);
    expect(passwordKey("correct horse", p)).toEqual(k);
    expect(passwordKey("correct horsf", p)).not.toEqual(k);
    expect(passwordKey("correct horse", cheap())).not.toEqual(k);
  });

  it("normalises Unicode so the same password typed on another keyboard matches", () => {
    const p = cheap();
    expect(passwordKey("café", p)).toEqual(passwordKey("café", p));
  });

  it("defaults to Argon2id at 256 MiB, three passes", () => {
    const p = newPasswordParams();
    expect(p).toMatchObject({ alg: "argon2id13", ops: 3, mem: 256 * 1024 * 1024 });
    expect(p.salt).toMatch(/^[A-Za-z0-9_-]{22}$/);
  });

  it("refuses parameters outside the limits (they come from synced data)", () => {
    const p = cheap();
    expect(() => passwordKey("x", { ...p, ops: 0 })).toThrow(CryptoError);
    expect(() => passwordKey("x", { ...p, mem: PASSWORD_LIMITS.minMem - 1 })).toThrow(CryptoError);
    expect(() => passwordKey("x", { ...p, mem: PASSWORD_LIMITS.maxMem + 1 })).toThrow(CryptoError);
    expect(() => passwordKey("x", { ...p, ops: PASSWORD_LIMITS.maxOps + 1 })).toThrow(CryptoError);
    expect(() => passwordKey("x", { ...p, alg: "argon2i13" as "argon2id13" })).toThrow(CryptoError);
    expect(() => passwordKey("x", { ...p, salt: "short" })).toThrow(CryptoError);
  });
});

describe("recoveryPhrase", () => {
  it("is 24 BIP39 words that give back 32 bytes of entropy", () => {
    const words = recoveryPhrase();
    expect(words).toHaveLength(24);
    const e = recoveryPhraseEntropy(words);
    expect(e).toHaveLength(32);
    expect(recoveryPhraseEntropy(words)).toEqual(e);
    expect(recoveryPhrase()).not.toEqual(words);
  });

  it("accepts the words with stray spaces and capitals", () => {
    const words = recoveryPhrase();
    const typed = ` ${words.join("  ").toUpperCase()} `;
    expect(recoveryPhraseEntropy(typed)).toEqual(recoveryPhraseEntropy(words));
  });

  it("refuses a mistyped or short phrase", () => {
    // BIP39 test vector: 23 × "abandon" + "art" is all-zero entropy; with "abandon" last the checksum fails.
    const zero = [...Array(23).fill("abandon"), "art"];
    expect(recoveryPhraseEntropy(zero)).toEqual(new Uint8Array(32));
    expect(() => recoveryPhraseEntropy(Array(24).fill("abandon"))).toThrow(CryptoError);
    const words = recoveryPhrase();
    expect(() => recoveryPhraseEntropy(words.slice(0, 12))).toThrow(CryptoError);
    expect(() => recoveryPhraseEntropy([...words.slice(0, 23), "notaword"])).toThrow(CryptoError);
  });
});
