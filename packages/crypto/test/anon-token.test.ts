import { describe, expect, it } from "vitest";
import { anonToken, type Bytes, CryptoError, concatBytes, generateKey, utf8 } from "../src/index.ts";
import { sodium } from "../src/sodium.ts";

const { blind, epochOf, epochSecret, evaluate, finalize, publicKey, redeemCheck } = anonToken;

/** Element i of a list the test knows is long enough. */
const at = <T>(list: T[], i: number): T => {
  const x = list[i];
  if (x === undefined) throw new Error(`no element ${i}`);
  return x;
};

const seed = generateKey();
const epoch = epochOf(new Date("2026-10-20T12:00:00Z"));
const k = epochSecret(seed, epoch);
const K = publicKey(k);

/*
 * An independent, test-only prover: it proves with a given secret over whatever transcript it is
 * handed, so a malicious server can be simulated (tampered elements with a fresh, consistent proof).
 */
const u32 = (i: number): Bytes => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, i);
  return b;
};
const one = new Uint8Array(32);
one[0] = 1;

function weights(pub: Bytes, blinded: Bytes[], evaluated: Bytes[]): Bytes[] {
  const s = sodium();
  const seedT = s.crypto_hash_sha512(concatBytes(pub, ...blinded, ...evaluated));
  return blinded.map((_, i) =>
    s.crypto_core_ristretto255_scalar_reduce(s.crypto_hash_sha512(concatBytes(seedT, u32(i)))),
  );
}

function fold(ws: Bytes[], xs: Bytes[]): Bytes {
  const s = sodium();
  return ws
    .map((w, i) => s.crypto_scalarmult_ristretto255(w, at(xs, i)))
    .reduce((a, b) => s.crypto_core_ristretto255_add(a, b));
}

function prove(secret: Bytes, pub: Bytes, blinded: Bytes[], evaluated: Bytes[]): Bytes {
  const s = sodium();
  const ws = weights(pub, blinded, evaluated);
  const M = fold(ws, blinded);
  const Z = fold(ws, evaluated);
  const nonce = s.crypto_core_ristretto255_scalar_random();
  const G = s.crypto_scalarmult_ristretto255_base(one);
  const A = s.crypto_scalarmult_ristretto255_base(nonce);
  const B = s.crypto_scalarmult_ristretto255(nonce, M);
  const c = s.crypto_core_ristretto255_scalar_reduce(
    s.crypto_hash_sha512(concatBytes(utf8("dleq"), G, pub, M, Z, A, B)),
  );
  return concatBytes(c, s.crypto_core_ristretto255_scalar_sub(nonce, s.crypto_core_ristretto255_scalar_mul(c, secret)));
}

describe("anonymous tokens", () => {
  it("round-trips a batch of 100 tokens", () => {
    const { tokens, blinded } = blind(100);
    expect(tokens).toHaveLength(100);
    expect(blinded).toHaveLength(100);
    const { evaluated, proof } = evaluate(k, blinded);
    expect(proof).toHaveLength(64);
    const out = finalize(K, tokens, blinded, evaluated, proof);
    expect(out).toHaveLength(100);
    for (const { t, n } of out) {
      expect(t).toHaveLength(32);
      expect(n).toHaveLength(32);
      expect(redeemCheck(k, t, n)).toBe(true);
    }
  });

  it("finalized tokens are not linkable to the blinded elements", () => {
    const { tokens, blinded } = blind(1);
    const { evaluated, proof } = evaluate(k, blinded);
    const { n } = at(finalize(K, tokens, blinded, evaluated, proof), 0);
    expect(n).not.toEqual(at(evaluated, 0));
    expect(at(tokens, 0).t).not.toEqual(at(blinded, 0));
  });

  it("rejects a batch evaluated with a different (tagging) key", () => {
    const { tokens, blinded } = blind(5);
    const tagging = epochSecret(generateKey(), epoch);
    const { evaluated, proof } = evaluate(tagging, blinded);
    expect(() => finalize(K, tokens, blinded, evaluated, proof)).toThrow(new CryptoError("bad token proof"));
  });

  it("rejects a malicious prover's consistent proofs over tampered batches", () => {
    const s = sodium();
    const { tokens, blinded } = blind(5);
    const { evaluated } = evaluate(k, blinded);

    // Control: the test prover over the honest transcript is accepted.
    expect(finalize(K, tokens, blinded, evaluated, prove(k, K, blinded, evaluated))).toHaveLength(5);

    // (i) One element under a tagging key, proven with the honest k over that exact transcript.
    const tagging = epochSecret(generateKey(), epoch);
    const tagged = evaluated.map((e, i) => (i === 2 ? s.crypto_scalarmult_ristretto255(tagging, at(blinded, 2)) : e));
    expect(() => finalize(K, tokens, blinded, tagged, prove(k, K, blinded, tagged))).toThrow(
      new CryptoError("bad token proof"),
    );

    // (ii) Cancellation: e0 + D and e1 − (w0/w1)·D keep Z unchanged under the honest transcript's weights.
    const ws = weights(K, blinded, evaluated);
    const D = s.crypto_core_ristretto255_random();
    const f = s.crypto_core_ristretto255_scalar_mul(at(ws, 0), s.crypto_core_ristretto255_scalar_invert(at(ws, 1)));
    const cancelled = [
      s.crypto_core_ristretto255_add(at(evaluated, 0), D),
      s.crypto_core_ristretto255_sub(at(evaluated, 1), s.crypto_scalarmult_ristretto255(f, D)),
      ...evaluated.slice(2),
    ];
    expect(fold(ws, cancelled)).toEqual(fold(ws, evaluated));
    expect(() => finalize(K, tokens, blinded, cancelled, prove(k, K, blinded, cancelled))).toThrow(
      new CryptoError("bad token proof"),
    );
  });

  it("rejects a non-canonical z (z + L)", () => {
    const { tokens, blinded } = blind(3);
    const { evaluated, proof } = evaluate(k, blinded);
    const L = 2n ** 252n + 27742317777372353535851937790883648493n;
    const toBig = (b: Bytes) => b.reduceRight((a, x) => (a << 8n) + BigInt(x), 0n);
    const toBytes = (n: bigint) => {
      const b = new Uint8Array(32);
      for (let i = 0; i < 32; i++) {
        b[i] = Number(n & 255n);
        n >>= 8n;
      }
      return b;
    };
    const zPlusL = concatBytes(proof.subarray(0, 32), toBytes(toBig(proof.subarray(32)) + L));
    expect(() => finalize(K, tokens, blinded, evaluated, zPlusL)).toThrow(new CryptoError("bad token proof"));
    expect(finalize(K, tokens, blinded, evaluated, proof)).toHaveLength(3);
  });

  it("rejects swapped evaluated elements", () => {
    const { tokens, blinded } = blind(3);
    const { evaluated, proof } = evaluate(k, blinded);
    const swapped: Bytes[] = [at(evaluated, 1), at(evaluated, 0), at(evaluated, 2)];
    expect(() => finalize(K, tokens, blinded, swapped, proof)).toThrow(new CryptoError("bad token proof"));
  });

  it("rejects a tampered proof", () => {
    const { tokens, blinded } = blind(3);
    const { evaluated, proof } = evaluate(k, blinded);
    const bad = proof.slice();
    bad[40] = (bad[40] ?? 0) ^ 1;
    expect(() => finalize(K, tokens, blinded, evaluated, bad)).toThrow(new CryptoError("bad token proof"));
  });

  it("rejects identity, invalid or wrongly sized elements from the server", () => {
    const { tokens, blinded } = blind(2);
    const { evaluated, proof } = evaluate(k, blinded);
    const identity = new Uint8Array(32);
    const invalid = new Uint8Array(32).fill(0xff);
    for (const e of [identity, invalid, new Uint8Array(31)]) {
      expect(() => finalize(K, tokens, blinded, [e, at(evaluated, 1)], proof)).toThrow(CryptoError);
    }
    for (const bad of [identity, invalid]) {
      expect(() => finalize(bad, tokens, blinded, evaluated, proof)).toThrow(CryptoError);
    }
    expect(() => finalize(K, tokens, blinded, evaluated.slice(0, 1), proof)).toThrow(CryptoError);
    expect(() => finalize(K, tokens, blinded, evaluated, proof.slice(0, 63))).toThrow(CryptoError);
  });

  it("evaluate rejects invalid blinded elements", () => {
    expect(() => evaluate(k, [new Uint8Array(32)])).toThrow(CryptoError);
    expect(() => evaluate(k, [new Uint8Array(32).fill(0xff)])).toThrow(CryptoError);
    expect(() => evaluate(k, [new Uint8Array(33)])).toThrow(CryptoError);
    expect(() => evaluate(k, [])).toThrow(CryptoError);
  });

  it("blind accepts 1 to 100 tokens", () => {
    expect(blind(1).blinded).toHaveLength(1);
    for (const n of [0, 101, 1.5, -1, Number.NaN]) {
      expect(() => blind(n)).toThrow(CryptoError);
    }
  });

  it("does not redeem a current token with the previous epoch's secret", () => {
    const { tokens, blinded } = blind(1);
    const { evaluated, proof } = evaluate(k, blinded);
    const { t, n } = at(finalize(K, tokens, blinded, evaluated, proof), 0);
    expect(redeemCheck(epochSecret(seed, epoch - 1), t, n)).toBe(false);
    expect(redeemCheck(k, t, n)).toBe(true);
  });

  it("redeemCheck is false for a forged or malformed token", () => {
    const { tokens } = blind(1);
    expect(redeemCheck(k, at(tokens, 0).t, generateKey())).toBe(false);
    expect(redeemCheck(k, at(tokens, 0).t, new Uint8Array(32))).toBe(false);
    expect(redeemCheck(k, new Uint8Array(31), new Uint8Array(32))).toBe(false);
  });

  it("derives a deterministic epoch secret that differs across epochs", () => {
    expect(epochSecret(seed, epoch)).toEqual(k);
    expect(epochSecret(seed, epoch + 1)).not.toEqual(k);
    expect(epochSecret(generateKey(), epoch)).not.toEqual(k);
    expect(k).toHaveLength(32);
  });

  it("rejects epochs that are not non-negative safe integers", () => {
    for (const e of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 53]) {
      expect(() => epochSecret(seed, e)).toThrow(CryptoError);
    }
    expect(epochSecret(seed, 0)).toHaveLength(32);
  });

  it("counts epochs in UTC days", () => {
    expect(epochOf(new Date("2026-10-20T23:59:59Z")) + 1).toBe(epochOf(new Date("2026-10-21T00:00:00Z")));
    expect(epochOf(new Date("1970-01-01T23:59:59Z"))).toBe(0);
  });
});
