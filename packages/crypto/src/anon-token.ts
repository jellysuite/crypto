/*
 * Anonymous tokens: a ristretto255 VOPRF with a batch DLEQ proof (RFC 9497 in spirit).
 *
 * The API issues tokens to logged-in users; the fetcher redeems them without learning who asks.
 * 1. Client: picks random t_i and r_i, sends blinded_i = r_i·H(t_i).
 * 2. Server: returns evaluated_i = k·blinded_i plus one proof that every evaluated_i used the
 *    same k as the published K = k·G (so the server cannot tag a user with a key of its own).
 * 3. Client: verifies the proof, unblinds n_i = r_i⁻¹·evaluated_i = k·H(t_i), keeps (t_i, n_i).
 * 4. Fetcher: accepts (t, n) when k·H(t) == n (and t is not yet spent).
 *
 * Batch DLEQ: the batch is folded into M = Σ c_i·blinded_i, Z = Σ c_i·evaluated_i with c_i
 * derived from a hash of the whole transcript, and a Schnorr-style proof shows log_G K = log_M Z.
 * Epoch keys are derived per UTC day from a shared seed.
 */
import { type Bytes, concatBytes, utf8 } from "./encoding.ts";
import { CryptoError } from "./errors.ts";
import { constantTimeEqual, derive } from "./hash.ts";
import { sodium } from "./sodium.ts";

const HASH_DST = utf8("jelly/reader-token@1");
const DLEQ_DST = utf8("dleq");
const MAX_BATCH = 100;
const DAY_MS = 86_400_000;

export interface Token {
  t: Bytes;
  r: Bytes;
}

export interface FinalToken {
  t: Bytes;
  n: Bytes;
}

/** UTC days since the Unix epoch. */
export function epochOf(date: Date): number {
  return Math.floor(date.getTime() / DAY_MS);
}

/** The secret scalar k for one epoch, derived from the shared seed. */
export function epochSecret(seed: Bytes, epoch: number): Bytes {
  if (!Number.isSafeInteger(epoch) || epoch < 0) throw new CryptoError("invalid token epoch");
  const wide = concatBytes(
    derive(seed, `jelly/reader-token-key@1:${epoch}`),
    derive(seed, `jelly/reader-token-key@1b:${epoch}`),
  );
  return sodium().crypto_core_ristretto255_scalar_reduce(wide);
}

/** K = k·G. */
export function publicKey(k: Bytes): Bytes {
  return mulBase(scalar(k));
}

/** Picks `count` (1–100) random tokens and blinds them for issuance. */
export function blind(count: number): { tokens: Token[]; blinded: Bytes[] } {
  if (!Number.isInteger(count) || count < 1 || count > MAX_BATCH) {
    throw new CryptoError("token batch must hold 1 to 100 tokens");
  }
  const s = sodium();
  const tokens: Token[] = [];
  const blinded: Bytes[] = [];
  for (let i = 0; i < count; i++) {
    const t = s.randombytes_buf(32);
    const r = s.crypto_core_ristretto255_scalar_random();
    tokens.push({ t, r });
    blinded.push(mul(r, hashToGroup(t)));
  }
  return { tokens, blinded };
}

/** Server side: evaluates a blinded batch under k and proves it used k. */
export function evaluate(k: Bytes, blinded: Bytes[]): { evaluated: Bytes[]; proof: Bytes } {
  const s = sodium();
  scalar(k);
  if (blinded.length < 1 || blinded.length > MAX_BATCH) {
    throw new CryptoError("token batch must hold 1 to 100 tokens");
  }
  for (const b of blinded) point(b);
  const evaluated = blinded.map((b) => mul(k, b));
  const K = publicKey(k);
  const { M, Z } = composite(K, blinded, evaluated);
  const nonce = s.crypto_core_ristretto255_scalar_random();
  const c = challenge(K, M, Z, mulBase(nonce), mul(nonce, M));
  const z = s.crypto_core_ristretto255_scalar_sub(nonce, s.crypto_core_ristretto255_scalar_mul(c, k));
  return { evaluated, proof: concatBytes(c, z) };
}

/** Client side: verifies the proof against K and unblinds. Throws CryptoError("bad token proof"). */
export function finalize(K: Bytes, tokens: Token[], blinded: Bytes[], evaluated: Bytes[], proof: Bytes): FinalToken[] {
  const s = sodium();
  try {
    if (
      tokens.length < 1 ||
      tokens.length > MAX_BATCH ||
      blinded.length !== tokens.length ||
      evaluated.length !== tokens.length ||
      proof.length !== 64
    ) {
      throw new CryptoError("bad token proof");
    }
    point(K);
    for (const b of blinded) point(b);
    for (const e of evaluated) point(e);
    const c = proof.subarray(0, 32);
    const z = proof.subarray(32);
    // A non-canonical z (z ≥ L) would verify too; reject it so each proof has one encoding.
    if (!constantTimeEqual(s.crypto_core_ristretto255_scalar_reduce(concatBytes(z, new Uint8Array(32))), z)) {
      throw new CryptoError("bad token proof");
    }
    const { M, Z } = composite(K, blinded, evaluated);
    const A = s.crypto_core_ristretto255_add(mulBase(z), mul(c, K));
    const B = s.crypto_core_ristretto255_add(mul(z, M), mul(c, Z));
    if (!constantTimeEqual(challenge(K, M, Z, A, B), c)) throw new CryptoError("bad token proof");
    return tokens.map(({ t, r }, i) => ({
      t,
      n: mul(s.crypto_core_ristretto255_scalar_invert(r), at(evaluated, i)),
    }));
  } catch (e) {
    // Only our own validation errors mean a bad server; anything else is a local bug.
    if (e instanceof CryptoError) throw new CryptoError("bad token proof");
    throw e;
  }
}

/** Fetcher side: true when n == k·H(t). Malformed input is simply false. */
export function redeemCheck(k: Bytes, t: Bytes, n: Bytes): boolean {
  if (t.length !== 32 || n.length !== 32) return false;
  try {
    return constantTimeEqual(mul(scalar(k), hashToGroup(t)), n);
  } catch (e) {
    if (e instanceof CryptoError) return false;
    throw e;
  }
}

function hashToGroup(t: Bytes): Bytes {
  const s = sodium();
  return s.crypto_core_ristretto255_from_hash(s.crypto_hash_sha512(concatBytes(HASH_DST, t)));
}

function composite(K: Bytes, blinded: Bytes[], evaluated: Bytes[]): { M: Bytes; Z: Bytes } {
  const s = sodium();
  const seedT = s.crypto_hash_sha512(concatBytes(K, ...blinded, ...evaluated));
  let M: Bytes | null = null;
  let Z: Bytes | null = null;
  for (let i = 0; i < blinded.length; i++) {
    const c = s.crypto_core_ristretto255_scalar_reduce(s.crypto_hash_sha512(concatBytes(seedT, u32(i))));
    const m = mul(c, at(blinded, i));
    const z = mul(c, at(evaluated, i));
    M = M ? s.crypto_core_ristretto255_add(M, m) : m;
    Z = Z ? s.crypto_core_ristretto255_add(Z, z) : z;
  }
  if (!M || !Z) throw new CryptoError("empty token batch");
  return { M, Z };
}

function challenge(K: Bytes, M: Bytes, Z: Bytes, A: Bytes, B: Bytes): Bytes {
  const s = sodium();
  baseG ??= mulBase(ONE);
  const G = baseG;
  return s.crypto_core_ristretto255_scalar_reduce(s.crypto_hash_sha512(concatBytes(DLEQ_DST, G, K, M, Z, A, B)));
}

let baseG: Bytes | null = null;

const ONE = (() => {
  const b = new Uint8Array(32);
  b[0] = 1;
  return b;
})();

function at(list: Bytes[], i: number): Bytes {
  const b = list[i];
  if (!b) throw new CryptoError("token batch length mismatch");
  return b;
}

/** Big-endian 32-bit counter. */
function u32(i: number): Bytes {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, i);
  return b;
}

function scalar(k: Bytes): Bytes {
  if (k.length !== 32) throw new CryptoError("invalid token key");
  return k;
}

/** A valid, non-identity ristretto255 element. */
function point(p: Bytes): Bytes {
  if (p.length !== 32 || p.every((x) => x === 0) || !sodium().crypto_core_ristretto255_is_valid_point(p)) {
    throw new CryptoError("invalid token element");
  }
  return p;
}

/** Scalar multiplication; libsodium throws on invalid points or an identity result. */
function mul(n: Bytes, p: Bytes): Bytes {
  const s = sodium();
  try {
    return s.crypto_scalarmult_ristretto255(n, p);
  } catch {
    throw new CryptoError("invalid token element");
  }
}

function mulBase(n: Bytes): Bytes {
  const s = sodium();
  try {
    return s.crypto_scalarmult_ristretto255_base(n);
  } catch {
    throw new CryptoError("invalid token key");
  }
}
