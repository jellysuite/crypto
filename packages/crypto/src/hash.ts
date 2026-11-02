import { type Bytes, concatBytes, utf8 } from "./encoding.ts";
import { sodium } from "./sodium.ts";

export const sha256 = (b: Bytes): Bytes => sodium().crypto_hash_sha256(b);

/** Subkey derivation: BLAKE2b-256 keyed by `key` over the context string. */
export function derive(key: Bytes, context: string): Bytes {
  const k = key.length > 64 ? sha256(key) : key;
  return sodium().crypto_generichash(32, utf8(context), k);
}

export function constantTimeEqual(a: Bytes, b: Bytes): boolean {
  return a.length === b.length && sodium().memcmp(a, b);
}

/** BLAKE2b-256 over a context string, a zero byte and the parts, so hashes made for one purpose never match another's. */
export const hashWith = (context: string, ...parts: Bytes[]): Bytes =>
  sodium().crypto_generichash(32, concatBytes(utf8(context), new Uint8Array([0]), ...parts), null);
