import { type Bytes, concatBytes, fromUtf8, randomBytes, utf8 } from "./encoding.ts";
import { CryptoError } from "./errors.ts";
import { sodium } from "./sodium.ts";

const FORMAT = 1;
const NONCE_BYTES = 24;
const EMPTY = new Uint8Array();

/**
 * Envelope v1: [format][tagLen][tag][nonce(24)][xchacha20-poly1305 ciphertext].
 * The header and caller-supplied associated data are authenticated, so a ciphertext
 * can't be reinterpreted as another type or moved to another node.
 */
export function seal(key: Bytes, typeTag: string, plaintext: Bytes, ad: Bytes = EMPTY): Bytes {
  const tag = utf8(typeTag);
  if (tag.length === 0 || tag.length > 255) throw new CryptoError("invalid type tag");
  const header = concatBytes(Uint8Array.of(FORMAT, tag.length), tag);
  const nonce = randomBytes(NONCE_BYTES);
  const ct = sodium().crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, concatBytes(header, ad), null, nonce, key);
  return concatBytes(header, nonce, ct);
}

export function open(key: Bytes, typeTag: string, envelope: Bytes, ad: Bytes = EMPTY): Bytes {
  if (envelope.length < 2 || envelope[0] !== FORMAT) throw new CryptoError("unsupported envelope");
  const tagEnd = 2 + (envelope[1] ?? 0);
  if (envelope.length < tagEnd + NONCE_BYTES) throw new CryptoError("truncated envelope");
  let tag: string;
  try {
    tag = fromUtf8(envelope.subarray(2, tagEnd));
  } catch {
    throw new CryptoError("invalid type tag");
  }
  if (tag !== typeTag) throw new CryptoError(`expected ${typeTag}, got ${tag}`);
  const header = envelope.subarray(0, tagEnd);
  const nonce = envelope.subarray(tagEnd, tagEnd + NONCE_BYTES);
  try {
    return sodium().crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      envelope.subarray(tagEnd + NONCE_BYTES),
      concatBytes(header, ad),
      nonce,
      key,
    );
  } catch {
    throw new CryptoError("decryption failed");
  }
}

export function sealJson(key: Bytes, typeTag: string, value: unknown, ad?: Bytes): Bytes {
  return seal(key, typeTag, utf8(JSON.stringify(value)), ad);
}

export function openJson<T>(key: Bytes, typeTag: string, envelope: Bytes, ad?: Bytes): T {
  return JSON.parse(fromUtf8(open(key, typeTag, envelope, ad))) as T;
}
