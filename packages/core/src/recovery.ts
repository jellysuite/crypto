import { type Bytes, derive, fromBase64Url, generateKey, open, seal, sha256, toBase64Url } from "@jelly/crypto";
import { KDF, TAG } from "./tags.ts";
import type { B64 } from "./wire.ts";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const KEY_BYTES = 32;
const KEY_CHARS = Math.ceil((KEY_BYTES * 8) / 5);

function base32(bytes: Bytes): string {
  let out = "";
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(buffer >> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(buffer << (5 - bits)) & 31];
  return out;
}

function unbase32(s: string): Bytes | null {
  const out: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const ch of s) {
    const v = ALPHABET.indexOf(ch);
    if (v < 0) return null;
    buffer = ((buffer << 5) | v) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      out.push((buffer >> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Uint8Array.from(out);
}

export function formatRecoveryKey(raw: Bytes): string {
  return `JELLY-${
    base32(raw)
      .match(/.{1,4}/g)
      ?.join("-") ?? ""
  }`;
}

export function parseRecoveryKey(input: string): Bytes | null {
  const compact = input
    .toUpperCase()
    .replace(/[\s-]/g, "")
    .replace(/^JELLY/, "");
  if (compact.length !== KEY_CHARS) return null;
  const bytes = unbase32(compact);
  return bytes && bytes.length === KEY_BYTES ? bytes : null;
}

function requireKey(recoveryKey: string): Bytes {
  const raw = parseRecoveryKey(recoveryKey);
  if (!raw) throw new Error("invalid recovery key");
  return raw;
}

export const recoveryAuth = (recoveryKey: string): B64 =>
  toBase64Url(derive(requireKey(recoveryKey), KDF.recoveryAuth));

export const recoveryAuthHash = (auth: B64): B64 => toBase64Url(sha256(fromBase64Url(auth)));

export function newRecoveryMaterial(ak: Bytes): {
  recoveryKey: string;
  recoveryWrap: B64;
  recoveryAuthHash: B64;
} {
  const raw = generateKey();
  const recoveryKey = formatRecoveryKey(raw);
  return {
    recoveryKey,
    recoveryWrap: toBase64Url(seal(derive(raw, KDF.recoveryWrap), TAG.akWrap, ak)),
    recoveryAuthHash: recoveryAuthHash(recoveryAuth(recoveryKey)),
  };
}

export function unwrapRecoveryWrap(wrap: B64, recoveryKey: string): Bytes {
  return open(derive(requireKey(recoveryKey), KDF.recoveryWrap), TAG.akWrap, fromBase64Url(wrap));
}
