import { CryptoError } from "./errors.ts";
import { sodium } from "./sodium.ts";

export type Bytes = Uint8Array;

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export const utf8 = (s: string): Bytes => encoder.encode(s);
export const fromUtf8 = (b: Bytes): string => decoder.decode(b);

export function toBase64Url(b: Bytes): string {
  return sodium().to_base64(b, sodium().base64_variants.URLSAFE_NO_PADDING);
}

export function fromBase64Url(s: string): Bytes {
  try {
    return sodium().from_base64(s, sodium().base64_variants.URLSAFE_NO_PADDING);
  } catch {
    throw new CryptoError("invalid base64url");
  }
}

export function concatBytes(...parts: Bytes[]): Bytes {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export const randomBytes = (n: number): Bytes => sodium().randombytes_buf(n);
export const generateKey = (): Bytes => randomBytes(32);
