import { wordlist } from "@scure/bip39/wordlists/english.js";
import type { Bytes } from "./encoding.ts";
import { sha256 } from "./hash.ts";

const WORDS = 12; // 132 bits: comparing them is as strong as comparing the keys for practical purposes
const BYTES = Math.ceil((WORDS * 11) / 8);

/** Twelve BIP39 words from sha256(publicKey), for comparing keys out of band. */
export function safetyPhrase(signPublicKey: Bytes): string[] {
  const digest = sha256(signPublicKey);
  let bits = 0n;
  for (const byte of digest.subarray(0, BYTES)) bits = (bits << 8n) | BigInt(byte);
  const words: string[] = [];
  for (let i = 0; i < WORDS; i++) {
    const index = Number((bits >> BigInt(BYTES * 8 - 11 * (i + 1))) & 0x7ffn);
    words.push(wordlist[index] ?? "");
  }
  return words;
}
