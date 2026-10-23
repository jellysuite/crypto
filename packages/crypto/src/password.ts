import { generateMnemonic, mnemonicToEntropy } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { type Bytes, fromBase64Url, randomBytes, toBase64Url, utf8 } from "./encoding.ts";
import { CryptoError } from "./errors.ts";
import { sodium } from "./sodium.ts";

const SALT_BYTES = 16;
const MiB = 1024 * 1024;

/**
 * Bounds for Argon2id parameters read back from storage or a synced vault: a floor so no one can talk a device
 * into a weak key, a ceiling so no one can make it allocate gigabytes.
 */
export const PASSWORD_LIMITS = { minOps: 1, maxOps: 10, minMem: 8 * MiB, maxMem: 1024 * MiB } as const;

/** How a key was derived from a password. Stored next to what it protects; `salt` is base64url. */
export type PasswordParams = { alg: "argon2id13"; ops: number; mem: number; salt: string };

export function newPasswordParams(cost: { ops?: number; mem?: number } = {}): PasswordParams {
  return {
    alg: "argon2id13",
    ops: cost.ops ?? 3,
    mem: cost.mem ?? 256 * MiB,
    salt: toBase64Url(randomBytes(SALT_BYTES)),
  };
}

/** A 32-byte key from a password (Argon2id). Unicode is normalised (NFC), so "é" typed either way gives the same key. */
export function passwordKey(password: string, params: PasswordParams): Bytes {
  const { alg, ops, mem } = params;
  if (alg !== "argon2id13") throw new CryptoError("unsupported password algorithm");
  if (!Number.isInteger(ops) || ops < PASSWORD_LIMITS.minOps || ops > PASSWORD_LIMITS.maxOps) {
    throw new CryptoError("password cost out of range");
  }
  if (!Number.isInteger(mem) || mem < PASSWORD_LIMITS.minMem || mem > PASSWORD_LIMITS.maxMem) {
    throw new CryptoError("password memory out of range");
  }
  let salt: Bytes;
  try {
    salt = fromBase64Url(params.salt);
  } catch {
    throw new CryptoError("invalid salt");
  }
  if (salt.length !== SALT_BYTES) throw new CryptoError("invalid salt");
  const s = sodium();
  return s.crypto_pwhash(32, utf8(password.normalize("NFC")), salt, ops, mem, s.crypto_pwhash_ALG_ARGON2ID13);
}

/** The BIP39 English list (2048 words): recovery phrases, and passphrases made up for people. */
export const BIP39_WORDS: readonly string[] = wordlist;

/** A new recovery phrase: 24 BIP39 words, 256 bits. */
export const recoveryPhrase = (): string[] => generateMnemonic(wordlist, 256).split(" ");

/** The 32 bytes behind a recovery phrase, as typed (any spacing or case). Throws on a wrong word or checksum. */
export function recoveryPhraseEntropy(phrase: string[] | string): Bytes {
  const words = (Array.isArray(phrase) ? phrase.join(" ") : phrase).toLowerCase().split(/\s+/).filter(Boolean);
  if (words.length !== 24) throw new CryptoError("a recovery phrase has 24 words");
  try {
    return mnemonicToEntropy(words.join(" "), wordlist);
  } catch {
    throw new CryptoError("invalid recovery phrase");
  }
}
