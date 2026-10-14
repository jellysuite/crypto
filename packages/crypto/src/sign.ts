import { type Bytes, concatBytes, utf8 } from "./encoding.ts";
import { sodium } from "./sodium.ts";

export type KeyPair = { publicKey: Bytes; privateKey: Bytes };

const message = (context: string, payload: Bytes) =>
  concatBytes(utf8(`jelly-sig:${context}`), Uint8Array.of(0), payload);

export function generateSigningKeyPair(): KeyPair {
  const { publicKey, privateKey } = sodium().crypto_sign_keypair();
  return { publicKey, privateKey };
}

export function signingKeyPairFromSeed(seed: Bytes): KeyPair {
  const { publicKey, privateKey } = sodium().crypto_sign_seed_keypair(seed);
  return { publicKey, privateKey };
}

/** Recomputed from the seed half: libsodium's sk_to_pk only copies the public half stored in the secret key. */
export const signingPublicFromPrivate = (privateKey: Bytes): Bytes =>
  sodium().crypto_sign_seed_keypair(sodium().crypto_sign_ed25519_sk_to_seed(privateKey)).publicKey;

export function sign(privateKey: Bytes, context: string, payload: Bytes): Bytes {
  return sodium().crypto_sign_detached(message(context, payload), privateKey);
}

export function verify(publicKey: Bytes, context: string, payload: Bytes, signature: Bytes): boolean {
  try {
    return sodium().crypto_sign_verify_detached(signature, message(context, payload), publicKey);
  } catch {
    return false;
  }
}
