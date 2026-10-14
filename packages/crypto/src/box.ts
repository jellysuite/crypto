import type { Bytes } from "./encoding.ts";
import { CryptoError } from "./errors.ts";
import type { KeyPair } from "./sign.ts";
import { sodium } from "./sodium.ts";

export function generateEncryptionKeyPair(): KeyPair {
  const { publicKey, privateKey } = sodium().crypto_box_keypair();
  return { publicKey, privateKey };
}

export function encryptionKeyPairFromSeed(seed: Bytes): KeyPair {
  const { publicKey, privateKey } = sodium().crypto_box_seed_keypair(seed);
  return { publicKey, privateKey };
}

export const encryptionPublicFromPrivate = (privateKey: Bytes): Bytes => sodium().crypto_scalarmult_base(privateKey);

/** Anonymous encryption to an X25519 public key. Pair with a signature when the sender matters. */
export function sealTo(publicKey: Bytes, plaintext: Bytes): Bytes {
  return sodium().crypto_box_seal(plaintext, publicKey);
}

export function openSealed(keyPair: KeyPair, ciphertext: Bytes): Bytes {
  try {
    return sodium().crypto_box_seal_open(ciphertext, keyPair.publicKey, keyPair.privateKey);
  } catch {
    throw new CryptoError("could not open sealed box");
  }
}
