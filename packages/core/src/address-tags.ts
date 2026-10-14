// Addresses remembered in the encrypted private settings (contact suggestions you dismissed, prompts already
// shown) are kept as keyed tags, not as addresses: the settings blob is encrypted anyway, but a list of tags can't
// be read back as the people you write to, by anyone who later gets hold of the decrypted settings or a debug dump.
import { type Bytes, derive, toBase64Url } from "@jelly/crypto";
import { KDF } from "./tags.ts";

/** The account's key for address tags: a subkey of the account key (BLAKE2b keyed, its own context). */
export const suggestionKey = (ak: Bytes): Bytes => derive(ak, KDF.contactSuggestions);

/** How an address is compared: trimmed, without "mailto:", NFC, lower case. */
const normalise = (address: string) =>
  address
    .trim()
    .replace(/^mailto:/i, "")
    .normalize("NFC")
    .toLowerCase();

/** A 128-bit keyed BLAKE2b tag of an address (base64url, 22 characters): the same address, the same tag. */
export function addressTag(key: Bytes, address: string): string {
  return toBase64Url(derive(key, `address:${normalise(address)}`).subarray(0, 16));
}
