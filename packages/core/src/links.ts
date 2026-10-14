import {
  type Bytes,
  CryptoError,
  derive,
  fromBase64Url,
  generateKey,
  open,
  seal,
  sha256,
  toBase64Url,
  utf8,
} from "@jelly/crypto";
import { KDF, TAG } from "./tags.ts";
import type { B64 } from "./wire.ts";

export const newLinkSecret = (): Bytes => generateKey();

export const encodeLinkFragment = (secret: Bytes): string => toBase64Url(secret);

export function decodeLinkFragment(fragment: string): Bytes | null {
  try {
    const b = fromBase64Url(fragment);
    return b.length === 32 ? b : null;
  } catch (e) {
    if (e instanceof CryptoError) return null;
    throw e;
  }
}

export const linkAuth = (secret: Bytes): B64 => toBase64Url(derive(secret, KDF.linkAuth));
export const linkAuthHash = (auth: B64): B64 => toBase64Url(sha256(fromBase64Url(auth)));

const linkNodeAd = (linkId: string, nodeId: string, keyVersion: number) => utf8(`${linkId}>${nodeId}:${keyVersion}`);

export const wrapNodeKeyForLink = (
  secret: Bytes,
  linkId: string,
  nodeId: string,
  keyVersion: number,
  nodeKey: Bytes,
): B64 =>
  toBase64Url(seal(derive(secret, KDF.linkWrap), TAG.linkNodeKey, nodeKey, linkNodeAd(linkId, nodeId, keyVersion)));

export const unwrapNodeKeyForLink = (
  secret: Bytes,
  linkId: string,
  nodeId: string,
  keyVersion: number,
  wrapped: B64,
): Bytes =>
  open(derive(secret, KDF.linkWrap), TAG.linkNodeKey, fromBase64Url(wrapped), linkNodeAd(linkId, nodeId, keyVersion));

export const wrapLinkSecret = (nodeKey: Bytes, linkId: string, secret: Bytes): B64 =>
  toBase64Url(seal(nodeKey, TAG.linkSecret, secret, utf8(linkId)));

export const unwrapLinkSecret = (nodeKey: Bytes, linkId: string, wrapped: B64): Bytes =>
  open(nodeKey, TAG.linkSecret, fromBase64Url(wrapped), utf8(linkId));
