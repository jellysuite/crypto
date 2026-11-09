import { fromBase64Url, sha256, sign, toBase64Url, verify } from "@jelly/crypto";
import type { UnlockedAccount } from "./account.ts";
import { lengthPrefixed } from "./grants.ts";
import { SIG } from "./tags.ts";
import type { B64 } from "./wire.ts";

/** The fields a comment's author signs (docs/superpowers/specs/2026-11-09-pages-comments-design.md §3). */
export type CommentSigned = {
  nodeId: string;
  id: string;
  keyVersion: number;
  threadRoot: string | null;
  envelope: B64 | null;
  signature: B64 | null;
};

const payload = (f: Omit<CommentSigned, "envelope" | "signature">, envelope: B64) =>
  lengthPrefixed([
    f.nodeId,
    f.id,
    String(f.keyVersion),
    f.threadRoot ?? "",
    toBase64Url(sha256(fromBase64Url(envelope))),
  ]);

/** The author's signature over the comment's page, id, key version, thread and envelope. */
export function signComment(
  author: Pick<UnlockedAccount, "signing">,
  f: Omit<CommentSigned, "envelope" | "signature"> & { envelope: B64 },
): B64 {
  return toBase64Url(sign(author.signing.privateKey, SIG.pageComment, payload(f, f.envelope)));
}

/**
 * Whether the comment carries its author's signature. Needs no node key, so the server checks it too. False
 * (never a throw) for a deleted comment or malformed input.
 */
export function verifyCommentSignature(c: CommentSigned, authorSignPub: B64): boolean {
  if (c.envelope === null || c.signature === null) return false;
  try {
    return verify(fromBase64Url(authorSignPub), SIG.pageComment, payload(c, c.envelope), fromBase64Url(c.signature));
  } catch {
    return false;
  }
}
