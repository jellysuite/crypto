import { toBase64Url, utf8 } from "@jelly/crypto";
import { describe, expect, it } from "vitest";
import { createAccount, unlockAccount } from "../src/account.ts";
import { type CommentSigned, signComment, verifyCommentSignature } from "../src/comments.ts";

function user() {
  const acct = createAccount();
  return unlockAccount({ userId: crypto.randomUUID(), handle: "ana", ak: acct.ak, bundle: acct.bundle });
}

const NODE = "00000000-0000-4000-8000-000000000001";
const ID = "00000000-0000-4000-8000-000000000002";
const ROOT = "00000000-0000-4000-8000-000000000003";

describe("comment signatures", () => {
  const ana = user();
  const pub = toBase64Url(ana.signing.publicKey);
  const envelope = toBase64Url(utf8("sealed"));
  const fields = { nodeId: NODE, id: ID, keyVersion: 2, threadRoot: ROOT, envelope };
  const signed: CommentSigned = { ...fields, signature: signComment(ana, fields) };

  it("verifies its author's signature over page, id, key version, thread and envelope", () => {
    expect(verifyCommentSignature(signed, pub)).toBe(true);
  });
  it("fails for anything moved or changed", () => {
    for (const bad of [
      { nodeId: ROOT },
      { id: ROOT },
      { keyVersion: 3 },
      { threadRoot: null },
      { envelope: toBase64Url(utf8("other")) },
    ]) {
      expect(verifyCommentSignature({ ...signed, ...bad }, pub)).toBe(false);
    }
  });
  it("fails for someone else's key, a deleted comment or garbage, without throwing", () => {
    expect(verifyCommentSignature(signed, toBase64Url(user().signing.publicKey))).toBe(false);
    expect(verifyCommentSignature({ ...signed, envelope: null, signature: null }, pub)).toBe(false);
    expect(verifyCommentSignature({ ...signed, signature: "!!" }, pub)).toBe(false);
  });
});
