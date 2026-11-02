import { type Bytes, fromBase64Url, openSealed, sealTo, sign, toBase64Url, utf8, verify } from "@jelly/crypto";
import { type UnlockedAccount, verifyIdentity } from "./account.ts";
import { SIG } from "./tags.ts";
import type { B64, PublicIdentity, Role } from "./wire.ts";

export type Grant = {
  nodeId: string;
  keyVersion: number;
  granteeId: string;
  grantorId: string;
  role: Role;
  sealedKey: B64;
  signature: B64;
};

/** grant@2: each field length-prefixed, so no value can be read as part of another. */
export const grantPayload = (g: Omit<Grant, "signature">): Bytes =>
  lengthPrefixed([g.nodeId, String(g.keyVersion), g.granteeId, g.grantorId, g.role, g.sealedKey]);

export function lengthPrefixed(fields: string[]): Bytes {
  const parts = fields.map((f) => utf8(f));
  const out = new Uint8Array(parts.reduce((n, p) => n + 4 + p.length, 0));
  const view = new DataView(out.buffer);
  let at = 0;
  for (const p of parts) {
    view.setUint32(at, p.length);
    out.set(p, at + 4);
    at += 4 + p.length;
  }
  return out;
}

export function createGrant(
  grantor: UnlockedAccount,
  a: { nodeId: string; keyVersion: number; nodeKey: Bytes; grantee: PublicIdentity; role: Role },
): Grant {
  if (!verifyIdentity(a.grantee)) throw new Error("grantee identity signature is invalid");
  const unsigned = {
    nodeId: a.nodeId,
    keyVersion: a.keyVersion,
    granteeId: a.grantee.userId,
    grantorId: grantor.userId,
    role: a.role,
    sealedKey: toBase64Url(sealTo(fromBase64Url(a.grantee.encPub), a.nodeKey)),
  };
  return {
    ...unsigned,
    signature: toBase64Url(sign(grantor.signing.privateKey, SIG.grantV2, grantPayload(unsigned))),
  };
}

export function verifyGrant(g: Grant, grantorSignPub: B64): boolean {
  try {
    return verify(fromBase64Url(grantorSignPub), SIG.grantV2, grantPayload(g), fromBase64Url(g.signature));
  } catch {
    return false;
  }
}

export const openGrant = (account: UnlockedAccount, g: Grant): Bytes =>
  openSealed(account.encryption, fromBase64Url(g.sealedKey));
