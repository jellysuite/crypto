import { type Bytes, fromBase64Url, openSealed, sealTo, sign, toBase64Url, utf8, verify } from "@jelly/crypto";
import { type UnlockedAccount, verifyIdentity } from "./account.ts";
import { SIG } from "./tags.ts";
import { atLeast, type B64, type PublicIdentity, type Role } from "./wire.ts";

/**
 * Says who let a person (with exactly this signing key) in at a role. Unlike the grant, which whoever
 * re-keys the node re-signs, it stays as made, so it keeps naming the person who authorised the share.
 */
export type Membership = { grantorId: string; granteeSignPub: B64; signature: B64 };

export type Grant = {
  nodeId: string;
  keyVersion: number;
  granteeId: string;
  grantorId: string;
  role: Role;
  sealedKey: B64;
  signature: B64;
  /** Null on grants made before membership statements existed (never trusted for re-sharing keys). */
  member?: Membership | null;
};

/** grant@2: each field length-prefixed, so no value can be read as part of another. */
export const grantPayload = (g: Omit<Grant, "signature">): Bytes =>
  lengthPrefixed([g.nodeId, String(g.keyVersion), g.granteeId, g.grantorId, g.role, g.sealedKey]);

/** The original format. Unambiguous only while every field is well-formed (checked before verifying). */
export const legacyGrantPayload = (g: Omit<Grant, "signature">): Bytes =>
  utf8([g.nodeId, g.keyVersion, g.granteeId, g.grantorId, g.role, g.sealedKey].join("|"));

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

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const B64URL = /^[A-Za-z0-9_-]+$/;

/** Whether every field has the shape the server would store (ids, version, role, base64url). */
export function wellFormedGrant(g: Grant): boolean {
  return (
    [g.nodeId, g.granteeId, g.grantorId].every((id) => typeof id === "string" && UUID.test(id)) &&
    Number.isSafeInteger(g.keyVersion) &&
    g.keyVersion > 0 &&
    (g.role === "viewer" || g.role === "editor" || g.role === "owner") &&
    typeof g.sealedKey === "string" &&
    B64URL.test(g.sealedKey) &&
    typeof g.signature === "string" &&
    B64URL.test(g.signature)
  );
}

type MemberFields = Pick<Grant, "nodeId" | "granteeId" | "role">;

const memberPayload = (g: MemberFields, grantorId: string, granteeSignPub: B64): Bytes =>
  lengthPrefixed([g.nodeId, g.granteeId, granteeSignPub, g.role, grantorId]);

export function createMembership(
  grantor: UnlockedAccount,
  a: { nodeId: string; grantee: PublicIdentity; role: Role },
): Membership {
  const fields = { nodeId: a.nodeId, granteeId: a.grantee.userId, role: a.role };
  const payload = memberPayload(fields, grantor.userId, a.grantee.signPub);
  return {
    grantorId: grantor.userId,
    granteeSignPub: a.grantee.signPub,
    signature: toBase64Url(sign(grantor.signing.privateKey, SIG.member, payload)),
  };
}

export function verifyMembership(g: MemberFields, m: Membership, grantorSignPub: B64): boolean {
  try {
    return verify(
      fromBase64Url(grantorSignPub),
      SIG.member,
      memberPayload(g, m.grantorId, m.granteeSignPub),
      fromBase64Url(m.signature),
    );
  } catch {
    return false;
  }
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
    member: createMembership(grantor, { nodeId: a.nodeId, grantee: a.grantee, role: a.role }),
  };
}

export function verifyGrant(g: Grant, grantorSignPub: B64): boolean {
  try {
    const pub = fromBase64Url(grantorSignPub);
    const sig = fromBase64Url(g.signature);
    if (verify(pub, SIG.grantV2, grantPayload(g), sig)) return true;
    return wellFormedGrant(g) && verify(pub, SIG.grant, legacyGrantPayload(g), sig);
  } catch {
    return false;
  }
}

export const openGrant = (account: UnlockedAccount, g: Grant): Bytes =>
  openSealed(account.encryption, fromBase64Url(g.sealedKey));

/**
 * Which of a node's shares are backed by people who hold the key, before re-sharing a new key with them.
 * `chain` is the node then its ancestors (nearest first, depth = index); `entries` are shares on any of them;
 * `anchors` are the people this client knows hold a key on the chain from its own cryptography (itself, the
 * grantor of a grant that opened a key here, a member the team key vouches for), each with owner-level
 * authority at its `depth` and below. Trusting someone's key (a pin) is not authority on an item.
 *
 * A statement counts when it's signed by someone with authority at its depth or above, at the role it hands
 * out (editor for viewer/editor shares, owner for owner shares): an anchor, or someone a counted statement on
 * the same node or an ancestor made an editor (an owner, for handing out ownership). Shares on the node itself
 * are verified when their statement counts and names the identity's own signing key; the rest (legacy grants,
 * people the server added or whose key it swapped) are returned as unverified.
 */
export function verifyShares(opts: {
  chain: string[];
  entries: Array<{ grant: Grant; identity: PublicIdentity }>;
  anchors: Map<string, { signPub: B64; depth: number }>;
}): {
  verified: Array<{ grant: Grant; identity: PublicIdentity }>;
  unverified: PublicIdentity[];
  /** Everyone who may vouch on the chain: the anchors, and editors/owners counted statements made. */
  authority: Array<{ userId: string; signPub: B64; role: Role; depth: number }>;
} {
  const depthOf = new Map(opts.chain.map((id, i) => [id, i]));
  const nodeId = opts.chain[0];
  // Who may vouch, with which key and role, at which depth (and everything below it).
  const authority: Array<{ userId: string; signPub: B64; role: Role; depth: number }> = [
    ...[...opts.anchors].map(([userId, a]) => ({ userId, signPub: a.signPub, role: "owner" as Role, depth: a.depth })),
  ];
  const counted = new Set<number>();
  const vouched = (g: Grant, m: Membership, depth: number): boolean => {
    const needs: Role = g.role === "owner" ? "owner" : "editor";
    return authority.some(
      (a) =>
        a.userId === m.grantorId && a.depth >= depth && atLeast(a.role, needs) && verifyMembership(g, m, a.signPub),
    );
  };
  for (let changed = true; changed; ) {
    changed = false;
    opts.entries.forEach(({ grant: g }, i) => {
      const depth = depthOf.get(g.nodeId);
      if (counted.has(i) || depth === undefined || !g.member || !vouched(g, g.member, depth)) return;
      counted.add(i);
      changed = true;
      if (atLeast(g.role, "editor"))
        authority.push({ userId: g.granteeId, signPub: g.member.granteeSignPub, role: g.role, depth });
    });
  }
  const verified: Array<{ grant: Grant; identity: PublicIdentity }> = [];
  const unverified: PublicIdentity[] = [];
  opts.entries.forEach((e, i) => {
    if (e.grant.nodeId !== nodeId) return;
    const ok =
      counted.has(i) &&
      e.identity.userId === e.grant.granteeId &&
      e.identity.signPub === e.grant.member?.granteeSignPub &&
      verifyIdentity(e.identity);
    if (ok) verified.push(e);
    else unverified.push(e.identity);
  });
  return { verified, unverified, authority };
}
