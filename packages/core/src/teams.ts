import {
  type Bytes,
  derive,
  encryptionKeyPairFromSeed,
  encryptionPublicFromPrivate,
  fromBase64Url,
  fromUtf8,
  generateEncryptionKeyPair,
  generateSigningKeyPair,
  type KeyPair,
  openJson,
  openSealed,
  randomBytes,
  safetyPhrase,
  sealJson,
  sealTo,
  sign,
  signingKeyPairFromSeed,
  signingPublicFromPrivate,
  toBase64Url,
  utf8,
  verify,
} from "@jelly/crypto";
import type { UnlockedAccount } from "./account.ts";
import { lengthPrefixed } from "./grants.ts";
import { KDF, SIG, TAG } from "./tags.ts";
import type { B64, Role } from "./wire.ts";

const b64 = toBase64Url;
const unb64 = fromBase64Url;

const checkSig = (pub: B64, context: string, payload: () => Bytes, signature: () => B64): boolean => {
  try {
    return verify(unb64(pub), context, payload(), unb64(signature()));
  } catch {
    return false;
  }
};

// ---- Team signing key chain ----

export type TeamKeyLink = { teamId: string; version: number; signPub: B64; prevSignature: B64 | null };
export type TeamSigner = { teamId: string; version: number; signing: KeyPair };

const linkPayload = (l: Pick<TeamKeyLink, "teamId" | "version" | "signPub">): Bytes =>
  lengthPrefixed([l.teamId, String(l.version), l.signPub]);

export function createTeamKey(teamId: string): { link: TeamKeyLink; signer: TeamSigner } {
  const signing = generateSigningKeyPair();
  return {
    link: { teamId, version: 1, signPub: b64(signing.publicKey), prevSignature: null },
    signer: { teamId, version: 1, signing },
  };
}

export function nextTeamKey(prev: TeamSigner): { link: TeamKeyLink; signer: TeamSigner } {
  const signing = generateSigningKeyPair();
  const link = { teamId: prev.teamId, version: prev.version + 1, signPub: b64(signing.publicKey) };
  return {
    link: { ...link, prevSignature: b64(sign(prev.signing.privateKey, SIG.teamKey, linkPayload(link))) },
    signer: { teamId: prev.teamId, version: link.version, signing },
  };
}

/** From a pinned (version, signPub), follows signed links to the newest; null on any break, fork or foreign link. */
export function verifyTeamChain(
  teamId: string,
  pinned: { version: number; signPub: B64 },
  links: TeamKeyLink[],
): TeamKeyLink | null {
  try {
    const byVersion = new Map<number, TeamKeyLink>();
    for (const l of links) {
      if (l.teamId !== teamId || byVersion.has(l.version)) return null;
      byVersion.set(l.version, l);
    }
    let current = byVersion.get(pinned.version);
    if (!current || current.signPub !== pinned.signPub) return null;
    for (let next = byVersion.get(current.version + 1); next; next = byVersion.get(current.version + 1)) {
      const sig = next.prevSignature;
      if (!sig) return null;
      if (
        !checkSig(
          current.signPub,
          SIG.teamKey,
          () => linkPayload(next),
          () => sig,
        )
      )
        return null;
      current = next;
    }
    // A newer link that the chain did not reach is a gap, not something to ignore.
    const reached = current.version;
    return links.some((l) => l.version > reached) ? null : current;
  } catch {
    return null;
  }
}

export function sealTeamSigner(s: TeamSigner, toEncPub: B64): B64 {
  const payload = {
    t: TAG.teamSigner,
    teamId: s.teamId,
    version: s.version,
    priv: b64(s.signing.privateKey),
    pub: b64(s.signing.publicKey),
  };
  return b64(sealTo(unb64(toEncPub), utf8(JSON.stringify(payload))));
}

export function openTeamSigner(
  account: UnlockedAccount,
  teamId: string,
  version: number,
  sealed: B64,
  expectedSignPub: B64,
): TeamSigner {
  const p = JSON.parse(fromUtf8(openSealed(account.encryption, unb64(sealed)))) as Record<string, unknown>;
  if (p.t !== TAG.teamSigner || p.teamId !== teamId || p.version !== version) throw new Error("sealed signer mismatch");
  const privateKey = unb64(String(p.priv));
  const publicKey = unb64(String(p.pub));
  if (b64(signingPublicFromPrivate(privateKey)) !== b64(publicKey) || b64(publicKey) !== expectedSignPub)
    throw new Error("sealed signer key mismatch");
  return { teamId, version, signing: { publicKey, privateKey } };
}

export const teamSafetyWords = (signPub: B64): string[] => safetyPhrase(unb64(signPub));

// ---- Groups ----

export type GroupVersion = {
  teamId: string;
  groupId: string;
  version: number;
  encPub: B64;
  teamKeyVersion: number;
  signature: B64;
};

const groupVersionPayload = (g: Omit<GroupVersion, "signature">): Bytes =>
  lengthPrefixed([g.teamId, g.groupId, String(g.version), g.encPub, String(g.teamKeyVersion)]);

export function createGroupVersion(
  team: TeamSigner,
  groupId: string,
  version: number,
): { wire: GroupVersion; keyPair: KeyPair } {
  const keyPair = generateEncryptionKeyPair();
  const unsigned = {
    teamId: team.teamId,
    groupId,
    version,
    encPub: b64(keyPair.publicKey),
    teamKeyVersion: team.version,
  };
  const signature = b64(sign(team.signing.privateKey, SIG.groupKey, groupVersionPayload(unsigned)));
  return { wire: { ...unsigned, signature }, keyPair };
}

export function verifyGroupVersion(g: GroupVersion, teamKeyVersion: number, teamSignPub: B64): boolean {
  try {
    return (
      g.teamKeyVersion === teamKeyVersion &&
      checkSig(
        teamSignPub,
        SIG.groupKey,
        () => groupVersionPayload(g),
        () => g.signature,
      )
    );
  } catch {
    return false;
  }
}

/** Same group key, signed again under the team's new key (after the team key rotates). */
export function resignGroupVersion(team: TeamSigner, g: GroupVersion): GroupVersion {
  const unsigned = {
    teamId: g.teamId,
    groupId: g.groupId,
    version: g.version,
    encPub: g.encPub,
    teamKeyVersion: team.version,
  };
  return { ...unsigned, signature: b64(sign(team.signing.privateKey, SIG.groupKey, groupVersionPayload(unsigned))) };
}

export function sealGroupKey(keyPair: KeyPair, toEncPub: B64, group: GroupVersion): B64 {
  const payload = {
    t: TAG.groupKey,
    teamId: group.teamId,
    groupId: group.groupId,
    version: group.version,
    priv: b64(keyPair.privateKey),
    pub: b64(keyPair.publicKey),
  };
  return b64(sealTo(unb64(toEncPub), utf8(JSON.stringify(payload))));
}

export function openGroupKey(account: { encryption: KeyPair }, sealed: B64, group: GroupVersion): KeyPair {
  const p = JSON.parse(fromUtf8(openSealed(account.encryption, unb64(sealed)))) as Record<string, unknown>;
  if (
    p.t !== TAG.groupKey ||
    p.teamId !== group.teamId ||
    p.groupId !== group.groupId ||
    p.version !== group.version ||
    p.pub !== group.encPub
  )
    throw new Error("sealed group key mismatch");
  const privateKey = unb64(String(p.priv));
  const publicKey = unb64(String(p.pub));
  if (b64(encryptionPublicFromPrivate(privateKey)) !== b64(publicKey)) throw new Error("sealed group key mismatch");
  return { publicKey, privateKey };
}

export type GroupStatement = {
  teamId: string;
  groupId: string;
  groupVersion: number;
  userId: string;
  userSignPub: B64;
  teamKeyVersion: number;
  signature: B64;
};

const statementPayload = (s: Omit<GroupStatement, "signature">): Bytes =>
  lengthPrefixed([s.teamId, s.groupId, String(s.groupVersion), s.userId, s.userSignPub, String(s.teamKeyVersion)]);

export function createGroupStatement(
  team: TeamSigner,
  a: { groupId: string; groupVersion: number; userId: string; userSignPub: B64 },
): GroupStatement {
  const unsigned = { teamId: team.teamId, ...a, teamKeyVersion: team.version };
  return { ...unsigned, signature: b64(sign(team.signing.privateKey, SIG.groupMember, statementPayload(unsigned))) };
}

export const verifyGroupStatement = (s: GroupStatement, teamSignPub: B64): boolean =>
  checkSig(
    teamSignPub,
    SIG.groupMember,
    () => statementPayload(s),
    () => s.signature,
  );

// ---- Group grants ----

export type GroupGrant = {
  nodeId: string;
  keyVersion: number;
  groupId: string;
  groupVersion: number;
  grantorId: string;
  role: Role;
  sealedKey: B64;
  signature: B64;
};

const groupGrantPayload = (g: Omit<GroupGrant, "signature">): Bytes =>
  lengthPrefixed([g.nodeId, String(g.keyVersion), g.groupId, String(g.groupVersion), g.grantorId, g.role, g.sealedKey]);

export function createGroupGrant(
  grantor: UnlockedAccount,
  a: { nodeId: string; keyVersion: number; nodeKey: Bytes; group: GroupVersion; role: Role },
): GroupGrant {
  const unsigned = {
    nodeId: a.nodeId,
    keyVersion: a.keyVersion,
    groupId: a.group.groupId,
    groupVersion: a.group.version,
    grantorId: grantor.userId,
    role: a.role,
    sealedKey: b64(sealTo(unb64(a.group.encPub), a.nodeKey)),
  };
  return {
    ...unsigned,
    signature: b64(sign(grantor.signing.privateKey, SIG.groupGrant, groupGrantPayload(unsigned))),
  };
}

export const verifyGroupGrant = (g: GroupGrant, grantorSignPub: B64): boolean =>
  checkSig(
    grantorSignPub,
    SIG.groupGrant,
    () => groupGrantPayload(g),
    () => g.signature,
  );

export const openGroupGrant = (groupKey: KeyPair, g: GroupGrant): Bytes => openSealed(groupKey, unb64(g.sealedKey));

// ---- Invites ----

export type InviteStatement = {
  inviteId: string;
  teamId: string;
  kind: "managed" | "joined";
  handle: string;
  /** groupId to the group version the invite was made for. */
  groupVersions: Record<string, number>;
  invitePub: B64 | null;
  inviteSignPub: B64 | null;
  teamKeyVersion: number;
  signature: B64;
};

const optional = (v: string | null): string[] => (v === null ? ["0"] : ["1", v]);

const groupVersionFields = (gv: Record<string, number>): string[] => {
  const entries = Object.entries(gv).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return [String(entries.length), ...entries.flatMap(([id, v]) => [id, String(v)])];
};

const invitePayload = (s: Omit<InviteStatement, "signature">): Bytes =>
  lengthPrefixed([
    s.inviteId,
    s.teamId,
    s.kind,
    s.handle,
    ...groupVersionFields(s.groupVersions),
    ...optional(s.invitePub),
    ...optional(s.inviteSignPub),
    String(s.teamKeyVersion),
  ]);

export const newInviteSecret = (): Bytes => randomBytes(32);
export const inviteKeyPair = (secret: Bytes): KeyPair => encryptionKeyPairFromSeed(derive(secret, KDF.inviteKey));
export const inviteSigningKeyPair = (secret: Bytes): KeyPair => signingKeyPairFromSeed(derive(secret, KDF.inviteSign));
export const inviteAuth = (secret: Bytes): B64 => b64(derive(secret, KDF.inviteAuth));

export function createInviteStatement(
  team: TeamSigner,
  a: Omit<InviteStatement, "teamKeyVersion" | "signature" | "teamId">,
): InviteStatement {
  const unsigned = { ...a, teamId: team.teamId, teamKeyVersion: team.version };
  return { ...unsigned, signature: b64(sign(team.signing.privateKey, SIG.teamInvite, invitePayload(unsigned))) };
}

export const verifyInviteStatement = (s: InviteStatement, teamSignPub: B64): boolean =>
  checkSig(
    teamSignPub,
    SIG.teamInvite,
    () => invitePayload(s),
    () => s.signature,
  );

export type InviteAcceptance = { inviteId: string; userId: string; userSignPub: B64; signature: B64 };

const acceptancePayload = (a: Omit<InviteAcceptance, "signature">): Bytes =>
  lengthPrefixed([a.inviteId, a.userId, a.userSignPub]);

export function createInviteAcceptance(
  secret: Bytes,
  a: { inviteId: string; userId: string; userSignPub: B64 },
): InviteAcceptance {
  const signature = b64(sign(inviteSigningKeyPair(secret).privateKey, SIG.inviteAccept, acceptancePayload(a)));
  return { inviteId: a.inviteId, userId: a.userId, userSignPub: a.userSignPub, signature };
}

export const verifyInviteAcceptance = (a: InviteAcceptance, inviteSignPub: B64): boolean =>
  checkSig(
    inviteSignPub,
    SIG.inviteAccept,
    () => acceptancePayload(a),
    () => a.signature,
  );

/** A member is trusted in a group when a team-signed statement, or a team-signed invite naming the group plus an acceptance, binds their signing key. */
export type MemberProof =
  | { kind: "statement"; statement: GroupStatement }
  | { kind: "invite"; invite: InviteStatement; acceptance: InviteAcceptance };

export function verifyMemberProof(
  p: MemberProof,
  a: {
    teamId: string;
    groupId: string;
    groupVersion: number;
    userId: string;
    userSignPub: B64;
    teamKeyVersion: number;
    teamSignPub: B64;
  },
): boolean {
  try {
    if (p.kind === "statement") {
      const s = p.statement;
      return (
        s.teamKeyVersion === a.teamKeyVersion &&
        s.teamId === a.teamId &&
        s.groupId === a.groupId &&
        s.groupVersion === a.groupVersion &&
        s.userId === a.userId &&
        s.userSignPub === a.userSignPub &&
        verifyGroupStatement(s, a.teamSignPub)
      );
    }
    const { invite, acceptance } = p;
    return (
      !!invite.inviteSignPub &&
      invite.teamKeyVersion === a.teamKeyVersion &&
      invite.teamId === a.teamId &&
      Object.hasOwn(invite.groupVersions, a.groupId) &&
      invite.groupVersions[a.groupId] === a.groupVersion &&
      acceptance.inviteId === invite.inviteId &&
      acceptance.userId === a.userId &&
      acceptance.userSignPub === a.userSignPub &&
      verifyInviteStatement(invite, a.teamSignPub) &&
      verifyInviteAcceptance(acceptance, invite.inviteSignPub)
    );
  } catch {
    return false;
  }
}

// ---- Team and group names ----

/**
 * A proof that `userId` was in `groupId` at some point: it must verify under the team key it names, which
 * `teamKeyAt` gives only for versions the caller verified (null for any other). For someone who has left,
 * whose last proof stays at the versions current when they went.
 */
export function verifyFormerMemberProof(
  p: MemberProof,
  a: { teamId: string; groupId: string; userId: string; userSignPub: B64; teamKeyAt: (version: number) => B64 | null },
): boolean {
  try {
    const teamKeyVersion = p.kind === "statement" ? p.statement.teamKeyVersion : p.invite.teamKeyVersion;
    const groupVersion =
      p.kind === "statement"
        ? p.statement.groupVersion
        : Object.hasOwn(p.invite.groupVersions, a.groupId)
          ? p.invite.groupVersions[a.groupId]
          : undefined;
    const teamSignPub = a.teamKeyAt(teamKeyVersion);
    if (!teamSignPub || typeof groupVersion !== "number") return false;
    return verifyMemberProof(p, { ...a, groupVersion, teamKeyVersion, teamSignPub });
  } catch {
    return false;
  }
}

export type TeamMeta = { name: string };
export type GroupMeta = { name: string };

export const teamMetaKey = (everyone: KeyPair): Bytes => derive(everyone.privateKey, KDF.teamMeta);

const metaAd = (id: string, everyoneVersion: number): Bytes => utf8(`${id}:${everyoneVersion}`);

export const encryptTeamMeta = (key: Bytes, teamId: string, everyoneVersion: number, m: TeamMeta): B64 =>
  b64(sealJson(key, TAG.teamMeta, m, metaAd(teamId, everyoneVersion)));

export const decryptTeamMeta = (key: Bytes, teamId: string, everyoneVersion: number, env: B64): TeamMeta =>
  openJson<TeamMeta>(key, TAG.teamMeta, unb64(env), metaAd(teamId, everyoneVersion));

export const encryptGroupMeta = (key: Bytes, groupId: string, everyoneVersion: number, m: GroupMeta): B64 =>
  b64(sealJson(key, TAG.groupMeta, m, metaAd(groupId, everyoneVersion)));

export const decryptGroupMeta = (key: Bytes, groupId: string, everyoneVersion: number, env: B64): GroupMeta =>
  openJson<GroupMeta>(key, TAG.groupMeta, unb64(env), metaAd(groupId, everyoneVersion));
