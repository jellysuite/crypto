import { fromBase64Url, ready, toBase64Url } from "@jelly/crypto";
import { beforeAll, describe, expect, it } from "vitest";
import { createAccount, unlockAccount } from "../src/account.ts";
import { newNodeKey } from "../src/nodes.ts";
import * as T from "../src/teams.ts";

beforeAll(ready);
const user = (handle: string) => {
  const a = createAccount();
  return unlockAccount({ userId: crypto.randomUUID(), handle, ak: a.ak, bundle: a.bundle });
};
const encPub = (u: ReturnType<typeof user>) => toBase64Url(u.encryption.publicKey);
const signPub = (u: ReturnType<typeof user>) => toBase64Url(u.signing.publicKey);

describe("team key chain", () => {
  it("follows signed links from the pinned key and rejects a broken or forged link", () => {
    const teamId = crypto.randomUUID();
    const v1 = T.createTeamKey(teamId);
    const v2 = T.nextTeamKey(v1.signer);
    const v3 = T.nextTeamKey(v2.signer);
    const pinned = { version: 1, signPub: v1.link.signPub };
    expect(T.verifyTeamChain(teamId, pinned, [v1.link, v2.link, v3.link])?.version).toBe(3);
    const evil = T.createTeamKey(teamId);
    expect(
      T.verifyTeamChain(teamId, pinned, [v1.link, { ...evil.link, version: 2, prevSignature: v2.link.prevSignature }]),
    ).toBeNull();
    expect(T.verifyTeamChain(teamId, pinned, [v1.link, v3.link])).toBeNull(); // gap
    expect(T.verifyTeamChain(teamId, { version: 1, signPub: evil.link.signPub }, [v1.link, v2.link])).toBeNull();
    expect(
      T.verifyTeamChain(teamId, { version: 2, signPub: v2.link.signPub }, [v1.link, v2.link, v3.link])?.version,
    ).toBe(3);
  });
  it("seals the signer to an admin, bound to team and version", () => {
    const alice = user("alice");
    const { signer } = T.createTeamKey(crypto.randomUUID());
    const sealed = T.sealTeamSigner(signer, encPub(alice));
    expect(
      toBase64Url(
        T.openTeamSigner(alice, signer.teamId, 1, sealed, toBase64Url(signer.signing.publicKey)).signing.publicKey,
      ),
    ).toBe(toBase64Url(signer.signing.publicKey));
    expect(() => T.openTeamSigner(alice, signer.teamId, 2, sealed, toBase64Url(signer.signing.publicKey))).toThrow();
    expect(() =>
      T.openTeamSigner(alice, crypto.randomUUID(), 1, sealed, toBase64Url(signer.signing.publicKey)),
    ).toThrow();
  });
  it("rejects a sealed signer whose key is consistent but not the chain's", () => {
    const alice = user("alice");
    const teamId = crypto.randomUUID();
    const real = T.createTeamKey(teamId).signer;
    const evil = T.createTeamKey(teamId).signer;
    const sealed = T.sealTeamSigner(evil, encPub(alice));
    expect(() => T.openTeamSigner(alice, teamId, 1, sealed, toBase64Url(real.signing.publicKey))).toThrow();
  });
  it("rejects a sealed signer whose private key does not belong to its public key", () => {
    const alice = user("alice");
    const teamId = crypto.randomUUID();
    const a = T.createTeamKey(teamId).signer;
    const b = T.createTeamKey(teamId).signer;
    const crafted = {
      ...a,
      signing: {
        publicKey: b.signing.publicKey,
        privateKey: new Uint8Array([...a.signing.privateKey.slice(0, 32), ...b.signing.publicKey]),
      },
    };
    const sealed = T.sealTeamSigner(crafted, encPub(alice));
    expect(() => T.openTeamSigner(alice, teamId, 1, sealed, toBase64Url(b.signing.publicKey))).toThrow();
  });
  it("rejects a duplicate version, a foreign team and a missing pin", () => {
    const teamId = crypto.randomUUID();
    const v1 = T.createTeamKey(teamId);
    const v2 = T.nextTeamKey(v1.signer);
    const v2b = T.nextTeamKey(v1.signer);
    const pinned = { version: 1, signPub: v1.link.signPub };
    expect(T.verifyTeamChain(teamId, pinned, [v1.link, v2.link, v2b.link])).toBeNull();
    expect(T.verifyTeamChain(crypto.randomUUID(), pinned, [v1.link, v2.link])).toBeNull();
    expect(T.verifyTeamChain(teamId, pinned, [v2.link])).toBeNull();
    expect(T.verifyTeamChain(teamId, pinned, null as never)).toBeNull();
  });
  it("gives twelve safety words", () => {
    expect(T.teamSafetyWords(T.createTeamKey(crypto.randomUUID()).link.signPub)).toHaveLength(12);
  });
});

describe("groups", () => {
  it("group versions are team-signed; keys open only for the right group/version", () => {
    const alice = user("alice");
    const { signer, link } = T.createTeamKey(crypto.randomUUID());
    const g = T.createGroupVersion(signer, crypto.randomUUID(), 1);
    expect(T.verifyGroupVersion(g.wire, 1, link.signPub)).toBe(true);
    expect(T.verifyGroupVersion({ ...g.wire, version: 2 }, 1, link.signPub)).toBe(false);
    expect(T.verifyGroupVersion(g.wire, 2, link.signPub)).toBe(false);
    const sealed = T.sealGroupKey(g.keyPair, encPub(alice), g.wire);
    expect(toBase64Url(T.openGroupKey(alice, sealed, g.wire).publicKey)).toBe(g.wire.encPub);
    const other = T.createGroupVersion(signer, crypto.randomUUID(), 1);
    expect(() => T.openGroupKey(alice, sealed, other.wire)).toThrow();
    expect(() => T.openGroupKey(alice, sealed, { ...g.wire, version: 2 })).toThrow();
  });
  it("a group version re-signed under a rotated team key verifies at the new version only", () => {
    const { signer, link } = T.createTeamKey(crypto.randomUUID());
    const g = T.createGroupVersion(signer, crypto.randomUUID(), 1);
    const next = T.nextTeamKey(signer);
    const re = T.resignGroupVersion(next.signer, g.wire);
    expect(re.encPub).toBe(g.wire.encPub);
    expect(T.verifyGroupVersion(re, 2, next.link.signPub)).toBe(true);
    expect(T.verifyGroupVersion(re, 1, link.signPub)).toBe(false);
  });
  it("statements bind the user's signing key; a swapped key fails", () => {
    const bob = user("bob");
    const carol = user("carol");
    const { signer, link } = T.createTeamKey(crypto.randomUUID());
    const groupId = crypto.randomUUID();
    const s = T.createGroupStatement(signer, {
      groupId,
      groupVersion: 1,
      userId: bob.userId,
      userSignPub: signPub(bob),
    });
    expect(T.verifyGroupStatement(s, link.signPub)).toBe(true);
    expect(T.verifyGroupStatement({ ...s, userSignPub: signPub(carol) }, link.signPub)).toBe(false);
    expect(T.verifyGroupStatement({ ...s, groupVersion: 2 }, link.signPub)).toBe(false);
  });
  it("group grants seal a node key to the group and are signed by the grantor", () => {
    const alice = user("alice");
    const { signer } = T.createTeamKey(crypto.randomUUID());
    const g = T.createGroupVersion(signer, crypto.randomUUID(), 1);
    const nodeKey = newNodeKey();
    const gg = T.createGroupGrant(alice, {
      nodeId: crypto.randomUUID(),
      keyVersion: 1,
      nodeKey,
      group: g.wire,
      role: "editor",
    });
    expect(T.verifyGroupGrant(gg, signPub(alice))).toBe(true);
    expect(T.verifyGroupGrant({ ...gg, role: "owner" }, signPub(alice))).toBe(false);
    expect(toBase64Url(T.openGroupGrant(g.keyPair, gg))).toBe(toBase64Url(nodeKey));
  });
});

describe("invites and member proofs", () => {
  const setup = () => {
    const bob = user("bob");
    const { signer, link } = T.createTeamKey(crypto.randomUUID());
    const groupId = crypto.randomUUID();
    const secret = T.newInviteSecret();
    const mk = (over: Partial<T.InviteStatement> = {}) =>
      T.createInviteStatement(signer, {
        inviteId: crypto.randomUUID(),
        kind: "managed",
        handle: "bob@acme.test",
        groupVersions: { [groupId]: 1 },
        invitePub: toBase64Url(T.inviteKeyPair(secret).publicKey),
        inviteSignPub: toBase64Url(T.inviteSigningKeyPair(secret).publicKey),
        ...over,
      });
    const invite = mk();
    const acceptance = T.createInviteAcceptance(secret, {
      inviteId: invite.inviteId,
      userId: bob.userId,
      userSignPub: signPub(bob),
    });
    const base = {
      teamId: signer.teamId,
      groupId,
      groupVersion: 1,
      userId: bob.userId,
      userSignPub: signPub(bob),
      teamKeyVersion: 1,
      teamSignPub: link.signPub,
    };
    return { bob, signer, link, groupId, secret, invite, acceptance, base, mk };
  };
  it("an invite-backed proof verifies for a group the invite names, with the accepted key", () => {
    const { invite, acceptance, base } = setup();
    const p = { kind: "invite" as const, invite, acceptance };
    expect(T.verifyMemberProof(p, base)).toBe(true);
    expect(T.verifyMemberProof(p, { ...base, groupId: crypto.randomUUID() })).toBe(false);
    expect(T.verifyMemberProof(p, { ...base, userSignPub: signPub(user("x")) })).toBe(false);
  });
  it("rejects a tampered invite, a foreign team and an acceptance signed by another secret", () => {
    const { invite, acceptance, base, bob } = setup();
    const proof = (i: typeof invite, a: typeof acceptance) => ({ kind: "invite" as const, invite: i, acceptance: a });
    const extra = { ...invite.groupVersions, [crypto.randomUUID()]: 1 };
    expect(T.verifyMemberProof(proof({ ...invite, groupVersions: extra }, acceptance), base)).toBe(false);
    expect(T.verifyMemberProof(proof(invite, acceptance), { ...base, teamId: crypto.randomUUID() })).toBe(false);
    const forged = T.createInviteAcceptance(T.newInviteSecret(), {
      inviteId: invite.inviteId,
      userId: bob.userId,
      userSignPub: signPub(bob),
    });
    expect(T.verifyMemberProof(proof(invite, forged), base)).toBe(false);
  });
  it("rejects an invite without an inviteSignPub", () => {
    const { mk, bob, secret, base } = setup();
    const invite = mk({ inviteSignPub: null });
    const acceptance = T.createInviteAcceptance(secret, {
      inviteId: invite.inviteId,
      userId: bob.userId,
      userSignPub: signPub(bob),
    });
    expect(T.verifyMemberProof({ kind: "invite", invite, acceptance }, base)).toBe(false);
  });
  it("statement proofs verify only for the statement's group, version, user and key", () => {
    const { signer, base, groupId, bob } = setup();
    const statement = T.createGroupStatement(signer, {
      groupId,
      groupVersion: 1,
      userId: bob.userId,
      userSignPub: signPub(bob),
    });
    const p = { kind: "statement" as const, statement };
    expect(T.verifyMemberProof(p, base)).toBe(true);
    expect(T.verifyMemberProof(p, { ...base, groupId: crypto.randomUUID() })).toBe(false);
    expect(T.verifyMemberProof(p, { ...base, groupVersion: 2 })).toBe(false);
  });
  it("a proof from an older group version or team key version fails", () => {
    const { signer, base, groupId, bob, invite, acceptance } = setup();
    const statement = T.createGroupStatement(signer, {
      groupId,
      groupVersion: 1,
      userId: bob.userId,
      userSignPub: signPub(bob),
    });
    const next = T.nextTeamKey(signer);
    const rotated = { ...base, teamKeyVersion: 2, teamSignPub: next.link.signPub };
    expect(T.verifyMemberProof({ kind: "statement", statement }, rotated)).toBe(false);
    expect(T.verifyMemberProof({ kind: "invite", invite, acceptance }, rotated)).toBe(false);
    expect(T.verifyMemberProof({ kind: "invite", invite, acceptance }, { ...base, groupVersion: 2 })).toBe(false);
    const fresh = T.createGroupStatement(next.signer, {
      groupId,
      groupVersion: 2,
      userId: bob.userId,
      userSignPub: signPub(bob),
    });
    expect(T.verifyMemberProof({ kind: "statement", statement: fresh }, { ...rotated, groupVersion: 2 })).toBe(true);
  });
  it("never throws on malformed proofs", () => {
    const { invite, acceptance, base } = setup();
    expect(
      T.verifyMemberProof({ kind: "invite", invite: { ...invite, groupVersions: null as never }, acceptance }, base),
    ).toBe(false);
    expect(T.verifyMemberProof({ kind: "statement" } as never, base)).toBe(false);
    expect(T.verifyInviteStatement({ ...invite, groupVersions: null as never }, base.teamSignPub)).toBe(false);
    expect(T.verifyGroupStatement(null as never, base.teamSignPub)).toBe(false);
    expect(T.verifyGroupVersion(null as never, 1, base.teamSignPub)).toBe(false);
    expect(T.verifyGroupGrant(null as never, base.teamSignPub)).toBe(false);
    expect(T.verifyInviteAcceptance(null as never, base.teamSignPub)).toBe(false);
  });
  it("auth value and keypairs are deterministic from the secret and independent of each other", () => {
    const s = T.newInviteSecret();
    expect(T.inviteAuth(s)).toBe(T.inviteAuth(s));
    expect(toBase64Url(T.inviteKeyPair(s).publicKey)).toBe(toBase64Url(T.inviteKeyPair(s).publicKey));
    expect(T.inviteAuth(s)).not.toBe(toBase64Url(T.inviteKeyPair(s).publicKey));
    expect(toBase64Url(T.inviteSigningKeyPair(s).publicKey)).not.toBe(toBase64Url(T.inviteKeyPair(s).publicKey));
    expect(fromBase64Url(T.inviteAuth(s))).toHaveLength(32);
  });
});

describe("team meta", () => {
  it("round-trips under the everyone-derived key and is bound to id and version", () => {
    const { signer } = T.createTeamKey(crypto.randomUUID());
    const everyone = T.createGroupVersion(signer, crypto.randomUUID(), 1);
    const k = T.teamMetaKey(everyone.keyPair);
    const env = T.encryptTeamMeta(k, signer.teamId, 1, { name: "Acme" });
    expect(T.decryptTeamMeta(k, signer.teamId, 1, env).name).toBe("Acme");
    expect(() => T.decryptTeamMeta(k, signer.teamId, 2, env)).toThrow();
    const genv = T.encryptGroupMeta(k, "g1", 1, { name: "Eng" });
    expect(T.decryptGroupMeta(k, "g1", 1, genv).name).toBe("Eng");
    expect(() => T.decryptGroupMeta(k, "g2", 1, genv)).toThrow();
  });
});

describe("former member proofs", () => {
  it("verify under the team key they name, only when the caller verified that key", () => {
    const teamId = crypto.randomUUID();
    const v1 = T.createTeamKey(teamId);
    const v2 = T.nextTeamKey(v1.signer);
    const alice = user("alice");
    const groupId = crypto.randomUUID();
    const statement = T.createGroupStatement(v1.signer, {
      groupId,
      groupVersion: 3,
      userId: alice.userId,
      userSignPub: signPub(alice),
    });
    const p = { kind: "statement" as const, statement };
    const keys = new Map([
      [1, v1.link.signPub],
      [2, v2.link.signPub],
    ]);
    const base = {
      teamId,
      groupId,
      userId: alice.userId,
      userSignPub: signPub(alice),
      teamKeyAt: (v: number) => keys.get(v) ?? null,
    };
    expect(T.verifyFormerMemberProof(p, base)).toBe(true);
    // A key the caller never verified (only v2 known) vouches for nothing.
    expect(T.verifyFormerMemberProof(p, { ...base, teamKeyAt: (v) => (v === 2 ? v2.link.signPub : null) })).toBe(false);
    // Signed under v1 but presented as v2's.
    expect(T.verifyFormerMemberProof(p, { ...base, teamKeyAt: () => v2.link.signPub })).toBe(false);
    expect(T.verifyFormerMemberProof(p, { ...base, groupId: crypto.randomUUID() })).toBe(false);
    expect(T.verifyFormerMemberProof(p, { ...base, userSignPub: signPub(user("x")) })).toBe(false);
  });
});
