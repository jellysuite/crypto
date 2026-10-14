import { describe, expect, it } from "vitest";
import {
  createAccount,
  createGrant,
  createMembership,
  type GrantEntry,
  newNodeKey,
  type PublicIdentity,
  type Role,
  unlockAccount,
  verifyMembership,
  verifyShares,
} from "../src/index.ts";

function user(handle: string) {
  const id = crypto.randomUUID();
  const acct = createAccount();
  const account = unlockAccount({ userId: id, handle, ak: acct.ak, bundle: acct.bundle });
  const identity: PublicIdentity = { userId: id, handle, ...acct.bundle };
  return { account, identity };
}
type U = ReturnType<typeof user>;

const NODE = crypto.randomUUID();
const PARENT = crypto.randomUUID();

const entry = (from: U, to: U, role: Role, nodeId = NODE): GrantEntry => ({
  grant: createGrant(from.account, { nodeId, keyVersion: 1, nodeKey: newNodeKey(), grantee: to.identity, role }),
  identity: to.identity,
});

describe("membership statements", () => {
  const alice = user("alice");
  const bob = user("bob");
  const carol = user("carol");

  it("are part of every grant and bind the grantee's signing key", () => {
    const { grant } = entry(alice, bob, "editor");
    expect(grant.member?.grantorId).toBe(alice.identity.userId);
    expect(grant.member?.granteeSignPub).toBe(bob.identity.signPub);
    expect(verifyMembership(grant, grant.member!, alice.identity.signPub)).toBe(true);
  });

  it("fail when the role, grantee, grantee key, node or signer differ", () => {
    const { grant } = entry(alice, bob, "editor");
    const m = grant.member!;
    expect(verifyMembership({ ...grant, role: "owner" }, m, alice.identity.signPub)).toBe(false);
    expect(verifyMembership({ ...grant, granteeId: carol.identity.userId }, m, alice.identity.signPub)).toBe(false);
    expect(verifyMembership(grant, { ...m, granteeSignPub: carol.identity.signPub }, alice.identity.signPub)).toBe(
      false,
    );
    expect(verifyMembership({ ...grant, nodeId: PARENT }, m, alice.identity.signPub)).toBe(false);
    expect(verifyMembership(grant, m, carol.identity.signPub)).toBe(false);
  });

  it("can be made on their own (e.g. by the owner for a grant someone else rotated)", () => {
    const m = createMembership(alice.account, { nodeId: NODE, grantee: bob.identity, role: "viewer" });
    expect(
      verifyMembership({ nodeId: NODE, granteeId: bob.identity.userId, role: "viewer" }, m, alice.identity.signPub),
    ).toBe(true);
  });
});

describe("verifyShares", () => {
  const alice = user("alice");
  const bob = user("bob");
  const carol = user("carol");
  const dave = user("dave");
  const mallory = user("mallory");
  /** Anchors: people this client knows hold the key at a depth of the chain (0 = the item itself). */
  const anchorsAt = (...as: Array<[U, number]>) =>
    new Map(as.map(([u, depth]) => [u.identity.userId, { signPub: u.identity.signPub, depth }]));
  const trustOnly = (...us: U[]) => anchorsAt(...us.map((u): [U, number] => [u, 0]));
  const handles = (r: { unverified: PublicIdentity[] }) => r.unverified.map((i) => i.handle).sort();

  it("accepts shares made by an anchor", () => {
    const r = verifyShares({ chain: [NODE], entries: [entry(alice, bob, "editor")], anchors: trustOnly(alice) });
    expect(r.verified.map((e) => e.identity.handle)).toEqual(["bob"]);
    expect(r.unverified).toEqual([]);
  });

  it("follows a chain of editors: alice → bob (editor) → carol", () => {
    const r = verifyShares({
      chain: [NODE],
      entries: [entry(bob, carol, "viewer"), entry(alice, bob, "editor")],
      anchors: trustOnly(alice),
    });
    expect(handles({ unverified: r.unverified })).toEqual([]);
    expect(r.verified).toHaveLength(2);
  });

  it("takes authority from shares on ancestors, but not from descendants", () => {
    const ok = verifyShares({
      chain: [NODE, PARENT],
      entries: [entry(alice, bob, "editor", PARENT), entry(bob, carol, "viewer")],
      anchors: anchorsAt([alice, 1]),
    });
    expect(ok.verified.map((e) => e.identity.handle)).toEqual(["carol"]);
    expect(ok.unverified).toEqual([]);
    // Bob being an editor of NODE says nothing about PARENT, so Carol's share there isn't backed.
    const up = verifyShares({
      chain: [PARENT, crypto.randomUUID()],
      entries: [entry(bob, carol, "viewer", PARENT)],
      anchors: trustOnly(alice),
    });
    expect(handles(up)).toEqual(["carol"]);
  });

  it("refuses people added by someone the server made up", () => {
    // Mallory is not trusted and holds no backed share: her own self-grant proves nothing.
    const r = verifyShares({
      chain: [NODE],
      entries: [entry(alice, bob, "viewer"), entry(mallory, mallory, "owner"), entry(mallory, dave, "viewer")],
      anchors: trustOnly(alice),
    });
    expect(handles(r)).toEqual(["dave", "mallory"]);
  });

  it("refuses a share whose grantee key was swapped by the server", () => {
    const e = entry(alice, bob, "viewer");
    const swapped = { ...e, identity: { ...mallory.identity, userId: bob.identity.userId, handle: "bob" } };
    expect(handles(verifyShares({ chain: [NODE], entries: [swapped], anchors: trustOnly(alice) }))).toEqual(["bob"]);
  });

  it("refuses legacy grants without a statement", () => {
    const e = entry(alice, bob, "viewer");
    const legacy = { ...e, grant: { ...e.grant, member: null } };
    expect(handles(verifyShares({ chain: [NODE], entries: [legacy], anchors: trustOnly(alice) }))).toEqual(["bob"]);
  });

  it("doesn't let viewers vouch, nor editors hand out ownership", () => {
    const r = verifyShares({
      chain: [NODE],
      entries: [
        entry(alice, bob, "viewer"),
        entry(bob, carol, "viewer"),
        entry(alice, dave, "editor"),
        entry(dave, mallory, "owner"),
      ],
      anchors: trustOnly(alice),
    });
    expect(handles(r)).toEqual(["carol", "mallory"]);
  });

  it("refuses a statement whose role differs from the grant", () => {
    const e = entry(alice, bob, "viewer");
    const bumped = { ...e, grant: { ...e.grant, role: "owner" as const } };
    expect(handles(verifyShares({ chain: [NODE], entries: [bumped], anchors: trustOnly(alice) }))).toEqual(["bob"]);
  });

  // Review finding CR-1: a pinned contact with no grant on the chain used to vouch anyone in, at any role.
  it("refuses an owner share signed by someone who isn't an anchor, however much we trust their key", () => {
    const me = user("me");
    const eve = user("eve");
    const entries = [entry(alice, me, "editor"), entry(mallory, eve, "owner")];
    // My key for NODE came from Alice's grant; I'm an anchor at the root.
    const r = verifyShares({ chain: [NODE, PARENT], entries, anchors: anchorsAt([me, 1], [alice, 0]) });
    expect(r.verified.map((e) => e.identity.handle)).toEqual(["me"]);
    expect(handles(r)).toEqual(["eve"]);
    // Anchors are the only gate: were Mallory an anchor, her statement would count.
    const anchored = verifyShares({
      chain: [NODE, PARENT],
      entries,
      anchors: anchorsAt([me, 1], [alice, 0], [mallory, 0]),
    });
    expect(anchored.verified.map((e) => e.identity.handle).sort()).toEqual(["eve", "me"]);
  });

  it("gives an anchor authority at its depth and below, not above", () => {
    const entries = [entry(alice, bob, "editor", PARENT), entry(bob, carol, "viewer")];
    // Alice holds NODE's key but nothing says she holds PARENT's: her statement up there doesn't count.
    expect(handles(verifyShares({ chain: [NODE, PARENT], entries, anchors: anchorsAt([alice, 0]) }))).toEqual([
      "carol",
    ]);
    expect(handles(verifyShares({ chain: [NODE, PARENT], entries, anchors: anchorsAt([alice, 1]) }))).toEqual([]);
  });

  it("lets an editor an anchor vouched for vouch viewers and editors below, but not owners", () => {
    const r = verifyShares({
      chain: [NODE, PARENT],
      entries: [
        entry(alice, bob, "editor", PARENT),
        entry(bob, carol, "editor"),
        entry(carol, dave, "viewer"),
        entry(bob, mallory, "owner"),
      ],
      anchors: anchorsAt([alice, 1]),
    });
    expect(r.verified.map((e) => e.identity.handle).sort()).toEqual(["carol", "dave"]);
    expect(handles(r)).toEqual(["mallory"]);
    // Who may vouch (and so re-key): the anchor, and the editors counted statements made, at their depths.
    const who = r.authority.map((a) => [a.userId, a.role, a.depth]);
    expect(who).toEqual(
      expect.arrayContaining([
        [alice.identity.userId, "owner", 1],
        [bob.identity.userId, "editor", 1],
        [carol.identity.userId, "editor", 0],
      ]),
    );
    expect(r.authority.map((a) => a.userId)).not.toContain(dave.identity.userId);
  });

  it("lets a viewer an anchor vouched for vouch nobody", () => {
    const r = verifyShares({
      chain: [NODE, PARENT],
      entries: [entry(alice, bob, "viewer", PARENT), entry(bob, carol, "viewer")],
      anchors: anchorsAt([alice, 1]),
    });
    expect(handles(r)).toEqual(["carol"]);
  });
});
