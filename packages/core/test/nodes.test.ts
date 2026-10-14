import { fromBase64Url, sign, toBase64Url, verify } from "@jelly/crypto";
import { describe, expect, it } from "vitest";
import {
  type ChildLink,
  createAccount,
  createGrant,
  decryptNodeMeta,
  encryptNodeMeta,
  type Grant,
  grantPayload,
  KeyResolver,
  legacyGrantPayload,
  newNodeKey,
  openGrant,
  type PublicIdentity,
  SIG,
  unlockAccount,
  unwrapChildKey,
  verifyGrant,
  wrapChildKey,
} from "../src/index.ts";

function user(id: string, handle: string) {
  const acct = createAccount();
  const account = unlockAccount({ userId: id, handle, ak: acct.ak, bundle: acct.bundle });
  const identity: PublicIdentity = { userId: id, handle, ...acct.bundle };
  return { account, identity };
}

describe("node meta", () => {
  it("round-trips and is bound to node id and key version", () => {
    const key = newNodeKey();
    const meta = encryptNodeMeta(key, "n1", 1, { title: "Q4 plans" });
    expect(decryptNodeMeta(key, "n1", 1, meta)).toEqual({ title: "Q4 plans" });
    expect(() => decryptNodeMeta(key, "n2", 1, meta)).toThrow();
    expect(() => decryptNodeMeta(key, "n1", 2, meta)).toThrow();
  });
});

describe("child links", () => {
  it("unwraps only with matching parent key and ids", () => {
    const parent = newNodeKey();
    const child = newNodeKey();
    const link = wrapChildKey(parent, { childId: "c", childVersion: 1, parentId: "p", parentVersion: 1 }, child);
    expect(unwrapChildKey(parent, link)).toEqual(child);
    expect(() => unwrapChildKey(parent, { ...link, childId: "x" })).toThrow();
    expect(() => unwrapChildKey(newNodeKey(), link)).toThrow();
  });
});

describe("grants", () => {
  const alice = user("alice-id", "alice");
  const bob = user("bob-id", "bob");
  const carol = user("carol-id", "carol");
  const key = newNodeKey();
  const grant = createGrant(alice.account, {
    nodeId: "n1",
    keyVersion: 1,
    nodeKey: key,
    grantee: bob.identity,
    role: "viewer",
  });

  it("opens for the grantee and verifies against the grantor", () => {
    expect(verifyGrant(grant, alice.identity.signPub)).toBe(true);
    expect(openGrant(bob.account, grant)).toEqual(key);
  });

  it("does not open for someone else", () => {
    expect(() => openGrant(carol.account, grant)).toThrow();
  });

  it("fails verification when the role or sealed key is altered or the signer differs", () => {
    expect(verifyGrant({ ...grant, role: "owner" }, alice.identity.signPub)).toBe(false);
    const other = createGrant(alice.account, {
      nodeId: "n1",
      keyVersion: 1,
      nodeKey: newNodeKey(),
      grantee: bob.identity,
      role: "viewer",
    });
    expect(verifyGrant({ ...grant, sealedKey: other.sealedKey }, alice.identity.signPub)).toBe(false);
    expect(verifyGrant(grant, carol.identity.signPub)).toBe(false);
  });

  it("signs new grants under the length-prefixed grant@2 format", () => {
    expect(
      verify(fromBase64Url(alice.identity.signPub), SIG.grantV2, grantPayload(grant), fromBase64Url(grant.signature)),
    ).toBe(true);
    expect(
      verify(
        fromBase64Url(alice.identity.signPub),
        SIG.grant,
        legacyGrantPayload(grant),
        fromBase64Url(grant.signature),
      ),
    ).toBe(false);
  });

  it("still accepts well-formed grants signed before grant@2, and nothing ambiguous", () => {
    const ids = { nodeId: crypto.randomUUID(), granteeId: crypto.randomUUID(), grantorId: crypto.randomUUID() };
    const unsigned = { ...ids, keyVersion: 1, role: "viewer" as const, sealedKey: grant.sealedKey };
    const legacy = {
      ...unsigned,
      signature: toBase64Url(sign(alice.account.signing.privateKey, SIG.grant, legacyGrantPayload(unsigned))),
    };
    expect(verifyGrant(legacy, alice.identity.signPub)).toBe(true);
    const odd = { ...unsigned, nodeId: "n|1" };
    const oddLegacy = {
      ...odd,
      signature: toBase64Url(sign(alice.account.signing.privateKey, SIG.grant, legacyGrantPayload(odd))),
    };
    expect(verifyGrant(oddLegacy, alice.identity.signPub)).toBe(false);
  });

  it("refuses to grant to an identity with a forged encryption key", () => {
    const forged = { ...bob.identity, encPub: carol.identity.encPub };
    expect(() =>
      createGrant(alice.account, {
        nodeId: "n1",
        keyVersion: 1,
        nodeKey: key,
        grantee: forged,
        role: "viewer",
      }),
    ).toThrow();
  });
});

describe("KeyResolver", () => {
  const alice = user("alice-id", "alice");
  const bob = user("bob-id", "bob");
  const mallory = user("mallory-id", "mallory");
  const identities = new Map([alice, bob, mallory].map((u) => [u.identity.userId, u.identity]));
  const lookup = (id: string) => identities.get(id);

  const root = newNodeKey();
  const mid = newNodeKey();
  const leaf = newNodeKey();
  const links: ChildLink[] = [
    wrapChildKey(root, { childId: "mid", childVersion: 1, parentId: "root", parentVersion: 1 }, mid),
    wrapChildKey(mid, { childId: "leaf", childVersion: 1, parentId: "mid", parentVersion: 1 }, leaf),
  ];
  const rootGrant = createGrant(alice.account, {
    nodeId: "root",
    keyVersion: 1,
    nodeKey: root,
    grantee: bob.identity,
    role: "viewer",
  });

  it("resolves descendants through a grant on an ancestor", () => {
    const r = new KeyResolver({ account: bob.account, identities: lookup });
    r.addGrant(rootGrant);
    for (const l of links) r.addChildLink(l);
    expect(r.keyFor("leaf", 1)).toEqual(leaf);
    expect(r.keyFor("mid", 1)).toEqual(mid);
  });

  it("returns null and flags nodes whose only grant fails verification", () => {
    const r = new KeyResolver({ account: bob.account, identities: lookup });
    // Mallory claims Alice granted it: signature won't verify against Alice's key.
    const forged: Grant = {
      ...createGrant(mallory.account, {
        nodeId: "root",
        keyVersion: 1,
        nodeKey: newNodeKey(),
        grantee: bob.identity,
        role: "editor",
      }),
      grantorId: "alice-id",
    };
    r.addGrant(forged);
    for (const l of links) r.addChildLink(l);
    expect(r.keyFor("leaf", 1)).toBeNull();
    expect(r.unverified.has("root")).toBe(true);
  });

  it("ignores grants addressed to other users", () => {
    const r = new KeyResolver({ account: mallory.account, identities: lookup });
    r.addGrant(rootGrant);
    expect(r.keyFor("root", 1)).toBeNull();
  });

  it("resolves from a key set directly (link shares) without an account", () => {
    const r = new KeyResolver({ identities: lookup });
    r.setKey("mid", 1, mid);
    for (const l of links) r.addChildLink(l);
    expect(r.keyFor("leaf", 1)).toEqual(leaf);
    expect(r.keyFor("root", 1)).toBeNull();
  });

  it("survives cyclic links", () => {
    const a = newNodeKey();
    const r = new KeyResolver({ identities: lookup });
    r.addChildLink(wrapChildKey(a, { childId: "x", childVersion: 1, parentId: "y", parentVersion: 1 }, a));
    r.addChildLink(wrapChildKey(a, { childId: "y", childVersion: 1, parentId: "x", parentVersion: 1 }, a));
    expect(r.keyFor("x", 1)).toBeNull();
  });

  it("exposes grant identities for unknown grantors as unverified", () => {
    const r = new KeyResolver({ account: bob.account, identities: () => undefined });
    r.addGrant(rootGrant);
    expect(r.keyFor("root", 1)).toBeNull();
    expect(r.unverified.has("root")).toBe(true);
    expect(toBase64Url(root)).toBeTruthy();
  });
});
