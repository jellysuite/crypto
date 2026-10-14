import { describe, expect, it } from "vitest";
import {
  type ChildLink,
  createAccount,
  createGrant,
  createGroupGrant,
  createGroupVersion,
  createTeamKey,
  KeyResolver,
  newNodeKey,
  type PublicIdentity,
  unlockAccount,
  wrapChildKey,
} from "../src/index.ts";

function user(handle: string) {
  const id = crypto.randomUUID();
  const acct = createAccount();
  const account = unlockAccount({ userId: id, handle, ak: acct.ak, bundle: acct.bundle });
  const identity: PublicIdentity = { userId: id, handle, ...acct.bundle };
  return { account, identity };
}

function setup() {
  const alice = user("alice");
  const bob = user("bob");
  const { signer } = createTeamKey(crypto.randomUUID());
  const groupId = crypto.randomUUID();
  const { wire: group, keyPair } = createGroupVersion(signer, groupId, 1);
  const nodeId = crypto.randomUUID();
  const nodeKey = newNodeKey();
  const grant = createGroupGrant(alice.account, { nodeId, keyVersion: 1, nodeKey, group, role: "editor" });
  const identities = (id: string) => [alice, bob].find((u) => u.identity.userId === id)?.identity;
  const resolver = () => new KeyResolver({ account: bob.account, identities });
  return { alice, bob, group, groupId, keyPair, nodeId, nodeKey, grant, resolver };
}

describe("KeyResolver group grants", () => {
  it("resolves a node reachable only through a group grant once the group key is set", () => {
    const s = setup();
    const r = s.resolver();
    r.addGroupGrant(s.grant);
    r.setGroupKey(s.groupId, 1, s.keyPair);
    expect(r.keyFor(s.nodeId, 1)).toEqual(s.nodeKey);
    expect(r.unverified.has(s.nodeId)).toBe(false);
  });

  it("does not resolve without the group key, and does not flag the node", () => {
    const s = setup();
    const r = s.resolver();
    r.addGroupGrant(s.grant);
    expect(r.keyFor(s.nodeId, 1)).toBeNull();
    expect(r.unverified.has(s.nodeId)).toBe(false);
  });

  it("does not resolve with a group key of another version", () => {
    const s = setup();
    const r = s.resolver();
    r.addGroupGrant(s.grant);
    r.setGroupKey(s.groupId, 2, s.keyPair);
    expect(r.keyFor(s.nodeId, 1)).toBeNull();
  });

  it("refuses a forged signature and marks the node unverified", () => {
    const s = setup();
    const r = s.resolver();
    r.addGroupGrant({ ...s.grant, role: "owner" });
    r.setGroupKey(s.groupId, 1, s.keyPair);
    expect(r.keyFor(s.nodeId, 1)).toBeNull();
    expect(r.unverified.has(s.nodeId)).toBe(true);
  });

  it("marks the node unverified when the grantor is unknown", () => {
    const s = setup();
    const r = new KeyResolver({ account: s.bob.account, identities: () => undefined });
    r.addGroupGrant(s.grant);
    r.setGroupKey(s.groupId, 1, s.keyPair);
    expect(r.keyFor(s.nodeId, 1)).toBeNull();
    expect(r.unverified.has(s.nodeId)).toBe(true);
  });

  it("tries each group when a node has several group grants", () => {
    const s = setup();
    const other = createGroupVersion(createTeamKey(crypto.randomUUID()).signer, crypto.randomUUID(), 1);
    const g2 = createGroupGrant(s.alice.account, {
      nodeId: s.nodeId,
      keyVersion: 1,
      nodeKey: s.nodeKey,
      group: other.wire,
      role: "viewer",
    });
    const r = s.resolver();
    r.addGroupGrant(g2);
    r.addGroupGrant(s.grant);
    r.setGroupKey(s.groupId, 1, s.keyPair);
    expect(r.keyFor(s.nodeId, 1)).toEqual(s.nodeKey);
  });

  it("never opens a validly signed group grant that trustGroupGrant rejects, and marks the node unverified", () => {
    const s = setup();
    const r = new KeyResolver({
      account: s.bob.account,
      identities: (id) => [s.alice, s.bob].find((u) => u.identity.userId === id)?.identity,
      trustGroupGrant: (g) => g.grantorId !== s.alice.identity.userId,
    });
    r.addGroupGrant(s.grant);
    r.setGroupKey(s.groupId, 1, s.keyPair);
    expect(r.keyFor(s.nodeId, 1)).toBeNull();
    expect(r.unverified.has(s.nodeId)).toBe(true);
  });

  it("lets a parent link win over a group grant", () => {
    const s = setup();
    const parentId = crypto.randomUUID();
    const parentKey = newNodeKey();
    const link: ChildLink = wrapChildKey(
      parentKey,
      { childId: s.nodeId, childVersion: 1, parentId, parentVersion: 1 },
      s.nodeKey,
    );
    const evil = createGroupGrant(s.alice.account, {
      nodeId: s.nodeId,
      keyVersion: 1,
      nodeKey: newNodeKey(),
      group: s.group,
      role: "editor",
    });
    const r = s.resolver();
    r.setKey(parentId, 1, parentKey);
    r.addChildLink(link);
    r.addGroupGrant(evil);
    r.setGroupKey(s.groupId, 1, s.keyPair);
    expect(r.keyFor(s.nodeId, 1)).toEqual(s.nodeKey);
  });
});

describe("KeyResolver via", () => {
  it("records how each key was reached: a child link, a grant (and its grantor), a group grant, or setKey", () => {
    const s = setup();
    const r = s.resolver();
    // A folder Alice shared with Bob directly, a page inside it, and the group-shared node from setup.
    const folderId = crypto.randomUUID();
    const folderKey = newNodeKey();
    r.addGrant(
      createGrant(s.alice.account, {
        nodeId: folderId,
        keyVersion: 1,
        nodeKey: folderKey,
        grantee: s.bob.identity,
        role: "editor",
      }),
    );
    const pageId = crypto.randomUUID();
    const pageKey = newNodeKey();
    const pageLink = wrapChildKey(
      folderKey,
      { childId: pageId, childVersion: 1, parentId: folderId, parentVersion: 1 },
      pageKey,
    );
    r.addChildLink(pageLink);
    r.addGroupGrant(s.grant);
    r.setGroupKey(s.groupId, 1, s.keyPair);
    const seeded = crypto.randomUUID();
    r.setKey(seeded, 3, newNodeKey());

    expect(r.via(pageId, 1)).toBeUndefined();
    expect(r.keyFor(pageId, 1)).toEqual(pageKey);
    expect(r.via(pageId, 1)).toEqual({ kind: "link", parentId: folderId, link: pageLink });
    expect(r.via(folderId, 1)).toEqual({ kind: "grant", grantorId: s.alice.identity.userId });
    expect(r.keyFor(s.nodeId, 1)).toEqual(s.nodeKey);
    expect(r.via(s.nodeId, 1)).toEqual({ kind: "group", groupId: s.groupId, grantorId: s.alice.identity.userId });
    expect(r.via(seeded, 3)).toEqual({ kind: "set" });
    expect(r.via(seeded, 2)).toBeUndefined();
  });

  it("records nothing for a key it couldn't reach", () => {
    const s = setup();
    const r = s.resolver();
    r.addGroupGrant(s.grant);
    expect(r.keyFor(s.nodeId, 1)).toBeNull();
    expect(r.via(s.nodeId, 1)).toBeUndefined();
  });
});
