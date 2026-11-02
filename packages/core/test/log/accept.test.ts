import { toBase64Url } from "@jelly/crypto";
import { describe, expect, it } from "vitest";
import {
  acceptChildLink,
  acceptGrant,
  acceptGroupGrant,
  acceptShareLink,
  applyIntent,
  type Change,
  type ChildLink,
  checkpointPrefill,
  createAccount,
  createFirstSnapshot,
  createGrant,
  createSnapshot,
  type Dep,
  type Grant,
  type GroupGrant,
  type GroupView,
  type Intent,
  keyCommit,
  type LegacyLeaf,
  type LogEntry,
  LogWorld,
  legacySnapshot,
  merkleProof,
  merkleRoot,
  type NodeState,
  nextSnapshot,
  type PublicIdentity,
  type Role,
  readOnlyKey,
  reissueSet,
  type Snapshot,
  type State,
  snapshotHash,
  unlockAccount,
  type WorldInput,
  writable,
} from "../../src/index.ts";

function user(handle: string) {
  const id = crypto.randomUUID();
  const acct = createAccount();
  const account = unlockAccount({ userId: id, handle, ak: acct.ak, bundle: acct.bundle });
  const { signPub, encPub, encPubSig } = acct.bundle;
  const identity: PublicIdentity = { userId: id, handle, signPub, encPub, encPubSig };
  return { id, account, signPub, identity };
}
type U = ReturnType<typeof user>;

const alice = user("alice");
const bob = user("bob");
const carol = user("carol");
const dan = user("dan");
const eve = user("eve");
const everyone = [alice, bob, carol, dan, eve];

const at = "2026-10-30T10:00:00.000Z";
const later = "2026-10-30T11:00:00.000Z";
const share = (u: U, role: Role) => ({ userId: u.id, role, signPub: u.signPub });
const known = (userId: string, signPub: string): "ok" | "unknown" | "mismatch" => {
  const u = everyone.find((x) => x.id === userId);
  return !u ? "unknown" : u.signPub === signPub ? "ok" : "mismatch";
};

/** A node key, and the commit a state at a version carries for it (§3.4: a v8 node's version 1 commits with an empty id). */
const key = (n: number) => new Uint8Array(32).fill(n);
const commitFor = (nodeId: string, version: number, k: Uint8Array) =>
  keyCommit(version === 1 ? "" : nodeId, version, k);
const firstCommit = (n: number) => keyCommit("", 1, key(n));

const noGroups: GroupView = {
  latest: () => null,
  member: () => false,
  removedAt: () => null,
  removedSince: () => false,
  teamGroups: () => null,
};

/** A group's signed versions as the client verified them: the members at each version, from 0. */
type Group = { id: string; versions: U[][] };
const group = (...versions: U[][]): Group => ({ id: crypto.randomUUID(), versions });
const groupHead = (g: Group, v: number) => toBase64Url(new TextEncoder().encode(`${g.id}:${v}`));
function view(gs: Group[], teams: Record<string, { everyone: Group; admins: Group; root?: string }> = {}): GroupView {
  const find = (id: string) => gs.find((g) => g.id === id);
  return {
    teamRoot: (teamId) => teams[teamId]?.root ?? null,
    latest: (id) => {
      const g = find(id);
      return g ? { version: g.versions.length - 1, head: groupHead(g, g.versions.length - 1) } : null;
    },
    member: (id, v, userId) => find(id)?.versions[v]?.some((u) => u.id === userId) ?? false,
    removedAt: (id, userId, after) => {
      const g = find(id);
      if (!g) return null;
      const has = (v: number) => g.versions[v]?.some((u) => u.id === userId) ?? false;
      for (let v = Math.max(after + 1, 1); v < g.versions.length; v++) if (has(v - 1) && !has(v)) return v;
      return null;
    },
    removedSince: (id, version) => {
      const g = find(id);
      if (!g) return false;
      const latest = g.versions[g.versions.length - 1] ?? [];
      return (g.versions[version] ?? []).some((u) => !latest.some((x) => x.id === u.id));
    },
    teamGroups: (teamId) => {
      const t = teams[teamId];
      return t ? { everyone: t.everyone.id, admins: t.admins.id } : null;
    },
  };
}

const folderState = (over: Partial<State> = {}): State => ({
  kind: "folder",
  parentId: null,
  anchor: { user: alice.id, signPub: alice.signPub },
  restricted: false,
  version: 1,
  keyCommit: firstCommit(1),
  shares: [share(alice, "owner")],
  groupShares: [],
  links: [],
  ...over,
});

const childState = (parentId: string, over: Partial<State> = {}): State => ({
  kind: "page",
  parentId,
  anchor: null,
  restricted: false,
  version: 1,
  keyCommit: firstCommit(1),
  shares: [],
  groupShares: [],
  links: [],
  ...over,
});

/** A node's log as a test builds it: each append chains onto whatever came last, applied or not. */
class Log {
  entries: LogEntry[] = [];
  readonly nodeId: string;
  constructor(nodeId: string) {
    this.nodeId = nodeId;
  }
  static create(by: U, state: State, deps: Dep[] = []): Log {
    const first = createFirstSnapshot(by.account, { state, deps, at });
    const log = new Log(first.nodeId);
    log.entries.push(first);
    return log;
  }
  last(): Snapshot {
    return this.entries[this.entries.length - 1] as Snapshot;
  }
  dep(seq = this.last().seq): Dep {
    const e = this.entries[seq] as Snapshot;
    return { log: this.nodeId, seq, head: snapshotHash(e) };
  }
  add(by: U, state: State, deps: Dep[] = [], change: Change = "change"): this {
    const prev = this.last();
    this.entries.push(
      createSnapshot(by.account, {
        nodeId: this.nodeId,
        seq: prev.seq + 1,
        prev: snapshotHash(prev),
        state,
        change,
        supersedes: null,
        skipped: [],
        nonce: null,
        deps,
        at,
      }),
    );
    return this;
  }
  push(e: LogEntry): this {
    this.entries.push(e);
    return this;
  }
  /** The log as the server might show it: only its first `n` entries. */
  upTo(n: number): [string, LogEntry[]] {
    return [this.nodeId, this.entries.slice(0, n)];
  }
}

function world(logs: (Log | [string, LogEntry[]])[], over: Partial<WorldInput> = {}): LogWorld {
  return new LogWorld({
    logs: new Map(logs.map((l) => (l instanceof Log ? [l.nodeId, l.entries] : l))),
    legacyRoot: null,
    identity: known,
    groups: noGroups,
    ...over,
  });
}

const st = (w: LogWorld, id: string): NodeState => {
  const ns = w.state(id);
  if (!ns) throw new Error("no state");
  return ns;
};
const verified = { kind: "verified" };
const shareIds = (ns: NodeState) => ns.state.shares.map((s) => s.userId).sort();
const ids = (...us: U[]) => us.map((u) => u.id).sort();
const roleOf = (ns: NodeState, u: U) => ns.state.shares.find((s) => s.userId === u.id)?.role ?? null;
const hidden = (): Dep => ({ log: crypto.randomUUID(), seq: 1, head: firstCommit(9) });

const grant = (by: U, to: U, nodeId: string, keyVersion: number, nodeKey: Uint8Array, role: Role = "viewer"): Grant =>
  createGrant(by.account, { nodeId, keyVersion, nodeKey, grantee: to.identity, role });

/** alice's folder: bob editor, carol viewer, dan viewer. */
const folder = (over: Partial<State> = {}) =>
  Log.create(
    alice,
    folderState({
      shares: [share(alice, "owner"), share(bob, "editor"), share(carol, "viewer"), share(dan, "viewer")],
      ...over,
    }),
  );

/** Applies the intent as `by` and appends the result, or throws with the refusal. */
function write(by: U, w: LogWorld, log: Log, intent: Intent, when = at): Snapshot {
  const s = nextSnapshot(by.account, w, st(w, log.nodeId), intent, when);
  if ("error" in s) throw new Error(`refused: ${s.error}`);
  log.push(s);
  return s;
}

const rekeyTo = (nodeId: string, version: number, n = version) => ({
  version,
  keyCommit: commitFor(nodeId, version, key(n)),
});

describe("accepting keys (§5.4)", () => {
  it("a viewer's grant is refused, also at a version without a commit", () => {
    const f = folder();
    const w = world([f]);
    const ns = st(w, f.nodeId);
    expect(ns.status).toEqual(verified);
    // an editor's grant to someone in the state, with the right key
    expect(acceptGrant(w, ns, grant(bob, dan, f.nodeId, 1, key(1)), key(1))).toBe(true);
    // the owner's too
    expect(acceptGrant(w, ns, grant(alice, dan, f.nodeId, 1, key(1)), key(1))).toBe(true);
    // a viewer has no share authority
    expect(acceptGrant(w, ns, grant(carol, dan, f.nodeId, 1, key(1)), key(1))).toBe(false);
    // nor does a stranger
    expect(acceptGrant(w, ns, grant(eve, dan, f.nodeId, 1, key(1)), key(1))).toBe(false);
    // a grantee the state doesn't name
    expect(acceptGrant(w, ns, grant(bob, eve, f.nodeId, 1, key(1)), key(1))).toBe(false);
    // the wrong version, or another node
    expect(acceptGrant(w, ns, grant(bob, dan, f.nodeId, 2, key(1)), key(1))).toBe(false);
    expect(acceptGrant(w, ns, grant(bob, dan, crypto.randomUUID(), 1, key(1)), key(1))).toBe(false);
    // the grant's role doesn't raise what the grantor needs: roles are the state's (an editor re-seals the
    // owner's share at a re-key; the server refuses a share whose role its maker may not give)
    expect(acceptGrant(w, ns, grant(bob, dan, f.nodeId, 1, key(1), "owner"), key(1))).toBe(true);
    expect(acceptGrant(w, ns, grant(alice, dan, f.nodeId, 1, key(1), "owner"), key(1))).toBe(true);

    // nothing is accepted on the strength of an unverified state
    const shaky = folder();
    shaky.add(alice, folderState({ shares: shaky.last().state.shares, version: 2, keyCommit: firstCommit(2) }), [
      hidden(),
    ]);
    const sw = world([shaky]);
    expect(st(sw, shaky.nodeId).status.kind).toBe("unverified");
    expect(acceptGrant(sw, st(sw, shaky.nodeId), grant(bob, dan, shaky.nodeId, 1, key(1)), key(1))).toBe(false);

    // a legacy version with no commit: the key can't be checked, the authority still is
    const legacyId = crypto.randomUUID();
    const state = folderState({
      shares: [share(alice, "owner"), share(bob, "editor"), share(carol, "viewer"), share(dan, "viewer")],
      version: 3,
      keyCommit: null,
    });
    const leaves: LegacyLeaf[] = [{ nodeId: legacyId, state }];
    const legacy = new Log(legacyId).push(
      legacySnapshot(leaves[0] as LegacyLeaf, merkleProof(leaves, legacyId) as string[]),
    );
    const lw = world([legacy], { legacyRoot: merkleRoot(leaves) });
    const lns = st(lw, legacyId);
    expect(lns.status).toEqual(verified);
    expect(writable(lns)).toBe("stale");
    expect(acceptGrant(lw, lns, grant(bob, dan, legacyId, 3, key(5)), key(5))).toBe(true);
    expect(acceptGrant(lw, lns, grant(carol, dan, legacyId, 3, key(5)), key(5))).toBe(false);
    expect(acceptGrant(lw, lns, grant(bob, dan, legacyId, 2, key(5)), key(5))).toBe(false);
  });

  it("a substituted key fails the commit", () => {
    const f = folder();
    let w = world([f]);
    expect(acceptGrant(w, st(w, f.nodeId), grant(bob, dan, f.nodeId, 1, key(2)), key(2))).toBe(false);
    // version 1 of a v8 node commits with an empty id (§3.4): a commit made with the node id is not it
    const wrongLog = Log.create(alice, folderState({ keyCommit: keyCommit(crypto.randomUUID(), 1, key(1)) }));
    w = world([wrongLog]);
    expect(st(w, wrongLog.nodeId).status).toEqual(verified);
    expect(acceptGrant(w, st(w, wrongLog.nodeId), grant(alice, bob, wrongLog.nodeId, 1, key(1)), key(1))).toBe(false);
    // later versions commit with the node id
    f.add(alice, { ...f.last().state, version: 2, keyCommit: commitFor(f.nodeId, 2, key(2)) });
    w = world([f]);
    const ns = st(w, f.nodeId);
    expect(ns.state.version).toBe(2);
    expect(acceptGrant(w, ns, grant(bob, dan, f.nodeId, 2, key(2)), key(2))).toBe(true);
    expect(acceptGrant(w, ns, grant(bob, dan, f.nodeId, 2, key(1)), key(1))).toBe(false);
    expect(acceptGrant(w, ns, grant(bob, dan, f.nodeId, 1, key(1)), key(1))).toBe(false);
  });

  it("a grantor who left during the version still vouches for the key they held", () => {
    const f = folder();
    const g = grant(bob, dan, f.nodeId, 1, key(1));
    f.add(bob, { ...f.last().state, shares: f.last().state.shares.filter((s) => s.userId !== bob.id) }, [], "leave");
    const w = world([f]);
    const ns = st(w, f.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.stale).toBe(true);
    expect(roleOf(ns, bob)).toBeNull();
    expect(acceptGrant(w, ns, g, key(1))).toBe(true);
    // but not someone who never had authority at it
    expect(acceptGrant(w, ns, grant(eve, dan, f.nodeId, 1, key(1)), key(1))).toBe(false);
  });

  it("a group grant needs the group in the state and a grantor with share authority", () => {
    const g = group([bob, eve]);
    const f = folder({ groupShares: [{ groupId: g.id, role: "editor" }] });
    const w = world([f], { groups: view([g]) });
    const ns = st(w, f.nodeId);
    const gg = (by: U, groupId: string, role: Role = "editor", keyVersion = 1): GroupGrant => ({
      nodeId: f.nodeId,
      keyVersion,
      groupId,
      groupVersion: 0,
      grantorId: by.id,
      role,
      sealedKey: "x",
      signature: "x",
    });
    expect(acceptGroupGrant(w, ns, gg(alice, g.id), key(1))).toBe(true);
    expect(acceptGroupGrant(w, ns, gg(bob, g.id), key(1))).toBe(true);
    expect(acceptGroupGrant(w, ns, gg(carol, g.id), key(1))).toBe(false);
    expect(acceptGroupGrant(w, ns, gg(alice, crypto.randomUUID()), key(1))).toBe(false);
    expect(acceptGroupGrant(w, ns, gg(alice, g.id, "editor", 2), key(1))).toBe(false);
    expect(acceptGroupGrant(w, ns, gg(alice, g.id), key(2))).toBe(false);
    // The grant's role decides nothing (the state's does): an editor re-seals an owner's share at a re-key.
    expect(acceptGroupGrant(w, ns, gg(bob, g.id, "owner"), key(1))).toBe(true);
    expect(acceptGroupGrant(w, ns, gg(alice, g.id, "owner"), key(1))).toBe(true);
  });

  it("a child link under a parent the state doesn't name is refused", () => {
    const p = folder();
    const q = folder();
    const c = Log.create(bob, childState(p.nodeId), [p.dep()]);
    const w = world([p, q, c]);
    const child = st(w, c.nodeId);
    expect(child.status).toEqual(verified);
    const link = (over: Partial<ChildLink> = {}): ChildLink => ({
      childId: c.nodeId,
      childVersion: 1,
      parentId: p.nodeId,
      parentVersion: 1,
      wrapped: "x",
      ...over,
    });
    expect(acceptChildLink(w, child, st(w, p.nodeId), link(), key(1))).toBe(true);
    // the state places it under p, not q
    expect(acceptChildLink(w, child, st(w, q.nodeId), link({ parentId: q.nodeId }), key(1))).toBe(false);
    // the link must say what the state says
    expect(acceptChildLink(w, child, st(w, p.nodeId), link({ parentId: q.nodeId }), key(1))).toBe(false);
    expect(acceptChildLink(w, child, st(w, p.nodeId), link({ childId: q.nodeId }), key(1))).toBe(false);
    expect(acceptChildLink(w, child, st(w, p.nodeId), link({ childVersion: 2 }), key(1))).toBe(false);
    expect(acceptChildLink(w, child, st(w, p.nodeId), link(), key(2))).toBe(false);
    // an unverified child links nothing
    const shaky = world([c]);
    expect(st(shaky, c.nodeId).status.kind).toBe("unverified");
    expect(acceptChildLink(shaky, st(shaky, c.nodeId), child, link(), key(1))).toBe(false);
  });

  it("a removed share link isn't accepted or re-wrapped", () => {
    const L = crypto.randomUUID();
    const f = folder({ links: [{ linkId: L, role: "viewer" }] });
    let w = world([f]);
    let ns = st(w, f.nodeId);
    expect(acceptShareLink(ns, L, key(1))).toBe(true);
    expect(acceptShareLink(ns, L, key(2))).toBe(false);
    expect(acceptShareLink(ns, crypto.randomUUID(), key(1))).toBe(false);
    expect(reissueSet(w, ns).links).toEqual([{ linkId: L, role: "viewer" }]);
    // alice removes it, re-keying
    write(alice, w, f, { removeLink: { linkId: L, rekey: rekeyTo(f.nodeId, 2) } });
    w = world([f]);
    ns = st(w, f.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.version).toBe(2);
    expect(acceptShareLink(ns, L, key(2))).toBe(false);
    expect(acceptShareLink(ns, L, key(1))).toBe(false);
    expect(reissueSet(w, ns).links).toEqual([]);
  });

  it("the re-issue set is the effective shares and groups, minus void team shares", () => {
    const admins = group([alice]);
    const everyoneG = group([alice, bob, carol], [alice, bob]);
    const team = crypto.randomUUID();
    const g = group([bob, dan]);
    const gdep = (gr: Group, v: number): Dep => ({ log: `group:${gr.id}`, seq: v, head: groupHead(gr, v) });
    // alice (an Admin) starts the team root while carol is still in Everyone
    const root = Log.create(
      alice,
      {
        kind: "folder",
        parentId: null,
        anchor: { team },
        restricted: false,
        version: 1,
        keyCommit: firstCommit(1),
        shares: [share(carol, "editor"), share(dan, "viewer")],
        groupShares: [{ groupId: g.id, role: "viewer" }],
        links: [],
      },
      [gdep(admins, 0), gdep(everyoneG, 0)],
    );
    const w = world([root], { groups: view([admins, everyoneG, g], { [team]: { everyone: everyoneG, admins } }) });
    const ns = st(w, root.nodeId);
    expect(ns.status).toEqual(verified);
    // carol left the team after the share: void; dan was never a member: a guest, kept
    expect(shareIds(ns)).toEqual(ids(dan));
    expect(ns.stale).toBe(true);
    const set = reissueSet(w, ns);
    expect(set.people.map((s) => s.userId)).toEqual([dan.id]);
    // the team's groups are sealed to through the anchor
    expect(set.groups).toEqual(
      expect.arrayContaining([
        { groupId: g.id, role: "viewer" },
        { groupId: everyoneG.id, role: "editor" },
        { groupId: admins.id, role: "owner" },
      ]),
    );
    expect(set.groups.length).toBe(3);
    expect(set.links).toEqual([]);
  });
});

describe("anchors and read-only keys (review fixes)", () => {
  const gdep = (gr: Group, v: number): Dep => ({ log: `group:${gr.id}`, seq: v, head: groupHead(gr, v) });

  it("a team root's Everyone and Admins group grants are accepted and re-issued", () => {
    const admins = group([alice]);
    const all = group([alice, bob]);
    const team = crypto.randomUUID();
    const root = Log.create(
      alice,
      {
        kind: "folder",
        parentId: null,
        anchor: { team },
        restricted: false,
        version: 1,
        keyCommit: firstCommit(1),
        shares: [],
        groupShares: [],
        links: [],
      },
      [gdep(admins, 0), gdep(all, 0)],
    );
    const w = world([root], { groups: view([admins, all], { [team]: { everyone: all, admins } }) });
    const ns = st(w, root.nodeId);
    expect(ns.status).toEqual(verified);
    const gg = (groupId: string, role: Role, by: U = alice): GroupGrant => ({
      nodeId: root.nodeId,
      keyVersion: 1,
      groupId,
      groupVersion: 0,
      grantorId: by.id,
      role,
      sealedKey: "x",
      signature: "x",
    });
    expect(acceptGroupGrant(w, ns, gg(all.id, "editor"), key(1))).toBe(true);
    expect(acceptGroupGrant(w, ns, gg(admins.id, "owner"), key(1))).toBe(true);
    // an Everyone member re-seals both groups' grants at a re-key (the roles are the state's, §4.2)
    expect(acceptGroupGrant(w, ns, gg(all.id, "editor", bob), key(1))).toBe(true);
    expect(acceptGroupGrant(w, ns, gg(admins.id, "owner", bob), key(1))).toBe(true);
    // someone outside the team can't
    expect(acceptGroupGrant(w, ns, gg(all.id, "editor", carol), key(1))).toBe(false);
    // a direct grant to someone whose role comes from the anchor
    expect(acceptGrant(w, ns, grant(alice, bob, root.nodeId, 1, key(1)), key(1))).toBe(true);
    expect(acceptGrant(w, ns, grant(alice, carol, root.nodeId, 1, key(1)), key(1))).toBe(false);
    const set = reissueSet(w, ns);
    expect(set.people).toEqual([]);
    expect(set.groups).toEqual(
      expect.arrayContaining([
        { groupId: all.id, role: "editor" },
        { groupId: admins.id, role: "owner" },
      ]),
    );
    expect(set.groups.length).toBe(2);
  });

  it("a team root's built-in group shares stand on the anchor after the creator leaves the team", () => {
    const admins = group([alice, carol], [carol]);
    const all = group([alice, bob, carol], [bob, carol]);
    const team = crypto.randomUUID();
    const root = Log.create(
      alice,
      {
        kind: "folder",
        parentId: null,
        anchor: { team },
        restricted: false,
        version: 1,
        keyCommit: firstCommit(1),
        shares: [],
        groupShares: [
          { groupId: all.id, role: "editor" },
          { groupId: admins.id, role: "owner" },
        ],
        links: [],
      },
      [gdep(admins, 0), gdep(all, 0)],
    );
    const w = world([root], { groups: view([admins, all], { [team]: { everyone: all, admins } }) });
    const ns = st(w, root.nodeId);
    expect(ns.status).toEqual(verified);
    // Alice held the key and is gone from both groups: a re-key comes next, with the groups still on the root.
    expect(ns.stale).toBe(true);
    expect(ns.state.groupShares.map((g) => g.role).sort()).toEqual(["editor", "owner"]);
    expect(reissueSet(w, ns).groups.length).toBe(2);
    expect(w.role(bob.id, root.nodeId)).toBe("editor");
    expect(w.role(alice.id, root.nodeId)).toBeNull();
    // Bob, through Everyone, re-keys it: the snapshot keeps both groups.
    const next = write(bob, w, root, { rekey: rekeyTo(root.nodeId, 2) });
    expect(next.state.groupShares.map((g) => g.role).sort()).toEqual(["editor", "owner"]);
    const ns2 = st(world([root], { groups: view([admins, all], { [team]: { everyone: all, admins } }) }), root.nodeId);
    expect(ns2.status).toEqual(verified);
    expect(ns2.stale).toBe(false);
  });

  it("a forged team root giving Everyone owner: the anchor implies Everyone at editor only, so members aren't owners once the forger is gone", () => {
    const admins = group([alice, eve], [alice]);
    const all = group([alice, bob, eve], [alice, bob]);
    const team = crypto.randomUUID();
    const root = Log.create(
      eve,
      {
        kind: "folder",
        parentId: null,
        anchor: { team },
        restricted: false,
        version: 1,
        keyCommit: firstCommit(1),
        shares: [],
        groupShares: [
          { groupId: all.id, role: "owner" },
          { groupId: admins.id, role: "owner" },
        ],
        links: [],
      },
      [gdep(admins, 0), gdep(all, 0)],
    );
    const w = world([root], { groups: view([admins, all], { [team]: { everyone: all, admins } }) });
    const ns = st(w, root.nodeId);
    expect(ns.status).toEqual(verified);
    // Everyone at owner was Eve's to vouch for, and lapses with her; Admins at owner is the anchor's.
    expect(ns.state.groupShares).toEqual([{ groupId: admins.id, role: "owner" }]);
    expect(w.role(bob.id, root.nodeId)).toBe("editor");
    expect(w.role(alice.id, root.nodeId)).toBe("owner");
    expect(reissueSet(w, ns).groups).toEqual(
      expect.arrayContaining([
        { groupId: admins.id, role: "owner" },
        { groupId: all.id, role: "editor" },
      ]),
    );
  });

  it("a former admin's new root naming an old Everyone: the anchor's groups stand, their own share to an outsider lapses", () => {
    // Eve was an admin at version 0 and is gone at version 1; she signs a fresh team-anchored root naming the old
    // versions, with a share to Dan, an outsider. Pinning the team's root id is Task 6b; here the fold alone.
    const admins = group([alice, eve], [alice]);
    const all = group([alice, bob, eve], [alice, bob]);
    const team = crypto.randomUUID();
    const root = Log.create(
      eve,
      {
        kind: "folder",
        parentId: null,
        anchor: { team },
        restricted: false,
        version: 1,
        keyCommit: firstCommit(1),
        shares: [share(dan, "editor")],
        groupShares: [
          { groupId: all.id, role: "editor" },
          { groupId: admins.id, role: "owner" },
        ],
        links: [],
      },
      [gdep(admins, 0), gdep(all, 0)],
    );
    const w = world([root], { groups: view([admins, all], { [team]: { everyone: all, admins } }) });
    const ns = st(w, root.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.stale).toBe(true);
    // The anchor's groups are the anchor's; Dan's share was Eve's to vouch for, and she can't any more.
    expect(ns.state.groupShares.map((g) => g.role).sort()).toEqual(["editor", "owner"]);
    expect(ns.state.shares).toEqual([]);
    expect(w.role(dan.id, root.nodeId)).toBeNull();
    expect(w.role(eve.id, root.nodeId)).toBeNull();
    expect(reissueSet(w, ns).people).toEqual([]);
    // Bob's re-key seals to the groups, not to Dan.
    const next = write(bob, w, root, { rekey: rekeyTo(root.nodeId, 2) });
    expect(next.state.shares).toEqual([]);
    expect(next.state.groupShares.length).toBe(2);
    expect(acceptGrant(w, ns, grant(bob, dan, root.nodeId, 1, key(1)), key(1))).toBe(false);
  });

  it("a team-anchored root other than the one the team key names is refused (Task 6b, I2)", () => {
    // The client pins the team's root id from a statement a verified team key signed; a second root anchored to
    // the team, however well its genesis is signed, is not the team's.
    const admins = group([alice]);
    const all = group([alice, bob]);
    const team = crypto.randomUUID();
    const teamRoot = (by: U) =>
      Log.create(
        by,
        {
          kind: "folder",
          parentId: null,
          anchor: { team },
          restricted: false,
          version: 1,
          keyCommit: firstCommit(1),
          shares: [],
          groupShares: [
            { groupId: all.id, role: "editor" },
            { groupId: admins.id, role: "owner" },
          ],
          links: [],
        },
        [gdep(admins, 0), gdep(all, 0)],
      );
    const real = teamRoot(alice);
    const decoy = teamRoot(alice);
    const groups = view([admins, all], { [team]: { everyone: all, admins, root: real.nodeId } });
    const w = world([real, decoy], { groups });
    expect(st(w, real.nodeId).status).toEqual(verified);
    expect(st(w, decoy.nodeId).status).toEqual({ kind: "unverified", atSeq: 0, reason: "anchor" });
    expect(w.role(alice.id, decoy.nodeId)).toBeNull();
    // A view that can't name the team's root (none pinned yet) judges the anchor as before.
    const open = world([real, decoy], { groups: view([admins, all], { [team]: { everyone: all, admins } }) });
    expect(st(open, decoy.nodeId).status).toEqual(verified);
  });

  it("a grantor a group has since dropped still vouches for the key of the version they held it at", () => {
    // Carol was in the group at the version the folder named; the group moved on without her (the folder is
    // stale: a re-key comes next), but the key she sealed is the version's, and she had authority then.
    const g = group([alice, carol], [alice]);
    const f = Log.create(
      alice,
      folderState({
        shares: [share(alice, "owner"), share(dan, "viewer")],
        groupShares: [{ groupId: g.id, role: "editor" }],
      }),
      [gdep(g, 0)],
    );
    const w = world([f], { groups: view([g]) });
    const ns = st(w, f.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.stale).toBe(true);
    const gg = (by: U): GroupGrant => ({
      nodeId: f.nodeId,
      keyVersion: 1,
      groupId: g.id,
      groupVersion: 0,
      grantorId: by.id,
      role: "editor",
      sealedKey: "x",
      signature: "x",
    });
    expect(acceptGroupGrant(w, ns, gg(carol), key(1))).toBe(true);
    expect(acceptGrant(w, ns, grant(carol, dan, f.nodeId, 1, key(1)), key(1))).toBe(true);
    // Never on the node at that version: refused, now as then.
    expect(acceptGroupGrant(w, ns, gg(eve), key(1))).toBe(false);
    expect(acceptGrant(w, ns, grant(eve, dan, f.nodeId, 1, key(1)), key(1))).toBe(false);
    // A re-key by the owner leaves Carol behind: her grants at the new version are refused.
    const next = write(alice, w, f, { rekey: rekeyTo(f.nodeId, 2) });
    const w2 = world([f], { groups: view([g]) });
    const ns2 = st(w2, f.nodeId);
    expect(ns2.stale).toBe(false);
    expect(next.state.version).toBe(2);
    expect(acceptGroupGrant(w2, ns2, { ...gg(carol), keyVersion: 2 }, key(2))).toBe(false);
    expect(acceptGroupGrant(w2, ns2, { ...gg(alice), keyVersion: 2 }, key(2))).toBe(true);
  });

  it("a personal root's owner is granted to and re-issued through the anchor", () => {
    const root = Log.create(alice, folderState({ shares: [share(bob, "editor")] }));
    const w = world([root]);
    const ns = st(w, root.nodeId);
    expect(ns.status).toEqual(verified);
    expect(acceptGrant(w, ns, grant(alice, alice, root.nodeId, 1, key(1), "owner"), key(1))).toBe(true);
    // the editor re-seals the owner's share at a re-key: share authority is all a grantor needs
    expect(acceptGrant(w, ns, grant(bob, alice, root.nodeId, 1, key(1), "owner"), key(1))).toBe(true);
    const set = reissueSet(w, ns);
    expect(set.people.map((s) => [s.userId, s.role, s.signPub]).sort()).toEqual(
      [
        [alice.id, "owner", alice.signPub],
        [bob.id, "editor", bob.signPub],
      ].sort(),
    );
    // with a share of her own, she is listed once
    const own = Log.create(alice, folderState({ shares: [share(alice, "owner"), share(bob, "editor")] }));
    const ow = world([own]);
    expect(
      reissueSet(ow, st(ow, own.nodeId))
        .people.map((s) => s.userId)
        .sort(),
    ).toEqual(ids(alice, bob));
  });

  it("an unverified node opens read-only with the prefix key, never with a stretch re-key's", () => {
    const f = folder();
    f.add(alice, { ...f.last().state, version: 2, keyCommit: commitFor(f.nodeId, 2, key(2)) }, [hidden()]);
    const w = world([f]);
    const ns = st(w, f.nodeId);
    expect(ns.status.kind).toBe("unverified");
    expect(ns.stretchVersion).toBe(2);
    expect(readOnlyKey(ns, key(1))).toBe(true);
    expect(readOnlyKey(ns, key(2))).toBe(false);
    expect(acceptGrant(w, ns, grant(bob, dan, f.nodeId, 1, key(1)), key(1))).toBe(false);
    // a verified node too, but never a version with no commit
    const ok = folder();
    const ow = world([ok]);
    const ons = st(ow, ok.nodeId);
    expect(readOnlyKey(ons, key(1))).toBe(true);
    expect(readOnlyKey(ons, key(2))).toBe(false);
    expect(readOnlyKey({ ...ons, state: { ...ons.state, keyCommit: null } }, key(1))).toBe(false);
  });

  it("a restricted child's key isn't taken from a parent link", () => {
    const p = folder();
    const c = Log.create(alice, childState(p.nodeId, { restricted: true, shares: [share(alice, "owner")] }), [p.dep()]);
    const w = world([p, c]);
    const link: ChildLink = { childId: c.nodeId, childVersion: 1, parentId: p.nodeId, parentVersion: 1, wrapped: "x" };
    expect(st(w, c.nodeId).status).toEqual(verified);
    expect(acceptChildLink(w, st(w, c.nodeId), st(w, p.nodeId), link, key(1))).toBe(false);
  });
});

describe("writable", () => {
  it("unverified and rolled-back states aren't writable", () => {
    const f = folder();
    expect(writable(st(world([f]), f.nodeId))).toBe("ok");
    // a leave makes it stale
    const left = folder();
    left.add(
      bob,
      { ...left.last().state, shares: left.last().state.shares.filter((s) => s.userId !== bob.id) },
      [],
      "leave",
    );
    expect(writable(st(world([left]), left.nodeId))).toBe("stale");
    // a dep the server doesn't show: unverified
    const shaky = folder();
    shaky.add(alice, { ...shaky.last().state, version: 2, keyCommit: firstCommit(2) }, [hidden()]);
    expect(writable(st(world([shaky]), shaky.nodeId))).toBe("unverified");
    // a floor the shown log doesn't extend: rolled back, even if it's also stale
    const floors = new Map([[left.nodeId, { seq: 1, head: firstCommit(7) }]]);
    expect(writable(st(world([left], { floors }), left.nodeId))).toBe("rolled-back");
  });
});

describe("writing by intent (§3.6)", () => {
  /** Projects (alice owner, bob editor, carol viewer) with Plans and Archive under it. */
  function tree() {
    const projects = Log.create(
      alice,
      folderState({ shares: [share(alice, "owner"), share(bob, "editor"), share(carol, "viewer")] }),
    );
    const plans = Log.create(bob, childState(projects.nodeId), [projects.dep()]);
    const archive = Log.create(alice, childState(projects.nodeId, { kind: "folder" }), [projects.dep()]);
    return { projects, plans, archive };
  }

  it("nextSnapshot produces what the fold accepts", () => {
    const g = group([dan, eve]);
    const L = crypto.randomUUID();
    const { projects, plans, archive } = tree();
    const groups = view([g]);
    const w = () => world([projects, plans, archive], { groups });
    const plansNow = () => st(w(), plans.nodeId);
    const id = plans.nodeId;

    // add (editor)
    let s = write(bob, w(), plans, { add: share(dan, "viewer") }, later);
    expect(s.seq).toBe(1);
    expect(s.prev).toBe(snapshotHash(plans.entries[0] as Snapshot));
    expect(s.change).toBe("change");
    expect(s.at).toBe(later);
    expect(s.deps.map((d) => d.log)).toContain(projects.nodeId);
    expect(plansNow().status).toEqual(verified);
    expect(roleOf(plansNow(), dan)).toBe("viewer");
    // role (owner)
    write(alice, w(), plans, { role: { userId: dan.id, role: "editor" } });
    expect(roleOf(plansNow(), dan)).toBe("editor");
    // addGroup, addLink (editor)
    write(bob, w(), plans, { addGroup: { groupId: g.id, role: "viewer" } });
    expect(plansNow().state.groupShares).toEqual([{ groupId: g.id, role: "viewer" }]);
    expect(w().role(eve.id, id)).toBe("viewer");
    write(bob, w(), plans, { addLink: { linkId: L, role: "viewer" } });
    expect(plansNow().state.links).toEqual([{ linkId: L, role: "viewer" }]);
    // rekey (editor): the group it shares with is named
    s = write(bob, w(), plans, { rekey: rekeyTo(id, 2) });
    expect(s.deps.map((d) => d.log)).toContain(`group:${g.id}`);
    expect(plansNow().state.version).toBe(2);
    expect(plansNow().state.keyCommit).toBe(commitFor(id, 2, key(2)));
    // removeLink, removeGroup, remove (owner, each with its re-key)
    write(alice, w(), plans, { removeLink: { linkId: L, rekey: rekeyTo(id, 3) } });
    expect(plansNow().state.links).toEqual([]);
    write(alice, w(), plans, { removeGroup: { groupId: g.id, rekey: rekeyTo(id, 4) } });
    expect(plansNow().state.groupShares).toEqual([]);
    write(alice, w(), plans, { remove: dan.id, rekey: rekeyTo(id, 5) });
    expect(shareIds(plansNow())).toEqual([]);
    expect(plansNow().state.version).toBe(5);
    expect(plansNow().stale).toBe(false);
    // move (editor on both): the new parent is named
    s = write(bob, w(), plans, { move: archive.nodeId });
    expect(s.deps.map((d) => d.log)).toContain(archive.nodeId);
    expect(plansNow().state.parentId).toBe(archive.nodeId);
    expect(w().role(carol.id, id)).toBe("viewer");
    // restrict (owner): alice keeps nobody, and gets her own owner share so the node keeps an owner
    s = write(alice, w(), plans, { restrict: { shares: [], groups: [], links: [], rekey: rekeyTo(id, 6) } });
    expect(plansNow().state.restricted).toBe(true);
    expect(plansNow().state.shares).toEqual([share(alice, "owner")]);
    expect(w().role(bob.id, id)).toBeNull();
    expect(w().role(alice.id, id)).toBe("owner");
    // unrestrict (owner here, editor on the parent), back under Projects
    s = write(alice, w(), plans, { unrestrict: projects.nodeId });
    expect(plansNow().state.restricted).toBe(false);
    expect(plansNow().state.parentId).toBe(projects.nodeId);
    expect(w().role(bob.id, id)).toBe("editor");
    // leave: only the author's own share goes, nothing else
    s = write(alice, w(), plans, { leave: true });
    expect(s.change).toBe("leave");
    expect(shareIds(plansNow())).toEqual([]);
    expect(plansNow().status).toEqual(verified);
    expect(plansNow().stale).toBe(true);
    expect(writable(plansNow())).toBe("stale");
    expect(plansNow().seq).toBe(12);
  });

  it("a checkpoint intent repairs an unverified node", () => {
    const root = Log.create(
      alice,
      folderState({ shares: [share(alice, "owner"), share(dan, "owner"), share(bob, "editor")] }),
    );
    // alice removes dan with a check the server hides
    root.add(
      alice,
      {
        ...root.last().state,
        shares: [share(alice, "owner"), share(bob, "editor")],
        version: 2,
        keyCommit: firstCommit(2),
      },
      [hidden()],
    );
    let w = world([root]);
    let ns = st(w, root.nodeId);
    expect(ns.status.kind).toBe("unverified");
    expect(writable(ns)).toBe("unverified");
    // nothing but a checkpoint applies to it
    expect(applyIntent(w, ns, { add: share(eve, "viewer") }, share(alice, "owner"))).toMatchObject({
      error: "not-applicable",
    });
    const pre = checkpointPrefill(ns, share(alice, "owner"));
    const rekey = rekeyTo(root.nodeId, pre.version + 1);
    const s = write(alice, w, root, { checkpoint: { state: pre, rekey } });
    expect(s.change).toBe("checkpoint");
    expect(s.supersedes).toBe(ns.head);
    expect(s.seq).toBe(2);
    w = world([root]);
    ns = st(w, root.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.version).toBe(3);
    expect(ns.state.keyCommit).toBe(rekey.keyCommit);
    expect(shareIds(ns)).toEqual(ids(alice, bob));
    expect(writable(ns)).toBe("ok");
    // a checkpoint at the wrong version is refused before signing
    const bad = nextSnapshot(alice.account, w, ns, { checkpoint: { state: pre, rekey } }, at);
    expect(bad).toMatchObject({ error: expect.stringContaining("not-applicable") });
  });

  it("refuses what doesn't apply to the effective state", () => {
    const { projects, plans } = tree();
    const w = world([projects, plans]);
    const ns = st(w, plans.nodeId);
    const me = share(bob, "editor");
    const refused = (i: Intent, by = me) => {
      const r = applyIntent(w, ns, i, by);
      expect(r).toMatchObject({ error: "not-applicable" });
      return "error" in r ? r.why : "";
    };
    refused({ remove: dan.id, rekey: rekeyTo(plans.nodeId, 2) });
    refused({ role: { userId: dan.id, role: "owner" } });
    refused({ removeGroup: { groupId: crypto.randomUUID(), rekey: rekeyTo(plans.nodeId, 2) } });
    refused({ removeLink: { linkId: crypto.randomUUID(), rekey: rekeyTo(plans.nodeId, 2) } });
    // bob's role comes from the folder: there is no share of his to leave
    refused({ leave: true });
    // the re-key must step the version from the effective one
    expect(refused({ rekey: rekeyTo(plans.nodeId, 3) })).toContain("version");
    expect(refused({ rekey: { version: 2, keyCommit: ns.state.keyCommit as string } })).toContain("commit");
    // moving to where it is, or into itself
    refused({ move: projects.nodeId });
    refused({ move: plans.nodeId });
    // a root doesn't move
    expect(applyIntent(w, st(w, projects.nodeId), { move: plans.nodeId }, share(alice, "owner"))).toMatchObject({
      error: "not-applicable",
    });
    // unrestricting what isn't restricted
    refused({ unrestrict: projects.nodeId });
    // a checkpoint belongs to an unverified node
    refused({ checkpoint: { state: ns.state, rekey: rekeyTo(plans.nodeId, 2) } });

    // the same person twice
    write(bob, w, plans, { add: share(dan, "viewer") });
    const w2 = world([projects, plans]);
    expect(applyIntent(w2, st(w2, plans.nodeId), { add: share(dan, "editor") }, me)).toMatchObject({
      error: "not-applicable",
    });
    expect(applyIntent(w2, st(w2, plans.nodeId), { role: { userId: dan.id, role: "viewer" } }, me)).toMatchObject({
      error: "not-applicable",
    });
  });

  it("a stale node takes nothing but a re-key, a removal with one, or a leave", () => {
    const f = folder();
    f.add(
      carol,
      { ...f.last().state, shares: f.last().state.shares.filter((s) => s.userId !== carol.id) },
      [],
      "leave",
    );
    const w = world([f]);
    const ns = st(w, f.nodeId);
    expect(writable(ns)).toBe("stale");
    expect(applyIntent(w, ns, { add: share(eve, "viewer") }, share(bob, "editor"))).toMatchObject({
      error: "not-applicable",
      why: expect.stringContaining("stale"),
    });
    expect(applyIntent(w, ns, { move: crypto.randomUUID() }, share(bob, "editor"))).toMatchObject({
      error: "not-applicable",
    });
    expect("error" in applyIntent(w, ns, { leave: true }, share(dan, "viewer"))).toBe(false);
    expect("error" in applyIntent(w, ns, { rekey: rekeyTo(f.nodeId, 2) }, share(bob, "editor"))).toBe(false);
    expect("error" in applyIntent(w, ns, { remove: dan.id, rekey: rekeyTo(f.nodeId, 2) }, share(alice, "owner"))).toBe(
      false,
    );
    // the re-key clears it
    write(bob, w, f, { rekey: rekeyTo(f.nodeId, 2) });
    expect(writable(st(world([f]), f.nodeId))).toBe("ok");
  });

  it("refuses to sign what the fold would skip", () => {
    const { projects, plans } = tree();
    const w = world([projects, plans]);
    const ns = st(w, plans.nodeId);
    // a viewer adding someone: applies to the state, but the fold would skip it
    const byCarol = nextSnapshot(carol.account, w, ns, { add: share(dan, "viewer") }, at);
    expect(byCarol).toMatchObject({ error: expect.any(String) });
    // an editor removing someone
    plans.add(alice, childState(projects.nodeId, { shares: [share(dan, "viewer")] }), [projects.dep()]);
    const w2 = world([projects, plans]);
    const byBob = nextSnapshot(
      bob.account,
      w2,
      st(w2, plans.nodeId),
      { remove: dan.id, rekey: rekeyTo(plans.nodeId, 2) },
      at,
    );
    expect(byBob).toMatchObject({ error: expect.any(String) });
    // an author this account doesn't resolve can't check their own work
    const strangerWorld = world([projects, plans], { identity: (u, k) => (u === bob.id ? "unknown" : known(u, k)) });
    expect(
      nextSnapshot(
        bob.account,
        strangerWorld,
        st(strangerWorld, plans.nodeId),
        { rekey: rekeyTo(plans.nodeId, 2) },
        at,
      ),
    ).toMatchObject({
      error: expect.any(String),
    });
    // nothing was appended by the refusals
    expect(plans.entries.length).toBe(2);
  });

  it("a restricted node keeps an owner", () => {
    const p = folder();
    const c = Log.create(
      alice,
      childState(p.nodeId, { restricted: true, shares: [share(alice, "owner"), share(dan, "editor")] }),
      [p.dep()],
    );
    const w = world([p, c]);
    const ns = st(w, c.nodeId);
    expect(ns.status).toEqual(verified);
    const me = share(alice, "owner");
    // the intents that would leave it ownerless are refused
    // (coded, so an app offers a hand-over without reading the words)
    const keepsOwner = { error: "not-applicable", code: "sole_owner" };
    expect(applyIntent(w, ns, { remove: alice.id, rekey: rekeyTo(c.nodeId, 2) }, me)).toMatchObject(keepsOwner);
    expect(applyIntent(w, ns, { role: { userId: alice.id, role: "editor" } }, me)).toMatchObject(keepsOwner);
    expect(applyIntent(w, ns, { leave: true }, me)).toMatchObject(keepsOwner);
    expect(nextSnapshot(alice.account, w, ns, { leave: true }, new Date().toISOString())).toMatchObject({
      code: "sole_owner",
    });
    // and the fold skips a signed one all the same
    c.add(
      alice,
      { ...ns.state, shares: [share(dan, "editor")], version: 2, keyCommit: commitFor(c.nodeId, 2, key(2)) },
      [p.dep()],
    );
    c.add(alice, { ...ns.state, shares: [share(alice, "editor"), share(dan, "editor")] }, [p.dep()]);
    c.add(alice, { ...ns.state, shares: [share(dan, "editor")] }, [p.dep()], "leave");
    const after = st(world([p, c]), c.nodeId);
    expect(after.status).toEqual(verified);
    expect(after.seq).toBe(3);
    expect(after.state.version).toBe(1);
    expect(roleOf(after, alice)).toBe("owner");
    // with another owner, she may go
    write(alice, world([p, c]), c, { role: { userId: dan.id, role: "owner" } });
    write(alice, world([p, c]), c, { leave: true });
    const gone = st(world([p, c]), c.nodeId);
    expect(gone.status).toEqual(verified);
    expect(shareIds(gone)).toEqual(ids(dan));
  });

  it("a lapsed addition isn't laundered", () => {
    // carol, an editor on Projects, adds dave on Plans; then alice removes carol from Projects
    const projects = Log.create(
      alice,
      folderState({ shares: [share(alice, "owner"), share(bob, "editor"), share(carol, "editor")] }),
    );
    const plans = Log.create(bob, childState(projects.nodeId), [projects.dep()]);
    plans.add(carol, childState(projects.nodeId, { shares: [share(dan, "viewer")] }), [projects.dep()]);
    expect(shareIds(st(world([projects, plans]), plans.nodeId))).toEqual(ids(dan));
    projects.add(
      alice,
      folderState({
        shares: [share(alice, "owner"), share(bob, "editor")],
        version: 2,
        keyCommit: commitFor(projects.nodeId, 2, key(2)),
      }),
    );
    let w = world([projects, plans]);
    let ns = st(w, plans.nodeId);
    expect(ns.status).toEqual(verified);
    // dave's share lapsed with carol's authority
    expect(shareIds(ns)).toEqual([]);
    // bob re-keys from the effective state: dave stays out, and the deps name Projects where carol's removal is
    const s = write(bob, w, plans, { rekey: rekeyTo(plans.nodeId, 2) });
    expect(s.state.shares).toEqual([]);
    expect(s.deps).toContainEqual(projects.dep());
    w = world([projects, plans]);
    ns = st(w, plans.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.seq).toBe(2);
    expect(ns.state.version).toBe(2);
    expect(shareIds(ns)).toEqual([]);
    expect(ns.stale).toBe(false);
    // dave comes back only by an explicit re-add
    write(bob, w, plans, { add: share(dan, "viewer") });
    expect(shareIds(st(world([projects, plans]), plans.nodeId))).toEqual(ids(dan));
  });

  it("a lapsed entry dropped at the named deps isn't judged a removal by a verifier with an older view that then fetches the dep", () => {
    const projects = Log.create(
      alice,
      folderState({ shares: [share(alice, "owner"), share(bob, "editor"), share(carol, "editor")] }),
    );
    const plans = Log.create(bob, childState(projects.nodeId), [projects.dep()]);
    plans.add(carol, childState(projects.nodeId, { shares: [share(dan, "viewer")] }), [projects.dep()]);
    projects.add(
      alice,
      folderState({
        shares: [share(alice, "owner"), share(bob, "editor")],
        version: 2,
        keyCommit: commitFor(projects.nodeId, 2, key(2)),
      }),
    );
    write(bob, world([projects, plans]), plans, { rekey: rekeyTo(plans.nodeId, 2) });
    // a verifier still shown Projects before carol's removal can't judge bob's re-key yet
    const older = world([projects.upTo(1), plans]);
    const then = st(older, plans.nodeId);
    expect(then.status).toMatchObject({ kind: "unverified", atSeq: 2, reason: "stale-dependency" });
    // while it can't, it reads the re-key conservatively: dave is out, nothing is skipped (§3.5)
    expect(shareIds(then)).toEqual([]);
    // once it fetches the dep, dropping dave is no removal: the re-key applies, nothing is stale
    const fresh = world([projects, plans]);
    const now = st(fresh, plans.nodeId);
    expect(now.status).toEqual(verified);
    expect(now.seq).toBe(2);
    expect(shareIds(now)).toEqual([]);
    expect(now.stale).toBe(false);
  });

  it("an ownerless restricted node isn't a valid origin, and an existing one isn't frozen", () => {
    const p = Log.create(alice, folderState({ shares: [share(alice, "owner"), share(bob, "editor")] }));
    // signed: unverified from its first entry
    const c = Log.create(
      alice,
      childState(p.nodeId, { restricted: true, shares: [share(bob, "editor"), share(carol, "viewer")] }),
      [p.dep()],
    );
    expect(st(world([p, c]), c.nodeId).status).toMatchObject({ kind: "unverified", atSeq: 0, reason: "owner" });
    // one with an owner group is fine
    const g = group([dan]);
    const byGroup = Log.create(
      alice,
      childState(p.nodeId, { restricted: true, shares: [], groupShares: [{ groupId: g.id, role: "owner" }] }),
      [p.dep()],
    );
    expect(st(world([p, byGroup], { groups: view([g]) }), byGroup.nodeId).status).toEqual(verified);

    // legacy data: an ownerless restricted node from before the log
    const legacyId = crypto.randomUUID();
    const state = childState(p.nodeId, {
      restricted: true,
      shares: [share(bob, "editor"), share(carol, "viewer")],
      keyCommit: keyCommit(legacyId, 1, key(1)),
    });
    const leaves: LegacyLeaf[] = [{ nodeId: legacyId, state }];
    const legacy = new Log(legacyId).push(
      legacySnapshot({ nodeId: legacyId, state }, merkleProof(leaves, legacyId) as string[]),
    );
    const over = { legacyRoot: merkleRoot(leaves) };
    let w = world([p, legacy], over);
    expect(st(w, legacyId).status).toEqual(verified);
    expect(writable(st(w, legacyId))).toBe("ok");
    // carol can leave
    write(carol, w, legacy, { leave: true });
    w = world([p, legacy], over);
    expect(st(w, legacyId).status).toEqual(verified);
    expect(shareIds(st(w, legacyId))).toEqual(ids(bob));
    expect(writable(st(w, legacyId))).toBe("stale");
    // bob can re-key
    write(bob, w, legacy, { rekey: { version: 2, keyCommit: keyCommit(legacyId, 2, key(2)) } });
    w = world([p, legacy], over);
    expect(st(w, legacyId).state.version).toBe(2);
    expect(writable(st(w, legacyId))).toBe("ok");
    // adding an owner isn't refused for want of one; it needs owner authority, which nobody here has
    expect("error" in applyIntent(w, st(w, legacyId), { add: share(alice, "owner") }, share(bob, "editor"))).toBe(
      false,
    );
    expect(nextSnapshot(bob.account, w, st(w, legacyId), { add: share(alice, "owner") }, at)).toMatchObject({
      error: expect.stringContaining("skip"),
    });

    // restricting with no owner left is still refused, also from a node with no shares of its own
    const open = Log.create(bob, childState(p.nodeId), [p.dep()]);
    open.add(
      alice,
      { ...open.last().state, restricted: true, version: 2, keyCommit: commitFor(open.nodeId, 2, key(2)) },
      [p.dep()],
    );
    const ons = st(world([p, open]), open.nodeId);
    expect(ons.status).toEqual(verified);
    expect(ons.state.restricted).toBe(false);
    expect(ons.state.version).toBe(1);
  });

  it("a checkpoint that moves the node names its new parent", () => {
    const projects = Log.create(alice, folderState({ shares: [share(alice, "owner"), share(bob, "editor")] }));
    const archive = Log.create(alice, childState(projects.nodeId, { kind: "folder" }), [projects.dep()]);
    const plans = Log.create(bob, childState(projects.nodeId, { shares: [share(dan, "viewer")] }), [projects.dep()]);
    plans.add(alice, { ...plans.last().state, shares: [], version: 2, keyCommit: commitFor(plans.nodeId, 2, key(2)) }, [
      projects.dep(),
      hidden(),
    ]);
    const w = world([projects, archive, plans]);
    const ns = st(w, plans.nodeId);
    expect(ns.status.kind).toBe("unverified");
    const pre = { ...checkpointPrefill(ns, share(alice, "owner")), parentId: archive.nodeId };
    const s = write(alice, w, plans, {
      checkpoint: { state: pre, rekey: rekeyTo(plans.nodeId, ns.stretchVersion + 1) },
    });
    expect(s.deps.map((d) => d.log)).toContain(archive.nodeId);
    const after = st(world([projects, archive, plans]), plans.nodeId);
    expect(after.status).toEqual(verified);
    expect(after.state.parentId).toBe(archive.nodeId);
    expect(shareIds(after)).toEqual([]);
  });

  it("a retry after a lost race re-applies the intent", () => {
    const f = folder();
    const w = world([f]);
    const ns = st(w, f.nodeId);
    // two writers from the same head: carol leaves, alice removes dan
    const leave = nextSnapshot(carol.account, w, ns, { leave: true }, at);
    const remove = nextSnapshot(alice.account, w, ns, { remove: dan.id, rekey: rekeyTo(f.nodeId, 2) }, at);
    if ("error" in leave || "error" in remove) throw new Error("refused");
    expect(leave.prev).toBe(remove.prev);
    // alice's first attempt still named carol: sent as is, it would undo her leave
    expect(remove.state.shares.some((s) => s.userId === carol.id)).toBe(true);
    // carol's wins; the server refuses alice's (its prev isn't the head any more)
    f.push(leave);
    expect(remove.prev).not.toBe(snapshotHash(leave));
    // alice refetches and applies the intent again: carol stays gone, dan goes
    const w2 = world([f]);
    const ns2 = st(w2, f.nodeId);
    expect(writable(ns2)).toBe("stale");
    const retry = write(alice, w2, f, { remove: dan.id, rekey: rekeyTo(f.nodeId, 2) });
    expect(retry.prev).toBe(snapshotHash(leave));
    expect(retry.seq).toBe(2);
    const after = st(world([f]), f.nodeId);
    expect(after.status).toEqual(verified);
    expect(shareIds(after)).toEqual(ids(alice, bob));
    expect(after.state.version).toBe(2);
    expect(after.stale).toBe(false);
    // the re-key's seals go to who is left
    expect(
      reissueSet(world([f]), after)
        .people.map((s) => s.userId)
        .sort(),
    ).toEqual(ids(alice, bob));
  });
});
