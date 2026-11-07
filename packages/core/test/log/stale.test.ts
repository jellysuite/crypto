import { toBase64Url } from "@jelly/crypto";
import { describe, expect, it } from "vitest";
import {
  authorityDeps,
  type Change,
  createAccount,
  createFirstSnapshot,
  createSnapshot,
  type Dep,
  type GroupView,
  type LegacyLeaf,
  type LogEntry,
  LogWorld,
  legacySnapshot,
  merkleProof,
  merkleRoot,
  type NodeState,
  type Role,
  type Snapshot,
  type State,
  snapshotHash,
  unlockAccount,
  type WorldInput,
} from "../../src/index.ts";
import { appliedOf } from "../../src/log/fold.ts";

function user(handle: string) {
  const id = crypto.randomUUID();
  const acct = createAccount();
  const account = unlockAccount({ userId: id, handle, ak: acct.ak, bundle: acct.bundle });
  return { id, account, signPub: acct.bundle.signPub };
}
type U = ReturnType<typeof user>;

const alice = user("alice");
const bob = user("bob");
const carol = user("carol");
const dan = user("dan");
const eve = user("eve");
const people = [alice, bob, carol, dan, eve];

const at = "2026-10-31T12:00:00.000Z";
const commit = (n: number) => toBase64Url(new Uint8Array(32).fill(n));
const share = (u: U, role: Role) => ({ userId: u.id, role, signPub: u.signPub });
const known = (userId: string, signPub: string): "ok" | "unknown" | "mismatch" => {
  const u = people.find((x) => x.id === userId);
  return !u ? "unknown" : u.signPub === signPub ? "ok" : "mismatch";
};

/** A group's signed versions as the client verified them: the members at each version, from 0. */
type Group = { id: string; versions: U[][] };
const group = (...versions: U[][]): Group => ({ id: crypto.randomUUID(), versions });
const groupHead = (g: Group, v: number) => toBase64Url(new TextEncoder().encode(`${g.id}:${v}`));
const gdep = (g: Group, v = g.versions.length - 1): Dep => ({ log: `group:${g.id}`, seq: v, head: groupHead(g, v) });

function view(gs: Group[]): GroupView {
  const find = (id: string) => gs.find((g) => g.id === id);
  const has = (g: Group, v: number, userId: string) => g.versions[v]?.some((u) => u.id === userId) ?? false;
  return {
    latest: (id) => {
      const g = find(id);
      return g ? { version: g.versions.length - 1, head: groupHead(g, g.versions.length - 1) } : null;
    },
    member: (id, v, userId) => {
      const g = find(id);
      return g ? has(g, v, userId) : false;
    },
    removedAt: (id, userId, after) => {
      const g = find(id);
      if (!g) return null;
      for (let v = Math.max(after + 1, 1); v < g.versions.length; v++)
        if (has(g, v - 1, userId) && !has(g, v, userId)) return v;
      return null;
    },
    removedSince: (id, version) => {
      const g = find(id);
      if (!g) return false;
      const latest = g.versions.length - 1;
      return (g.versions[version] ?? []).some((u) => !has(g, latest, u.id));
    },
    teamGroups: () => null,
  };
}
const noGroups = view([]);

const rootState = (over: Partial<State> = {}): State => ({
  kind: "folder",
  parentId: null,
  anchor: { user: alice.id, signPub: alice.signPub },
  restricted: false,
  version: 1,
  keyCommit: commit(1),
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
  keyCommit: commit(1),
  shares: [],
  groupShares: [],
  links: [],
  ...over,
});

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
    return { log: this.nodeId, seq, head: snapshotHash(this.entries[seq] as Snapshot) };
  }
  add(by: U, state: State, deps: Dep[] = [], change: Change = "change", skipped: string[] = []): this {
    const prev = this.last();
    this.entries.push(
      createSnapshot(by.account, {
        nodeId: this.nodeId,
        seq: prev.seq + 1,
        prev: snapshotHash(prev),
        state,
        change,
        supersedes: null,
        skipped,
        nonce: null,
        deps,
        at,
      }),
    );
    return this;
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
/** Whether each node is stale, in one world. */
const staleOf = (w: LogWorld, ...logs: Log[]) =>
  logs.map((l) => {
    const ns = st(w, l.nodeId);
    expect(ns.status).toEqual(verified);
    return ns.stale;
  });

describe("stale versions (§5.2)", () => {
  it("a removal with its re-key leaves the node fresh", () => {
    const g = group([bob]);
    const base = rootState({
      shares: [share(alice, "owner"), share(bob, "editor"), share(carol, "viewer")],
      groupShares: [{ groupId: g.id, role: "viewer" }],
      links: [{ linkId: crypto.randomUUID(), role: "viewer" }],
    });
    const r = Log.create(alice, base);
    r.add(alice, { ...base, shares: base.shares.slice(0, 2), version: 2, keyCommit: commit(2) });
    r.add(alice, { ...base, shares: base.shares.slice(0, 2), groupShares: [], version: 3, keyCommit: commit(3) });
    r.add(alice, {
      ...base,
      shares: base.shares.slice(0, 2),
      groupShares: [],
      links: [],
      version: 4,
      keyCommit: commit(4),
    });
    const ns = st(world([r], { groups: view([g]) }), r.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.version).toBe(4);
    expect(shareIds(ns)).toEqual(ids(alice, bob));
    expect(ns.state.groupShares).toEqual([]);
    expect(ns.state.links).toEqual([]);
    expect(ns.stale).toBe(false);

    // and a child below a removal made before its key was made isn't stale either
    const c = Log.create(alice, childState(r.nodeId), [r.dep()]);
    expect(staleOf(world([r, c]), r, c)).toEqual([false, false]);
    // nor by a later change that removes nothing
    r.add(alice, { ...r.last().state, shares: [...r.last().state.shares, share(dan, "viewer")] });
    expect(staleOf(world([r, c]), r, c)).toEqual([false, false]);
  });

  it("leaving makes it stale", () => {
    const base = rootState({ shares: [share(alice, "owner"), share(bob, "editor"), share(carol, "viewer")] });
    const r = Log.create(alice, base);
    const c = Log.create(alice, childState(r.nodeId, { shares: [share(dan, "viewer")] }), [r.dep()]);
    // carol leaves the root: the root is stale, and so is its child, whose key she knew
    r.add(carol, { ...base, shares: base.shares.slice(0, 2) }, [], "leave");
    let w = world([r, c]);
    expect(staleOf(w, r, c)).toEqual([true, true]);
    expect(w.role(carol.id, c.nodeId)).toBeNull();
    expect(w.role(dan.id, c.nodeId)).toBe("viewer");

    // the root's re-key makes it fresh; the child stays stale until its own
    r.add(bob, { ...base, shares: base.shares.slice(0, 2), version: 2, keyCommit: commit(2) });
    w = world([r, c]);
    expect(staleOf(w, r, c)).toEqual([false, true]);
    c.add(
      bob,
      childState(r.nodeId, { shares: [share(dan, "viewer")], version: 2, keyCommit: commit(2) }),
      authorityDeps(w, c.nodeId),
    );
    expect(staleOf(world([r, c]), r, c)).toEqual([false, false]);
  });

  it("an ancestor's removal makes unrestricted descendants stale, not restricted ones", () => {
    const base = rootState({ shares: [share(alice, "owner"), share(bob, "editor"), share(carol, "viewer")] });
    const g = Log.create(alice, base);
    const c = Log.create(alice, childState(g.nodeId, { kind: "folder" }), [g.dep()]);
    const gc = Log.create(alice, childState(c.nodeId), [c.dep(), g.dep()]);
    const r = Log.create(
      alice,
      childState(g.nodeId, { restricted: true, shares: [share(alice, "owner"), share(dan, "editor")] }),
      [g.dep()],
    );
    const below = Log.create(alice, childState(r.nodeId), [r.dep(), g.dep()]);
    expect(staleOf(world([g, c, gc, r, below]), g, c, gc, r, below)).toEqual([false, false, false, false, false]);

    // bob is removed from the root, with its re-key
    g.add(alice, {
      ...base,
      shares: [share(alice, "owner"), share(carol, "viewer")],
      version: 2,
      keyCommit: commit(2),
    });
    let w = world([g, c, gc, r, below]);
    expect(staleOf(w, g, c, gc, r, below)).toEqual([false, true, true, false, false]);

    // re-keying the folder makes it fresh, not the page below it, whose key bob knew too
    c.add(
      alice,
      childState(g.nodeId, { kind: "folder", version: 2, keyCommit: commit(2) }),
      authorityDeps(w, c.nodeId),
    );
    w = world([g, c, gc, r, below]);
    expect(staleOf(w, c, gc)).toEqual([false, true]);
    gc.add(alice, childState(c.nodeId, { version: 2, keyCommit: commit(2) }), authorityDeps(w, gc.nodeId));
    expect(staleOf(world([g, c, gc, r, below]), c, gc)).toEqual([false, false]);

    // a removal on the restricted node's own parent chain doesn't reach below it, but one on itself does
    r.add(
      alice,
      childState(g.nodeId, { restricted: true, shares: [share(alice, "owner")], version: 2, keyCommit: commit(2) }),
      [g.dep()],
    );
    expect(staleOf(world([g, c, gc, r, below]), r, below)).toEqual([false, true]);
  });

  it("an ancestor that restricts itself makes what is below it stale", () => {
    const base = rootState({ shares: [share(alice, "owner"), share(carol, "viewer")] });
    const g = Log.create(alice, base);
    const f = Log.create(alice, childState(g.nodeId, { kind: "folder", shares: [share(alice, "owner")] }), [g.dep()]);
    const x = Log.create(alice, childState(f.nodeId), [f.dep(), g.dep()]);
    f.add(
      alice,
      childState(g.nodeId, {
        kind: "folder",
        shares: [share(alice, "owner")],
        restricted: true,
        version: 2,
        keyCommit: commit(2),
      }),
      [g.dep()],
    );
    const w = world([g, f, x]);
    expect(st(w, f.nodeId).state.restricted).toBe(true);
    expect(staleOf(w, f, x)).toEqual([false, true]);
    expect(w.role(carol.id, x.nodeId)).toBeNull();
  });

  it("a group removal makes stale only its sharers' subtrees", () => {
    const team = group([bob, carol], [bob]);
    const gv = view([team]);
    const r = Log.create(alice, rootState());
    const a = Log.create(
      alice,
      childState(r.nodeId, { kind: "folder", groupShares: [{ groupId: team.id, role: "viewer" }] }),
      [r.dep(), gdep(team, 0)],
    );
    const a1 = Log.create(alice, childState(a.nodeId), [a.dep(), r.dep(), gdep(team, 0)]);
    const a2 = Log.create(alice, childState(a.nodeId, { restricted: true, shares: [share(alice, "owner")] }), [
      a.dep(),
      r.dep(),
    ]);
    const b = Log.create(alice, childState(r.nodeId, { kind: "folder" }), [r.dep()]);
    const b1 = Log.create(alice, childState(b.nodeId), [b.dep(), r.dep()]);
    const d = Log.create(alice, childState(r.nodeId, { groupShares: [{ groupId: team.id, role: "editor" }] }), [
      r.dep(),
      gdep(team, 0),
    ]);
    // one that named the group version showing carol gone is fresh
    const later = Log.create(alice, childState(r.nodeId, { groupShares: [{ groupId: team.id, role: "editor" }] }), [
      r.dep(),
      gdep(team, 1),
    ]);
    let w = world([r, a, a1, a2, b, b1, d, later], { groups: gv });
    expect(staleOf(w, r, a, a1, a2, b, b1, d, later)).toEqual([false, true, true, false, false, false, true, false]);

    // a re-key naming the newer group version makes it fresh
    a1.add(alice, childState(a.nodeId, { version: 2, keyCommit: commit(2) }), authorityDeps(w, a1.nodeId));
    w = world([r, a, a1, a2, b, b1, d, later], { groups: gv });
    expect(staleOf(w, a, a1)).toEqual([true, false]);

    // without the removal nothing is stale
    const same = view([
      {
        id: team.id,
        versions: [
          [bob, carol],
          [bob, carol, dan],
        ],
      },
    ]);
    w = world([r, a, a2, b, d], { groups: same });
    expect(staleOf(w, a, a2, b, d)).toEqual([false, false, false, false]);
  });

  it("a move into a restricted area is stale, a move between open folders isn't", () => {
    const r = Log.create(
      alice,
      rootState({ shares: [share(alice, "owner"), share(bob, "editor"), share(carol, "viewer")] }),
    );
    const z = Log.create(
      alice,
      childState(r.nodeId, { kind: "folder", restricted: true, shares: [share(alice, "owner"), share(bob, "editor")] }),
      [r.dep()],
    );
    const p = Log.create(alice, childState(r.nodeId, { kind: "folder" }), [r.dep()]);
    const q = Log.create(alice, childState(r.nodeId, { kind: "folder" }), [r.dep()]);
    const n = Log.create(alice, childState(p.nodeId), [p.dep(), r.dep()]);
    const m = Log.create(alice, childState(p.nodeId), [p.dep(), r.dep()]);
    n.add(alice, childState(z.nodeId), [p.dep(), z.dep(), r.dep()]);
    m.add(bob, childState(q.nodeId), [p.dep(), q.dep(), r.dep()]);
    const w = world([r, z, p, q, n, m]);
    expect(st(w, n.nodeId).state.parentId).toBe(z.nodeId);
    expect(st(w, m.nodeId).state.parentId).toBe(q.nodeId);
    expect(staleOf(w, n, m)).toEqual([true, false]);
    expect(w.role(carol.id, n.nodeId)).toBeNull();
    // re-keyed there, it's fresh
    n.add(bob, childState(z.nodeId, { version: 2, keyCommit: commit(2) }), authorityDeps(w, n.nodeId));
    expect(staleOf(world([r, z, p, q, n, m]), n)).toEqual([false]);
  });

  it("a lapsed move falling back from where the key was made is stale", () => {
    const g = Log.create(alice, rootState());
    const p1 = Log.create(alice, childState(g.nodeId, { kind: "folder" }), [g.dep()]);
    const p2 = Log.create(alice, childState(g.nodeId, { kind: "folder", shares: [share(bob, "editor")] }), [g.dep()]);
    const c = Log.create(alice, childState(p1.nodeId, { shares: [share(bob, "editor"), share(carol, "editor")] }), [
      p1.dep(),
      g.dep(),
    ]);
    c.add(bob, childState(p2.nodeId, { shares: [share(bob, "editor"), share(carol, "editor")] }), [
      p1.dep(),
      p2.dep(),
      g.dep(),
    ]);
    let w = world([g, p1, p2, c]);
    expect(st(w, c.nodeId).state.parentId).toBe(p2.nodeId);
    c.add(
      carol,
      childState(p2.nodeId, {
        shares: [share(bob, "editor"), share(carol, "editor")],
        version: 2,
        keyCommit: commit(2),
      }),
      authorityDeps(w, c.nodeId),
    );
    w = world([g, p1, p2, c]);
    expect(staleOf(w, c)).toEqual([false]);
    // bob loses editor on the folder he moved it to: the move lapses, back to where the key wasn't made
    p2.add(alice, childState(g.nodeId, { kind: "folder", version: 2, keyCommit: commit(2) }), [g.dep()]);
    w = world([g, p1, p2, c]);
    expect(st(w, c.nodeId).state.parentId).toBe(p1.nodeId);
    expect(staleOf(w, c)).toEqual([true]);
  });

  it("a legacy version without a commit is stale for writing", () => {
    const owner = share(alice, "owner");
    const leaves: LegacyLeaf[] = [
      { nodeId: crypto.randomUUID(), state: rootState({ shares: [owner], keyCommit: null }) },
      { nodeId: crypto.randomUUID(), state: rootState({ shares: [owner] }) },
    ];
    const legacyRoot = merkleRoot(leaves);
    const logs: [string, LogEntry[]][] = leaves.map((l) => [
      l.nodeId,
      [legacySnapshot(l, merkleProof(leaves, l.nodeId) as string[])],
    ]);
    const w = world(logs, { legacyRoot });
    const [none, some] = leaves.map((l) => st(w, l.nodeId));
    expect(none?.status).toEqual(verified);
    expect(none?.stale).toBe(true);
    expect(some?.status).toEqual(verified);
    expect(some?.stale).toBe(false);

    // its first re-key gives it a commit, and it's fresh
    const nid = (leaves[0] as LegacyLeaf).nodeId;
    const log = new Log(nid);
    log.entries = [...(logs[0] as [string, LogEntry[]])[1]];
    log.add(alice, rootState({ shares: [owner], version: 2, keyCommit: commit(2) }));
    const ns = st(world([log], { legacyRoot }), nid);
    expect(ns.status).toEqual(verified);
    expect(ns.state.keyCommit).toBe(commit(2));
    expect(ns.stale).toBe(false);
  });

  it("a skipped member stays", () => {
    const base = rootState({ shares: [share(alice, "owner"), share(bob, "editor"), share(carol, "viewer")] });
    const r = Log.create(alice, base);
    // carol's account is reported deleted: she is left out of the seals, not out of the state
    r.add(alice, { ...base, version: 2, keyCommit: commit(2) }, [], "change", [carol.id]);
    let ns = st(world([r]), r.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.version).toBe(2);
    expect(shareIds(ns)).toEqual(ids(alice, bob, carol));
    expect(ns.stale).toBe(false);
    // also beside a removal
    r.add(
      alice,
      { ...base, shares: base.shares.slice(0, 1).concat(base.shares[2] ?? []), version: 3, keyCommit: commit(3) },
      [],
      "change",
      [carol.id],
    );
    ns = st(world([r]), r.nodeId);
    expect(shareIds(ns)).toEqual(ids(alice, carol));
    expect(ns.stale).toBe(false);
  });

  it("an ancestor the key didn't name counts from its start", () => {
    // root r, folders s (bob a viewer) and q, p under q, n under p; n's key names p, q and r
    const r = Log.create(alice, rootState());
    const sb = childState(r.nodeId, { kind: "folder", shares: [share(bob, "viewer")] });
    const s = Log.create(alice, sb, [r.dep()]);
    const q = Log.create(alice, childState(r.nodeId, { kind: "folder" }), [r.dep()]);
    const p = Log.create(alice, childState(q.nodeId, { kind: "folder" }), [q.dep(), r.dep()]);
    const n = Log.create(alice, childState(p.nodeId), [p.dep(), q.dep(), r.dep()]);
    // q moves under s: bob gains n, an addition, so nothing is stale yet
    q.add(alice, childState(s.nodeId, { kind: "folder" }), [r.dep(), s.dep()]);
    let w = world([r, s, q, p, n]);
    expect(w.role(bob.id, n.nodeId)).toBe("viewer");
    expect(staleOf(w, q, p, n)).toEqual([false, false, false]);
    // s removes bob with its re-key: everything below that bob could open is stale
    s.add(alice, { ...sb, shares: [], version: 2, keyCommit: commit(2) }, [r.dep()]);
    w = world([r, s, q, p, n]);
    expect(staleOf(w, s, q, p, n)).toEqual([false, true, true, true]);
    // one honest re-key naming what authorityDeps names clears it
    n.add(alice, childState(p.nodeId, { version: 2, keyCommit: commit(2) }), authorityDeps(w, n.nodeId));
    w = world([r, s, q, p, n]);
    expect(staleOf(w, p, n)).toEqual([true, false]);
  });

  it("a move into a restricted folder, from a chain the key named, is stale", () => {
    const r = Log.create(alice, rootState({ shares: [share(alice, "owner"), share(carol, "viewer")] }));
    const z = Log.create(
      alice,
      childState(r.nodeId, { kind: "folder", restricted: true, shares: [share(alice, "owner")] }),
      [r.dep()],
    );
    const q = Log.create(alice, childState(r.nodeId, { kind: "folder" }), [r.dep()]);
    const p = Log.create(alice, childState(q.nodeId, { kind: "folder" }), [q.dep(), r.dep()]);
    const n = Log.create(alice, childState(p.nodeId), [p.dep(), q.dep(), r.dep()]);
    expect(staleOf(world([r, z, q, p, n]), n)).toEqual([false]);
    n.add(alice, childState(z.nodeId), [p.dep(), q.dep(), z.dep(), r.dep()]);
    const w = world([r, z, q, p, n]);
    expect(st(w, n.nodeId).state.parentId).toBe(z.nodeId);
    expect(w.role(carol.id, n.nodeId)).toBeNull();
    expect(staleOf(w, n)).toEqual([true]);
  });

  it("someone added to an ancestor after the key and removed again makes it stale", () => {
    const base = rootState();
    const r = Log.create(alice, base);
    const n = Log.create(alice, childState(r.nodeId), [r.dep()]);
    r.add(alice, { ...base, shares: [...base.shares, share(eve, "viewer")] });
    expect(staleOf(world([r, n]), n)).toEqual([false]);
    r.add(alice, { ...base, version: 2, keyCommit: commit(2) });
    expect(staleOf(world([r, n]), r, n)).toEqual([false, true]);
  });

  it("a later change without a re-key doesn't move the floor", () => {
    const G = group([alice, bob, carol], [alice, bob]);
    const gv = view([G]);
    const r = Log.create(alice, rootState());
    const gs = [{ groupId: G.id, role: "viewer" as Role }];
    // the key doesn't name G: its version then is unknown
    const n = Log.create(alice, childState(r.nodeId, { groupShares: gs }), [r.dep()]);
    expect(staleOf(world([r, n], { groups: gv }), n)).toEqual([true]);
    n.add(alice, childState(r.nodeId, { groupShares: gs, shares: [share(dan, "viewer")] }), [r.dep(), gdep(G, 1)]);
    let w = world([r, n], { groups: gv });
    expect(staleOf(w, n)).toEqual([true]);
    n.add(
      alice,
      childState(r.nodeId, { groupShares: gs, shares: [share(dan, "viewer")], version: 2, keyCommit: commit(2) }),
      authorityDeps(w, n.nodeId),
    );
    w = world([r, n], { groups: gv });
    expect(staleOf(w, n)).toEqual([false]);

    // a group a later change adds counts from the version that change names
    const H = group([bob, carol], [bob]);
    const hv = view([G, H]);
    const m = Log.create(alice, childState(r.nodeId), [r.dep()]);
    const withH = Log.create(alice, childState(r.nodeId), [r.dep()]);
    m.add(alice, childState(r.nodeId, { groupShares: [{ groupId: H.id, role: "viewer" }] }), [r.dep(), gdep(H, 1)]);
    withH.add(alice, childState(r.nodeId, { groupShares: [{ groupId: H.id, role: "viewer" }] }), [r.dep(), gdep(H, 0)]);
    expect(staleOf(world([r, m, withH], { groups: hv }), m, withH)).toEqual([false, true]);
  });
});

describe("deps name the whole stretch up to the role (§4.4)", () => {
  /** alice's root r (carol a viewer), a restricted folder z of hers, and q > p > n > m, each naming every ancestor. */
  const setup = () => {
    const r = Log.create(alice, rootState({ shares: [share(alice, "owner"), share(carol, "viewer")] }));
    const z = Log.create(
      alice,
      childState(r.nodeId, { kind: "folder", restricted: true, shares: [share(alice, "owner")] }),
      [r.dep()],
    );
    const q = Log.create(alice, childState(r.nodeId, { kind: "folder" }), [r.dep()]);
    const p = Log.create(alice, childState(q.nodeId, { kind: "folder" }), [q.dep(), r.dep()]);
    const n = Log.create(alice, childState(p.nodeId, { kind: "folder" }), [p.dep(), q.dep(), r.dep()]);
    const m = Log.create(alice, childState(n.nodeId), [n.dep(), p.dep(), q.dep(), r.dep()]);
    return { r, z, q, p, n, m };
  };
  /** Re-keys each log from the effective state with authorityDeps, in order, and returns the world after. */
  const rekey = (logs: Log[], all: Log[]) => {
    for (const l of logs) {
      const w = world(all);
      const eff = st(w, l.nodeId).state;
      l.add(
        alice,
        { ...eff, version: eff.version + 1, keyCommit: commit(eff.version + 1) },
        authorityDeps(w, l.nodeId),
      );
    }
    return world(all);
  };

  it("an honest move of q into a restricted folder leaves what's below verified and stale", () => {
    const { r, z, q, p, n, m } = setup();
    const all = [r, z, q, p, n, m];
    q.add(alice, childState(z.nodeId, { kind: "folder" }), [r.dep(), z.dep()]);
    let w = world(all);
    expect(st(w, q.nodeId).state.parentId).toBe(z.nodeId);
    expect(staleOf(w, n, m)).toEqual([true, true]);
    expect(w.role(alice.id, n.nodeId)).toBe("owner");
    expect(w.role(alice.id, m.nodeId)).toBe("owner");
    expect(w.role(carol.id, n.nodeId)).toBeNull();
    w = rekey([p, n, m], all);
    expect(staleOf(w, p, n, m)).toEqual([false, false, false]);
  });

  it("restricting q in place leaves what's below verified and stale", () => {
    const { r, z, q, p, n, m } = setup();
    const all = [r, z, q, p, n, m];
    q.add(
      alice,
      childState(r.nodeId, {
        kind: "folder",
        restricted: true,
        shares: [share(alice, "owner")],
        version: 2,
        keyCommit: commit(2),
      }),
      [r.dep()],
    );
    let w = world(all);
    expect(st(w, q.nodeId).state.restricted).toBe(true);
    expect(staleOf(w, q, p, n, m)).toEqual([false, true, true, true]);
    expect(w.role(alice.id, n.nodeId)).toBe("owner");
    expect(w.role(carol.id, n.nodeId)).toBeNull();
    w = rekey([p, n, m], all);
    expect(staleOf(w, p, n, m)).toEqual([false, false, false]);
  });

  it("moving q away from the folder the creator's role came from leaves n verified and stale", () => {
    const r = Log.create(alice, rootState());
    const f = Log.create(alice, childState(r.nodeId, { kind: "folder", shares: [share(bob, "editor")] }), [r.dep()]);
    const s = Log.create(alice, childState(r.nodeId, { kind: "folder" }), [r.dep()]);
    const q = Log.create(alice, childState(f.nodeId, { kind: "folder" }), [f.dep(), r.dep()]);
    const p = Log.create(alice, childState(q.nodeId, { kind: "folder" }), [q.dep(), f.dep(), r.dep()]);
    // bob, an editor through f, names p, q, f and r
    const n = Log.create(bob, childState(p.nodeId), [p.dep(), q.dep(), f.dep(), r.dep()]);
    const all = [r, f, s, q, p, n];
    expect(staleOf(world(all), n)).toEqual([false]);
    q.add(alice, childState(s.nodeId, { kind: "folder" }), [r.dep(), s.dep(), f.dep()]);
    let w = world(all);
    expect(staleOf(w, n)).toEqual([true]);
    expect(w.role(alice.id, n.nodeId)).toBe("owner");
    expect(w.role(bob.id, n.nodeId)).toBeNull();
    // the re-key names f, the place q's move would fall back to, so the move can be judged
    expect(authorityDeps(w, n.nodeId).map((d) => d.log)).toContain(f.nodeId);
    w = rekey([n], all);
    expect(staleOf(w, n)).toEqual([false]);
  });

  it("moving q when the role comes from the root keeps it verified", () => {
    const { r, z, q, p, n, m } = setup();
    const s = Log.create(alice, childState(r.nodeId, { kind: "folder" }), [r.dep()]);
    q.add(alice, childState(s.nodeId, { kind: "folder" }), [r.dep(), s.dep()]);
    const w = world([r, z, s, q, p, n, m]);
    expect(staleOf(w, q, p, n, m)).toEqual([false, false, false, false]);
    expect(w.role(alice.id, m.nodeId)).toBe("owner");
  });

  it("an unnamed ancestor that never sat under the named log doesn't link to it", () => {
    // bob edits g; q has only ever been under h, dan's root
    const g = Log.create(alice, rootState({ shares: [share(alice, "owner"), share(bob, "editor")] }));
    const h = Log.create(
      dan,
      rootState({ anchor: { user: dan.id, signPub: dan.signPub }, shares: [share(dan, "owner")] }),
    );
    const q = Log.create(dan, childState(h.nodeId, { kind: "folder" }), [h.dep()]);
    const p = Log.create(dan, childState(q.nodeId, { kind: "folder" }), [q.dep(), h.dep()]);
    // bob names p and g, as if q led to g
    const x = Log.create(bob, childState(p.nodeId), [p.dep(), g.dep()]);
    const w = world([g, h, q, p, x]);
    expect(st(w, x.nodeId).status).toMatchObject({ kind: "unverified", atSeq: 0 });
    expect(w.role(bob.id, x.nodeId)).toBeNull();
  });

  it("a move without a re-key floors every log it names that the key didn't", () => {
    const r = Log.create(alice, rootState());
    const q2b = childState(r.nodeId, { kind: "folder", shares: [share(eve, "viewer")] });
    const q2 = Log.create(alice, q2b, [r.dep()]);
    const p2 = Log.create(alice, childState(q2.nodeId, { kind: "folder" }), [q2.dep(), r.dep()]);
    const p = Log.create(alice, childState(r.nodeId, { kind: "folder" }), [r.dep()]);
    const n = Log.create(alice, childState(p.nodeId), [p.dep(), r.dep()]);
    // eve leaves q2's folder before n gets there
    q2.add(alice, { ...q2b, shares: [], version: 2, keyCommit: commit(2) }, [r.dep()]);
    n.add(alice, childState(p2.nodeId), [p.dep(), p2.dep(), q2.dep(), r.dep()]);
    const w = world([r, q2, p2, p, n]);
    expect(st(w, n.nodeId).state.parentId).toBe(p2.nodeId);
    expect(staleOf(w, n)).toEqual([false]);
  });

  it("a folder's owner can't act on a subtree moved out of it", () => {
    // carol owns M, under alice's root; q > p > n sat under M, then alice moves q into her own restricted z
    const r = Log.create(alice, rootState());
    const mf = Log.create(alice, childState(r.nodeId, { kind: "folder", shares: [share(carol, "owner")] }), [r.dep()]);
    const z = Log.create(
      alice,
      childState(r.nodeId, { kind: "folder", restricted: true, shares: [share(alice, "owner")] }),
      [r.dep()],
    );
    const q = Log.create(alice, childState(mf.nodeId, { kind: "folder" }), [mf.dep(), r.dep()]);
    const p = Log.create(alice, childState(q.nodeId, { kind: "folder" }), [q.dep(), mf.dep(), r.dep()]);
    const n = Log.create(alice, childState(p.nodeId), [p.dep(), q.dep(), mf.dep(), r.dep()]);
    q.add(alice, childState(z.nodeId, { kind: "folder" }), [mf.dep(), z.dep(), r.dep()]);
    let w = world([r, mf, z, q, p, n]);
    expect(w.role(carol.id, n.nodeId)).toBeNull();
    const base = [...n.entries];
    // carol names M, with q left out or at its current state
    for (const deps of [
      [p.dep(), mf.dep()],
      [p.dep(), mf.dep(), r.dep()],
      [p.dep(), q.dep(), mf.dep()],
      [p.dep(), q.dep(), mf.dep(), r.dep()],
    ]) {
      const attempt = new Log(n.nodeId);
      attempt.entries = [...base];
      attempt.add(carol, childState(p.nodeId, { shares: [share(dan, "viewer")] }), deps);
      w = world([r, mf, z, q, p, attempt]);
      const ns = st(w, n.nodeId);
      expect(ns.status).toEqual(verified);
      expect(ns.seq).toBe(1);
      expect(ns.state.shares).toEqual([]);
      // skipped, not applied and then lapsed
      expect(appliedOf(ns)?.shares).toEqual([]);
      expect(w.role(carol.id, n.nodeId)).toBeNull();
      expect(w.role(dan.id, n.nodeId)).toBeNull();
    }
  });
});

describe("an unnamed place is a gap (§4.4)", () => {
  /** alice's root r with folders P (bob editor) and X (bob owner); n under P, which bob moves into X naming everything. */
  const movedByBob = (nShares: ReturnType<typeof share>[] = []) => {
    const r = Log.create(alice, rootState());
    const P = Log.create(alice, childState(r.nodeId, { kind: "folder", shares: [share(bob, "editor")] }), [r.dep()]);
    const X = Log.create(alice, childState(r.nodeId, { kind: "folder", shares: [share(bob, "owner")] }), [r.dep()]);
    const n = Log.create(alice, childState(P.nodeId, { shares: nShares }), [P.dep(), r.dep()]);
    n.add(bob, childState(X.nodeId, { shares: nShares }), [P.dep(), X.dep(), r.dep()]);
    expect(st(world([r, P, X, n]), n.nodeId).state.parentId).toBe(X.nodeId);
    // alice removes bob from P with a re-key: bob's move lapses and n sits at P again
    P.add(alice, childState(r.nodeId, { kind: "folder", version: 2, keyCommit: commit(2) }), [r.dep()]);
    const w = world([r, P, X, n]);
    expect(st(w, n.nodeId).state.parentId).toBe(P.nodeId);
    expect(w.role(bob.id, n.nodeId)).toBeNull();
    return { r, P, X, n };
  };
  /** The log with one more snapshot, in a copy. */
  const attempt = (n: Log, by: U, state: State, deps: Dep[]) => {
    const a = new Log(n.nodeId);
    a.entries = [...n.entries];
    a.add(by, state, deps);
    return a;
  };

  it("a lapsed mover can't act through the destination by leaving the fallback unnamed", () => {
    const { r, P, X, n } = movedByBob();
    for (const deps of [[X.dep(), r.dep()], [X.dep()], [P.dep(), X.dep(), r.dep()]]) {
      const a = attempt(n, bob, childState(X.nodeId, { shares: [share(dan, "viewer")] }), deps);
      const w = world([r, P, X, a]);
      const ns = st(w, n.nodeId);
      expect(ns.status).toEqual(verified);
      expect(appliedOf(ns)?.shares).toEqual([]);
      expect(ns.state.parentId).toBe(P.nodeId);
      expect(w.role(bob.id, n.nodeId)).toBeNull();
      expect(w.role(dan.id, n.nodeId)).toBeNull();
    }
  });

  it("a lapsed mover can't re-key through the destination by leaving the fallback unnamed", () => {
    const { r, P, X, n } = movedByBob([share(carol, "editor")]);
    const a = attempt(n, bob, childState(X.nodeId, { shares: [], version: 2, keyCommit: commit(9) }), [
      X.dep(),
      r.dep(),
    ]);
    const w = world([r, P, X, a]);
    const ns = st(w, n.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.version).toBe(1);
    expect(ns.state.keyCommit).toBe(commit(1));
    expect(shareIds(ns)).toEqual(ids(carol));
    expect(w.role(carol.id, n.nodeId)).toBe("editor");
    expect(w.role(bob.id, n.nodeId)).toBeNull();
  });

  it("an honest editor at the place a two-hop move fell back to applies with exactly authorityDeps", () => {
    const r = Log.create(alice, rootState());
    const P0 = Log.create(
      alice,
      childState(r.nodeId, { kind: "folder", shares: [share(bob, "editor"), share(dan, "editor")] }),
      [r.dep()],
    );
    const P1 = Log.create(alice, childState(r.nodeId, { kind: "folder", shares: [share(bob, "editor")] }), [r.dep()]);
    const P2 = Log.create(alice, childState(r.nodeId, { kind: "folder", shares: [share(bob, "editor")] }), [r.dep()]);
    const n = Log.create(alice, childState(P0.nodeId), [P0.dep(), r.dep()]);
    n.add(bob, childState(P1.nodeId), [P0.dep(), P1.dep(), r.dep()]);
    // the second hop names P0 too: the place the first would fall back to
    n.add(bob, childState(P2.nodeId), [P0.dep(), P1.dep(), P2.dep(), r.dep()]);
    expect(st(world([r, P0, P1, P2, n]), n.nodeId).state.parentId).toBe(P2.nodeId);
    // alice removes bob from P0: both hops lapse
    P0.add(
      alice,
      childState(r.nodeId, { kind: "folder", shares: [share(dan, "editor")], version: 2, keyCommit: commit(2) }),
      [r.dep()],
    );
    let w = world([r, P0, P1, P2, n]);
    expect(st(w, n.nodeId).state.parentId).toBe(P0.nodeId);
    expect(w.role(dan.id, n.nodeId)).toBe("editor");
    const deps = authorityDeps(w, n.nodeId);
    // every place in n's history, each with its chain
    expect(deps.map((d) => d.log).sort()).toEqual([r.nodeId, P0.nodeId, P1.nodeId, P2.nodeId].sort());
    n.add(dan, childState(P0.nodeId, { shares: [share(carol, "viewer")] }), deps);
    w = world([r, P0, P1, P2, n]);
    const ns = st(w, n.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.seq).toBe(3);
    expect(ns.state.parentId).toBe(P0.nodeId);
    expect(shareIds(ns)).toEqual(ids(carol));
    expect(w.role(carol.id, n.nodeId)).toBe("viewer");
  });

  it("a move whose voucher can only be seen through an unnamed group doesn't lapse for a writer at the fallback", () => {
    // eve edits P and X through G; she moves n from P to X. dan, an editor on P, names P, X and r but not G.
    const G = group([eve]);
    const gv = view([G]);
    const r = Log.create(alice, rootState());
    const P = Log.create(
      alice,
      childState(r.nodeId, {
        kind: "folder",
        shares: [share(dan, "editor")],
        groupShares: [{ groupId: G.id, role: "editor" }],
      }),
      [r.dep()],
    );
    const X = Log.create(
      alice,
      childState(r.nodeId, { kind: "folder", groupShares: [{ groupId: G.id, role: "editor" }] }),
      [r.dep()],
    );
    const n = Log.create(alice, childState(P.nodeId), [P.dep(), r.dep()]);
    n.add(eve, childState(X.nodeId), [P.dep(), X.dep(), r.dep(), gdep(G)]);
    let w = world([r, P, X, n], { groups: gv });
    expect(st(w, n.nodeId).state.parentId).toBe(X.nodeId);
    expect(w.role(dan.id, n.nodeId)).toBeNull();
    for (const deps of [
      [P.dep(), X.dep(), r.dep()],
      [P.dep(), X.dep(), r.dep(), gdep(G)],
    ]) {
      const a = attempt(n, dan, childState(X.nodeId, { shares: [share(carol, "viewer")] }), deps);
      w = world([r, P, X, a], { groups: gv });
      const ns = st(w, n.nodeId);
      expect(ns.status).toEqual(verified);
      expect(ns.seq).toBe(2);
      expect(appliedOf(ns)?.shares).toEqual([]);
      expect(ns.state.parentId).toBe(X.nodeId);
      expect(w.role(carol.id, n.nodeId)).toBeNull();
    }
  });
});

describe("a restriction the deps can't judge stands (§4.4)", () => {
  type GroupShare = { groupId: string; role: Role };
  /** alice's root r; folder P with dan an editor and group G (eve) an owner; n under P with carol an editor. */
  const setup = () => {
    const G = group([eve]);
    const gv = view([G]);
    const gs: GroupShare[] = [{ groupId: G.id, role: "owner" }];
    const r = Log.create(alice, rootState());
    const P = Log.create(
      alice,
      childState(r.nodeId, { kind: "folder", shares: [share(dan, "editor")], groupShares: gs }),
      [r.dep()],
    );
    const n = Log.create(alice, childState(P.nodeId, { shares: [share(carol, "editor")] }), [P.dep(), r.dep()]);
    return { G, gv, gs, r, P, n };
  };
  const attempt = (n: Log, by: U, state: State, deps: Dep[]) => {
    const a = new Log(n.nodeId);
    a.entries = [...n.entries];
    a.add(by, state, deps);
    return a;
  };

  it("an editor on the folder can't act on a node restricted through an unnamed group", () => {
    const { G, gv, r, P, n } = setup();
    const kept = [share(carol, "editor"), share(eve, "owner")];
    n.add(eve, childState(P.nodeId, { restricted: true, version: 2, keyCommit: commit(2), shares: kept }), [
      P.dep(),
      r.dep(),
      gdep(G),
    ]);
    let w = world([r, P, n], { groups: gv });
    expect(st(w, n.nodeId).state.restricted).toBe(true);
    expect(w.role(dan.id, n.nodeId)).toBeNull();
    for (const deps of [
      [P.dep(), r.dep()],
      [P.dep(), r.dep(), gdep(G)],
    ]) {
      // R1: a share added; R1c: a re-key with dan's own commit
      for (const state of [
        childState(P.nodeId, {
          restricted: true,
          version: 2,
          keyCommit: commit(2),
          shares: [...kept, share(bob, "viewer")],
        }),
        childState(P.nodeId, { restricted: true, version: 3, keyCommit: commit(9), shares: kept }),
      ]) {
        w = world([r, P, attempt(n, dan, state, deps)], { groups: gv });
        const ns = st(w, n.nodeId);
        expect(ns.status).toEqual(verified);
        expect(ns.state.version).toBe(2);
        expect(ns.state.keyCommit).toBe(commit(2));
        expect(shareIds(ns)).toEqual(ids(carol, eve));
        expect(
          appliedOf(ns)
            ?.shares.map((s) => s.userId)
            .sort(),
        ).toEqual(ids(carol, eve));
        expect(ns.stale).toBe(false);
        expect(w.role(bob.id, n.nodeId)).toBeNull();
      }
    }
    // eve, naming authorityDeps, adds bob
    w = world([r, P, n], { groups: gv });
    n.add(
      dan === eve ? alice : eve,
      childState(P.nodeId, {
        restricted: true,
        version: 2,
        keyCommit: commit(2),
        shares: [...kept, share(bob, "viewer")],
      }),
      authorityDeps(w, n.nodeId),
    );
    w = world([r, P, n], { groups: gv });
    expect(st(w, n.nodeId).status).toEqual(verified);
    expect(shareIds(st(w, n.nodeId))).toEqual(ids(bob, carol, eve));
  });

  it("a restriction whose author kept no share here makes the node stale: their authority came only from above", () => {
    const { G, gv, r, P, n } = setup();
    n.add(
      eve,
      childState(P.nodeId, { restricted: true, version: 2, keyCommit: commit(2), shares: [share(carol, "owner")] }),
      [P.dep(), r.dep(), gdep(G)],
    );
    const w = world([r, P, n], { groups: gv });
    const ns = st(w, n.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.restricted).toBe(true);
    expect(ns.stale).toBe(true);
    expect(w.role(eve.id, n.nodeId)).toBeNull();
  });

  /** F with dan an editor and G an owner; A under F, restricted by eve (who keeps an owner share); n under A. */
  const restrictedAncestor = () => {
    const G = group([eve]);
    const gv = view([G]);
    const r = Log.create(alice, rootState());
    const F = Log.create(
      alice,
      childState(r.nodeId, {
        kind: "folder",
        shares: [share(dan, "editor")],
        groupShares: [{ groupId: G.id, role: "owner" }],
      }),
      [r.dep()],
    );
    const A = Log.create(alice, childState(F.nodeId, { kind: "folder" }), [F.dep(), r.dep()]);
    const n = Log.create(alice, childState(A.nodeId), [A.dep(), F.dep(), r.dep()]);
    A.add(
      eve,
      childState(F.nodeId, {
        kind: "folder",
        restricted: true,
        version: 2,
        keyCommit: commit(2),
        shares: [share(eve, "owner")],
      }),
      [F.dep(), r.dep(), gdep(G)],
    );
    const w = world([r, F, A, n], { groups: gv });
    expect(st(w, A.nodeId).state.restricted).toBe(true);
    expect(w.role(dan.id, n.nodeId)).toBeNull();
    return { G, gv, r, F, A, n };
  };

  it("an editor above an ancestor restricted through an unnamed group can't act below it", () => {
    const { G, gv, r, F, A, n } = restrictedAncestor();
    for (const deps of [
      [A.dep(), F.dep(), r.dep()],
      [A.dep(), F.dep(), r.dep(), gdep(G)],
    ]) {
      const w = world([r, F, A, attempt(n, dan, childState(A.nodeId, { shares: [share(carol, "viewer")] }), deps)], {
        groups: gv,
      });
      const ns = st(w, n.nodeId);
      expect(ns.status).toEqual(verified);
      expect(appliedOf(ns)?.shares).toEqual([]);
      expect(w.role(carol.id, n.nodeId)).toBeNull();
    }
    // eve, the owner of A, can
    let w = world([r, F, A, n], { groups: gv });
    n.add(eve, childState(A.nodeId, { shares: [share(carol, "viewer")] }), authorityDeps(w, n.nodeId));
    w = world([r, F, A, n], { groups: gv });
    expect(st(w, n.nodeId).status).toEqual(verified);
    expect(w.role(carol.id, n.nodeId)).toBe("viewer");
  });

  it("nor create under it", () => {
    const { G, gv, r, F, A } = restrictedAncestor();
    for (const deps of [
      [A.dep(), F.dep(), r.dep()],
      [A.dep(), F.dep(), r.dep(), gdep(G)],
    ]) {
      const c = Log.create(dan, childState(A.nodeId), deps);
      const w = world([r, F, A, c], { groups: gv });
      expect(st(w, c.nodeId).status).toEqual({ kind: "unverified", atSeq: 0, reason: "origin" });
      expect(w.role(dan.id, c.nodeId)).toBeNull();
    }
    const c = Log.create(eve, childState(A.nodeId), [A.dep(), F.dep(), r.dep(), gdep(G)]);
    const w = world([r, F, A, c], { groups: gv });
    expect(st(w, c.nodeId).status).toEqual(verified);
    expect(w.role(eve.id, c.nodeId)).toBe("owner");
  });

  it("a dep that can't be checked, met only beyond a gap, leaves the snapshot unchecked rather than skipped", () => {
    // bob's lapsed move (as in the gap tests); he names X at a seq the client wasn't shown
    const r = Log.create(alice, rootState());
    const P = Log.create(alice, childState(r.nodeId, { kind: "folder", shares: [share(bob, "editor")] }), [r.dep()]);
    const X = Log.create(alice, childState(r.nodeId, { kind: "folder", shares: [share(bob, "owner")] }), [r.dep()]);
    const n = Log.create(alice, childState(P.nodeId), [P.dep(), r.dep()]);
    n.add(bob, childState(X.nodeId), [P.dep(), X.dep(), r.dep()]);
    P.add(alice, childState(r.nodeId, { kind: "folder", version: 2, keyCommit: commit(2) }), [r.dep()]);
    const newer = X.add(
      alice,
      childState(r.nodeId, { kind: "folder", shares: [share(bob, "owner")], version: 2, keyCommit: commit(2) }),
      [r.dep()],
    ).dep();
    X.entries.pop();
    n.add(bob, childState(X.nodeId, { shares: [share(dan, "viewer")] }), [newer, r.dep()]);
    const ns = st(world([r, P, X, n]), n.nodeId);
    expect(ns.status).toEqual({ kind: "unverified", atSeq: 2, reason: "stale-dependency" });
    expect(appliedOf(ns)?.shares).toEqual([]);
  });
});
