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
const everyone = [alice, bob, carol, dan, eve];

const at = "2026-10-30T10:00:00.000Z";
const commit = (n: number) => toBase64Url(new Uint8Array(32).fill(n));
const share = (u: U, role: Role) => ({ userId: u.id, role, signPub: u.signPub });

const noGroups: GroupView = {
  latest: () => null,
  member: () => false,
  removedAt: () => null,
  removedSince: () => false,
  teamGroups: () => null,
};
const known = (userId: string, signPub: string): "ok" | "unknown" | "mismatch" => {
  const u = everyone.find((x) => x.id === userId);
  return !u ? "unknown" : u.signPub === signPub ? "ok" : "mismatch";
};

const folderState = (over: Partial<State> = {}): State => ({
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
  /** Where this log is now, as a dep. */
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
  /** The log as the server might show it: only its first `n` entries. */
  upTo(n: number): LogEntry[] {
    return this.entries.slice(0, n);
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

/** alice's folder, bob editor and carol viewer on it. */
function folder(): Log {
  return Log.create(
    alice,
    folderState({ shares: [share(alice, "owner"), share(bob, "editor"), share(carol, "viewer")] }),
  );
}

describe("authority through parents and dependencies", () => {
  it("a child inherits roles from an unrestricted parent, not a restricted one", () => {
    const p = folder();
    const child = Log.create(bob, childState(p.nodeId), [p.dep()]);
    const w = world([p, child]);
    expect(st(w, child.nodeId).status).toEqual(verified);
    expect(w.role(alice.id, child.nodeId)).toBe("owner");
    expect(w.role(bob.id, child.nodeId)).toBe("editor");
    expect(w.role(carol.id, child.nodeId)).toBe("viewer");
    expect(w.role(dan.id, child.nodeId)).toBeNull();

    // a grandchild goes all the way up
    const grand = Log.create(bob, childState(child.nodeId), [child.dep(), p.dep()]);
    const w2 = world([p, child, grand]);
    expect(st(w2, grand.nodeId).status).toEqual(verified);
    expect(w2.role(carol.id, grand.nodeId)).toBe("viewer");

    // a restricted child gets nothing from its parent (it keeps an owner of its own, so alice makes it)
    const closed = Log.create(alice, childState(p.nodeId, { restricted: true, shares: [share(dan, "owner")] }), [
      p.dep(),
    ]);
    const w3 = world([p, closed]);
    expect(st(w3, closed.nodeId).status).toEqual(verified);
    expect(w3.role(carol.id, closed.nodeId)).toBeNull();
    expect(w3.role(alice.id, closed.nodeId)).toBeNull();
    expect(w3.role(dan.id, closed.nodeId)).toBe("owner");

    // the parent's role counts for later snapshots too: bob adds dan, relying on the folder
    child.add(bob, childState(p.nodeId, { shares: [share(dan, "viewer")] }), [p.dep()]);
    expect(shareIds(st(world([p, child]), child.nodeId))).toEqual(ids(dan));
    // without naming the folder, his role there doesn't count, and nothing else gives him one
    child.add(bob, childState(p.nodeId, { shares: [share(dan, "viewer"), share(eve, "viewer")] }));
    const ns = st(world([p, child]), child.nodeId);
    expect(ns.status).toEqual(verified);
    expect(shareIds(ns)).toEqual(ids(dan));

    // an unverified parent gives no role, and the unrestricted child under it is unverified
    const shaky = folder();
    const under = Log.create(bob, childState(shaky.nodeId), [shaky.dep()]);
    // a re-key relying on a log the server doesn't show isn't checkable yet
    shaky.add(
      alice,
      folderState({
        shares: [share(alice, "owner"), share(bob, "editor"), share(carol, "viewer")],
        version: 2,
        keyCommit: commit(2),
      }),
      [{ log: crypto.randomUUID(), seq: 1, head: commit(9) }],
    );
    const w4 = world([shaky, under]);
    expect(st(w4, shaky.nodeId).status).toMatchObject({ kind: "unverified", atSeq: 1 });
    expect(st(w4, under.nodeId).status).toMatchObject({ kind: "unverified", reason: "needs-parent" });
    expect(w4.role(bob.id, under.nodeId)).toBeNull();
  });

  it("a viewer can't create under a folder", () => {
    const p = folder();
    const byViewer = Log.create(carol, childState(p.nodeId), [p.dep()]);
    const w = world([p, byViewer]);
    expect(st(w, byViewer.nodeId).status).toMatchObject({ kind: "unverified", atSeq: 0 });
    expect(st(w, byViewer.nodeId).state.shares).toEqual([]);

    const stranger = Log.create(dan, childState(p.nodeId), [p.dep()]);
    expect(st(world([p, stranger]), stranger.nodeId).status).toMatchObject({ kind: "unverified", atSeq: 0 });

    // the parent dep must be there
    const noDep = Log.create(bob, childState(p.nodeId));
    expect(st(world([p, noDep]), noDep.nodeId).status).toMatchObject({
      kind: "unverified",
      atSeq: 0,
      reason: "needs-dep",
    });

    // an editor may create; an owner share in the child needs owner on the parent
    const byEditor = Log.create(bob, childState(p.nodeId, { shares: [share(dan, "editor")] }), [p.dep()]);
    expect(st(world([p, byEditor]), byEditor.nodeId).status).toEqual(verified);
    const selfOwner = Log.create(bob, childState(p.nodeId, { shares: [share(bob, "owner")] }), [p.dep()]);
    expect(st(world([p, selfOwner]), selfOwner.nodeId).status).toMatchObject({ kind: "unverified", atSeq: 0 });
    const byOwner = Log.create(alice, childState(p.nodeId, { shares: [share(bob, "owner")] }), [p.dep()]);
    expect(st(world([p, byOwner]), byOwner.nodeId).status).toEqual(verified);
  });

  it("a creation naming its parent and the root but not the folder between is skipped", () => {
    const g = folder();
    const c = Log.create(alice, childState(g.nodeId, { kind: "folder" }), [g.dep()]);
    const d = Log.create(alice, childState(c.nodeId, { kind: "folder" }), [c.dep(), g.dep()]);
    const x = Log.create(bob, childState(d.nodeId), [d.dep(), g.dep()]);
    const w = world([g, c, d, x]);
    // a seq 0 can't be skipped: the node is unverified at its origin
    expect(st(w, x.nodeId).status).toEqual({ kind: "unverified", atSeq: 0, reason: "origin" });
    expect(w.role(bob.id, x.nodeId)).toBeNull();
    // naming the whole stretch, it verifies
    const full = Log.create(bob, childState(d.nodeId), [d.dep(), c.dep(), g.dep()]);
    const w2 = world([g, c, d, full]);
    expect(st(w2, full.nodeId).status).toEqual(verified);
    expect(w2.role(bob.id, full.nodeId)).toBe("editor");
  });

  it("deps never go backwards", () => {
    const p = folder();
    const child = Log.create(bob, childState(p.nodeId), [p.dep()]);
    p.add(
      alice,
      folderState({ shares: [share(alice, "owner"), share(bob, "editor"), share(carol, "viewer")], links: [] }),
    );
    p.add(alice, folderState({ shares: [share(alice, "owner"), share(bob, "editor"), share(carol, "editor")] }));
    child.add(bob, childState(p.nodeId, { shares: [share(dan, "viewer")] }), [p.dep(2)]);
    child.add(bob, childState(p.nodeId, { shares: [share(dan, "viewer"), share(eve, "viewer")] }), [p.dep(1)]);
    const ns = st(world([p, child]), child.nodeId);
    expect(ns.status).toEqual(verified);
    expect(shareIds(ns)).toEqual(ids(dan));
    expect(ns.deps.get(p.nodeId)?.seq).toBe(2);
    // the same seq again is fine
    child.add(bob, childState(p.nodeId, { shares: [share(dan, "viewer"), share(eve, "viewer")] }), [p.dep(2)]);
    expect(shareIds(st(world([p, child]), child.nodeId))).toEqual(ids(dan, eve));
  });

  it("a stale ancestor log is refused", () => {
    const p = folder();
    p.add(alice, folderState({ shares: [share(alice, "owner"), share(bob, "editor"), share(carol, "editor")] }));
    const child = Log.create(bob, childState(p.nodeId), [p.dep(0)]);
    child.add(bob, childState(p.nodeId, { shares: [share(dan, "viewer")] }), [p.dep(1)]);

    // the server shows the folder as it was before the dep bob named
    const stale = st(world([[p.nodeId, p.upTo(1)], child]), child.nodeId);
    expect(stale.status).toMatchObject({ kind: "unverified", atSeq: 1, reason: "stale-dependency" });
    expect(stale.state.shares).toEqual([]);

    // or a fork of it
    const fork = new Log(p.nodeId);
    fork.entries = p.upTo(1);
    fork.add(alice, folderState({ shares: [share(alice, "owner"), share(bob, "editor")] }));
    expect(st(world([fork, child]), child.nodeId).status).toMatchObject({
      kind: "unverified",
      atSeq: 1,
      reason: "stale-dependency",
    });

    // or not at all
    const missing = st(world([child]), child.nodeId);
    expect(missing.status).toMatchObject({ kind: "unverified", atSeq: 0, reason: "stale-dependency" });

    // the full folder is fine
    expect(st(world([p, child]), child.nodeId).status).toEqual(verified);

    // an owner of the child naming a dep the server can't show is stale too
    const own = Log.create(alice, childState(p.nodeId, { shares: [share(bob, "owner")] }), [p.dep(0)]);
    own.add(bob, childState(p.nodeId, { shares: [share(bob, "owner"), share(dan, "viewer")] }), [p.dep(1)]);
    expect(st(world([[p.nodeId, p.upTo(1)], own]), own.nodeId).status).toMatchObject({
      kind: "unverified",
      atSeq: 1,
      reason: "stale-dependency",
    });
  });

  it("a removed editor's later addition doesn't count", () => {
    const p = folder();
    const child = Log.create(alice, childState(p.nodeId), [p.dep()]);
    const before = p.dep();
    // alice removes bob from the folder
    p.add(
      alice,
      folderState({ shares: [share(alice, "owner"), share(carol, "viewer")], version: 2, keyCommit: commit(2) }),
    );
    // bob signs an addition relying on the folder from before his removal
    child.add(bob, childState(p.nodeId, { shares: [share(dan, "editor")] }), [before]);
    const ns = st(world([p, child]), child.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.shares).toEqual([]);
    expect(world([p, child]).role(dan.id, child.nodeId)).toBeNull();
    // and once someone named the newer folder, relying on the old one is skipped
    child.add(alice, childState(p.nodeId, { shares: [share(eve, "viewer")] }), [p.dep()]);
    child.add(bob, childState(p.nodeId, { shares: [share(eve, "viewer"), share(dan, "editor")] }), [before]);
    expect(shareIds(st(world([p, child]), child.nodeId))).toEqual(ids(eve));
  });

  it("an honest addition survives its author's removal once someone with authority changes the node", () => {
    const p = folder();
    const child = Log.create(alice, childState(p.nodeId), [p.dep()]);
    child.add(bob, childState(p.nodeId, { shares: [share(dan, "editor")] }), [p.dep()]);
    const dropped = new Log(child.nodeId);
    dropped.entries = [...child.entries];
    child.add(alice, childState(p.nodeId, { shares: [share(dan, "editor"), share(eve, "viewer")] }), [p.dep()]);
    const whileBob = p.dep();
    p.add(
      alice,
      folderState({ shares: [share(alice, "owner"), share(carol, "viewer")], version: 2, keyCommit: commit(2) }),
    );

    const ns = st(world([p, child]), child.nodeId);
    expect(ns.status).toEqual(verified);
    expect(shareIds(ns)).toEqual(ids(dan, eve));

    // nobody with authority changed it: dan's share lapsed with bob's role
    const lapsed = st(world([p, dropped]), dropped.nodeId);
    expect(lapsed.status).toEqual(verified);
    expect(lapsed.state.shares).toEqual([]);
    // an honest writer leaves the lapsed entry out, naming the folder that shows it lapsed: not a removal
    const honest = new Log(child.nodeId);
    honest.entries = [...dropped.entries];
    honest.add(alice, childState(p.nodeId, { shares: [share(eve, "viewer")] }), [p.dep()]);
    const h = st(world([p, honest]), honest.nodeId);
    expect(h.status).toEqual(verified);
    expect(shareIds(h)).toEqual(ids(eve));
    // leaving it out against a folder where bob still held is a removal, and that needs a re-key
    const notLapsed = new Log(child.nodeId);
    notLapsed.entries = [...dropped.entries];
    notLapsed.add(alice, childState(p.nodeId, { shares: [share(eve, "viewer")] }), [whileBob]);
    expect(st(world([p, notLapsed]), notLapsed.nodeId).state.shares).toEqual([]);
    // re-adding it later is an addition by alice, and counts
    honest.add(alice, childState(p.nodeId, { shares: [share(eve, "viewer"), share(dan, "editor")] }), [p.dep()]);
    expect(shareIds(st(world([p, honest]), honest.nodeId))).toEqual(ids(dan, eve));
  });

  it("a looser role from a lapsed author falls back to the role before it", () => {
    const p = Log.create(alice, folderState({ shares: [share(alice, "owner"), share(bob, "owner")] }));
    const child = Log.create(alice, childState(p.nodeId, { shares: [share(dan, "viewer")] }), [p.dep()]);
    child.add(bob, childState(p.nodeId, { shares: [share(dan, "editor")] }), [p.dep()]);
    expect(st(world([p, child]), child.nodeId).state.shares).toEqual([share(dan, "editor")]);
    p.add(alice, folderState({ shares: [share(alice, "owner")], version: 2, keyCommit: commit(2) }));
    const ns = st(world([p, child]), child.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.shares).toEqual([share(dan, "viewer")]);
    // removals by him never lapse
    const removed = Log.create(alice, childState(p.nodeId, { shares: [share(dan, "viewer")] }), [p.dep(0)]);
    removed.add(bob, childState(p.nodeId, { version: 2, keyCommit: commit(2) }), [p.dep(0)]);
    expect(st(world([p, removed]), removed.nodeId).state.shares).toEqual([]);
  });

  it("floors: shorter or forked → rolled back, longer → verified", () => {
    const p = folder();
    p.add(
      alice,
      folderState({ shares: [share(alice, "owner"), share(bob, "editor")], version: 2, keyCommit: commit(2) }),
    );
    p.add(alice, folderState({ shares: [share(alice, "owner"), share(bob, "editor"), share(dan, "viewer")] }));
    const floor = (seq: number, head: string) => new Map([[p.nodeId, { seq, head }]]);

    const shorter = world([[p.nodeId, p.upTo(2)]], { floors: floor(2, p.dep(2).head) });
    expect(st(shorter, p.nodeId).status).toEqual({ kind: "rolled-back", log: p.nodeId });
    const forked = world([p], { floors: floor(1, commit(9)) });
    expect(st(forked, p.nodeId).status).toEqual({ kind: "rolled-back", log: p.nodeId });
    expect(st(world([p], { floors: floor(1, p.dep(1).head) }), p.nodeId).status).toEqual(verified);
    expect(st(world([p], { floors: floor(2, p.dep(2).head) }), p.nodeId).status).toEqual(verified);

    // a rolled-back ancestor gives no role
    const child = Log.create(bob, childState(p.nodeId), [p.dep(0)]);
    const w = world([p, child], { floors: floor(1, commit(9)) });
    expect(w.role(bob.id, child.nodeId)).toBeNull();
    expect(st(w, child.nodeId).status).toMatchObject({ kind: "unverified", reason: "needs-parent" });
  });

  it("authorityDeps names the parent and where the role comes from", () => {
    const p = folder();
    const child = Log.create(bob, childState(p.nodeId, { shares: [share(dan, "editor")] }), [p.dep()]);
    const grand = Log.create(bob, childState(child.nodeId), [child.dep(), p.dep()]);
    const w = world([p, child, grand]);
    // bob's role on the grandchild comes from the folder
    expect(authorityDeps(w, grand.nodeId)).toEqual([child.dep(), p.dep()]);
    // dan's from the child, whose share for him bob vouched for from the folder: both named
    expect(authorityDeps(w, grand.nodeId)).toEqual([child.dep(), p.dep()]);
    // on the child, bob's role is the folder's
    expect(authorityDeps(w, child.nodeId)).toEqual([p.dep()]);
    // a root has no parent, and its anchor is its own
    expect(authorityDeps(w, p.nodeId)).toEqual([]);
    // the deps it gives make a valid snapshot
    grand.add(bob, childState(child.nodeId, { shares: [share(eve, "viewer")] }), authorityDeps(w, grand.nodeId));
    expect(shareIds(st(world([p, child, grand]), grand.nodeId))).toEqual(ids(eve));
  });

  it("a parent cycle is unverified whichever log is folded first", () => {
    const a = crypto.randomUUID();
    const b = crypto.randomUUID();
    const leaves: LegacyLeaf[] = [
      { nodeId: a, state: childState(b, { shares: [share(alice, "owner")] }) },
      { nodeId: b, state: childState(a) },
    ];
    const legacyRoot = merkleRoot(leaves);
    const logs: [string, LogEntry[]][] = leaves.map((l) => [
      l.nodeId,
      [legacySnapshot(l, merkleProof(leaves, l.nodeId) as string[])],
    ]);
    const ab = world(logs, { legacyRoot });
    const sa = st(ab, a).status;
    const sb = st(ab, b).status;
    const ba = world(logs, { legacyRoot });
    expect(st(ba, b).status).toEqual(sb);
    expect(st(ba, a).status).toEqual(sa);
    expect(sa.kind).toBe("unverified");
    expect(sb.kind).toBe("unverified");
    expect(ab.role(alice.id, b)).toBeNull();
  });

  it("a removal from a folder doesn't undo the re-keys made below it", () => {
    const p = folder();
    const child = Log.create(alice, childState(p.nodeId), [p.dep()]);
    child.add(bob, childState(p.nodeId, { shares: [share(dan, "editor")] }), [p.dep()]);
    // dan's role comes from bob's addition, so he names the folder too
    child.add(dan, childState(p.nodeId, { shares: [share(dan, "editor")], version: 2, keyCommit: commit(2) }), [
      p.dep(),
    ]);
    child.add(alice, childState(p.nodeId, { shares: [share(dan, "editor")], version: 3, keyCommit: commit(3) }), [
      p.dep(),
    ]);
    child.add(
      alice,
      childState(p.nodeId, { shares: [share(dan, "editor"), share(eve, "viewer")], version: 3, keyCommit: commit(3) }),
      [p.dep()],
    );
    // something only bob vouched for
    child.add(
      bob,
      childState(p.nodeId, {
        shares: [share(dan, "editor"), share(eve, "viewer"), share(carol, "viewer")],
        version: 3,
        keyCommit: commit(3),
      }),
      [p.dep()],
    );
    p.add(
      alice,
      folderState({ shares: [share(alice, "owner"), share(carol, "viewer")], version: 2, keyCommit: commit(2) }),
    );

    const ns = st(world([p, child]), child.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.version).toBe(3);
    expect(ns.state.keyCommit).toBe(commit(3));
    // dan stays: alice's snapshots repeated him; carol had only bob
    expect(shareIds(ns)).toEqual(ids(dan, eve));
    // but bob, removed from the folder after it, knew the v3 key: stale (§5.2)
    expect(ns.stale).toBe(true);

    // and the owner's next re-key applies
    child.add(alice, childState(p.nodeId, { shares: [share(eve, "viewer")], version: 4, keyCommit: commit(4) }), [
      p.dep(),
    ]);
    const next = st(world([p, child]), child.nodeId);
    expect(next.status).toEqual(verified);
    expect(next.state.version).toBe(4);
    expect(shareIds(next)).toEqual(ids(eve));
    expect(next.stale).toBe(false);
  });

  it("a key made by someone whose authority lapsed is stale", () => {
    const p = folder();
    const before = p.dep();
    // an honest creation by bob, before he is removed
    const honest = Log.create(bob, childState(p.nodeId), [before]);
    const childOfAlice = Log.create(alice, childState(p.nodeId), [before]);
    expect(st(world([p, honest]), honest.nodeId).stale).toBe(false);
    p.add(
      alice,
      folderState({ shares: [share(alice, "owner"), share(carol, "viewer")], version: 2, keyCommit: commit(2) }),
    );

    let ns = st(world([p, honest]), honest.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.stale).toBe(true);
    // until someone with authority re-keys it
    honest.add(alice, childState(p.nodeId, { version: 2, keyCommit: commit(2) }), [p.dep()]);
    ns = st(world([p, honest]), honest.nodeId);
    expect(ns.stale).toBe(false);
    expect(ns.state.version).toBe(2);

    // a creation backdated to before his removal
    const backdated = Log.create(bob, childState(p.nodeId, { shares: [share(dan, "viewer")] }), [before]);
    ns = st(world([p, backdated]), backdated.nodeId);
    expect(ns.stale).toBe(true);
    expect(ns.state.shares).toEqual([]);

    // a re-key backdated the same way
    childOfAlice.add(bob, childState(p.nodeId, { version: 2, keyCommit: commit(2) }), [before]);
    ns = st(world([p, childOfAlice]), childOfAlice.nodeId);
    expect(ns.state.version).toBe(2);
    expect(ns.stale).toBe(true);
  });

  it("a dependency's states come from its one fold", () => {
    const p = folder();
    const n = 500;
    for (let i = 0; i < n; i++) p.add(alice, p.last().state);
    const child = Log.create(bob, childState(p.nodeId), [p.dep(0)]);
    for (let i = 1; i <= n; i++) child.add(bob, childState(p.nodeId, { version: 1 }), [p.dep(i)]);
    let aliceChecks = 0;
    const w = world([p, child], {
      identity: (id, pub) => {
        if (id === alice.id) aliceChecks++;
        return known(id, pub);
      },
    });
    const t = performance.now();
    const ns = st(w, child.nodeId);
    expect(performance.now() - t).toBeLessThan(2000);
    expect(ns.status).toEqual(verified);
    expect(ns.deps.get(p.nodeId)?.seq).toBe(n);
    expect(aliceChecks).toBe(n + 1);
  });

  it("a dep on a part of a log that isn't verified can't be judged: needs-parent, not stale", () => {
    const p = folder();
    const child = Log.create(alice, childState(p.nodeId), [p.dep()]);
    child.add(bob, childState(p.nodeId, { shares: [share(dan, "viewer")] }), [p.dep()]);
    p.add(
      alice,
      folderState({
        shares: [share(alice, "owner"), share(bob, "editor"), share(carol, "viewer")],
        version: 2,
        keyCommit: commit(2),
      }),
      [{ log: crypto.randomUUID(), seq: 1, head: commit(9) }],
    );
    // leaving dan out as lapsed, against the folder's unverified tail
    child.add(alice, childState(p.nodeId), [p.dep()]);
    expect(st(world([p, child]), child.nodeId).status).toEqual({
      kind: "unverified",
      atSeq: 2,
      reason: "needs-parent",
    });
  });

  it("a snapshot is judged in the view its deps name, two levels up too", () => {
    const g = Log.create(
      alice,
      folderState({ shares: [share(alice, "owner"), share(bob, "editor"), share(carol, "editor")] }),
    );
    const p = Log.create(alice, childState(g.nodeId, { kind: "folder" }), [g.dep()]);
    p.add(bob, childState(g.nodeId, { kind: "folder", shares: [share(eve, "editor")] }), [g.dep()]);
    const c = Log.create(alice, childState(p.nodeId), [p.dep(), g.dep()]);
    c.add(eve, childState(p.nodeId, { shares: [share(dan, "viewer")] }), [p.dep(), g.dep()]);
    g.add(
      alice,
      folderState({ shares: [share(alice, "owner"), share(carol, "editor")], version: 2, keyCommit: commit(2) }),
    );
    const base = [...c.entries];
    expect(st(world([g, p, c]), c.nodeId).state.shares).toEqual([]);

    // (a) carol, an editor through G, re-keys from the effective state, leaving dan out
    c.add(carol, childState(p.nodeId, { version: 2, keyCommit: commit(2) }), [p.dep(), g.dep()]);
    const ns = st(world([g, p, c]), c.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.version).toBe(2);
    expect(ns.state.shares).toEqual([]);
    expect(ns.stale).toBe(false);

    // (b) eve, lapsed in P, can't act by naming the newest states
    const byEve = new Log(c.nodeId);
    byEve.entries = [...base];
    byEve.add(eve, childState(p.nodeId, { shares: [share(dan, "viewer")], version: 2, keyCommit: commit(2) }), [
      p.dep(),
      g.dep(),
    ]);
    byEve.add(eve, childState(p.nodeId, { shares: [share(dan, "viewer"), share(carol, "viewer")] }), [
      p.dep(),
      g.dep(),
    ]);
    const e = st(world([g, p, byEve]), byEve.nodeId);
    expect(e.status).toEqual(verified);
    expect(e.state.version).toBe(1);
    expect(e.state.shares).toEqual([]);
  });

  it("a removed owner's backdated restrict stands while nothing on the node named the newer folder; the node is stale (§11)", () => {
    const p = Log.create(alice, folderState({ shares: [share(alice, "owner"), share(bob, "owner")] }));
    const before = p.dep();
    const c = Log.create(alice, childState(p.nodeId, { shares: [share(carol, "editor")] }), [before]);
    p.add(alice, folderState({ shares: [share(alice, "owner")], version: 2, keyCommit: commit(2) }));
    const restrict = childState(p.nodeId, {
      shares: [share(carol, "editor"), share(bob, "owner")],
      restricted: true,
      version: 2,
      keyCommit: commit(2),
    });
    // a restriction, once applied, is not undone by its author lapsing above (§3.3): bob could read c already, and
    // opening it again would hand it back to the folder; it is his now, stale until he re-keys as its owner
    const backdated = new Log(c.nodeId);
    backdated.entries = [...c.entries];
    backdated.add(bob, restrict, [before]);
    const w = world([p, backdated]);
    const ns = st(w, c.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.restricted).toBe(true);
    expect(ns.state.parentId).toBe(p.nodeId);
    expect(ns.state.version).toBe(2);
    expect(ns.stale).toBe(true);
    expect(w.role(alice.id, c.nodeId)).toBeNull();
    expect(w.role(bob.id, c.nodeId)).toBe("owner");

    // once any snapshot on c has named the folder after his removal, his backdated restrict is skipped (§4.4)
    c.add(carol, childState(p.nodeId, { shares: [share(carol, "editor")], version: 2, keyCommit: commit(2) }), [
      p.dep(),
    ]);
    c.add(bob, { ...restrict, version: 3, keyCommit: commit(3) }, [before]);
    const w2 = world([p, c]);
    const later = st(w2, c.nodeId);
    expect(later.status).toEqual(verified);
    expect(later.state.restricted).toBe(false);
    expect(later.state.version).toBe(2);
    expect(w2.role(alice.id, c.nodeId)).toBe("owner");
    expect(w2.role(bob.id, c.nodeId)).toBeNull();
  });

  it("a removed editor's backdated move falls back to the folder it was in", () => {
    const g = Log.create(alice, folderState({ shares: [share(alice, "owner"), share(bob, "editor")] }));
    const p1 = Log.create(alice, childState(g.nodeId, { kind: "folder" }), [g.dep()]);
    const p2 = Log.create(alice, childState(g.nodeId, { kind: "folder" }), [g.dep()]);
    const before = g.dep();
    const c = Log.create(alice, childState(p1.nodeId), [p1.dep(), g.dep()]);
    g.add(alice, folderState({ shares: [share(alice, "owner")], version: 2, keyCommit: commit(2) }));
    const moved = new Log(c.nodeId);
    moved.entries = [...c.entries];
    moved.add(bob, childState(p2.nodeId), [p1.dep(), p2.dep(), before]);
    const ns = st(world([g, p1, p2, moved]), moved.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.parentId).toBe(p1.nodeId);

    // an honest move by someone whose authority holds applies
    c.add(alice, childState(p2.nodeId), [p1.dep(), p2.dep(), g.dep()]);
    const ok = st(world([g, p1, p2, c]), c.nodeId);
    expect(ok.status).toEqual(verified);
    expect(ok.state.parentId).toBe(p2.nodeId);
  });

  it("a move's voucher needs editor at the place it falls back to, as well as on the new parent", () => {
    // S1: bob, removed from G, moves C from P1 into his own root, backdated
    const g = Log.create(alice, folderState({ shares: [share(alice, "owner"), share(bob, "editor")] }));
    const p1 = Log.create(alice, childState(g.nodeId, { kind: "folder" }), [g.dep()]);
    const b = Log.create(
      bob,
      folderState({ anchor: { user: bob.id, signPub: bob.signPub }, shares: [share(bob, "owner")] }),
    );
    const p2 = Log.create(alice, childState(g.nodeId, { kind: "folder", shares: [share(bob, "editor")] }), [g.dep()]);
    const before = g.dep();
    const c = Log.create(alice, childState(p1.nodeId), [p1.dep(), g.dep()]);
    g.add(alice, folderState({ shares: [share(alice, "owner")], version: 2, keyCommit: commit(2) }));
    const intoB = new Log(c.nodeId);
    intoB.entries = [...c.entries];
    intoB.add(bob, childState(b.nodeId), [p1.dep(), b.dep(), before]);
    let w = world([g, p1, b, intoB]);
    let ns = st(w, intoB.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.parentId).toBe(p1.nodeId);
    expect(w.role(alice.id, intoB.nodeId)).toBe("owner");
    expect(w.role(bob.id, intoB.nodeId)).toBeNull();

    // S2: into a sibling folder he still edits
    const intoP2 = new Log(c.nodeId);
    intoP2.entries = [...c.entries];
    intoP2.add(bob, childState(p2.nodeId), [p1.dep(), p2.dep(), before]);
    w = world([g, p1, p2, intoP2]);
    ns = st(w, intoP2.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.parentId).toBe(p1.nodeId);
    expect(w.role(alice.id, intoP2.nodeId)).toBe("owner");
    expect(w.role(bob.id, intoP2.nodeId)).toBeNull();
  });

  it("an honest writer restoring the effective parent with authorityDeps applies", () => {
    for (const crossRoot of [false, true]) {
      const g = Log.create(alice, folderState({ shares: [share(alice, "owner"), share(bob, "editor")] }));
      const p1 = Log.create(alice, childState(g.nodeId, { kind: "folder" }), [g.dep()]);
      const other = crossRoot
        ? Log.create(alice, folderState({ shares: [share(alice, "owner"), share(bob, "editor")] }))
        : Log.create(alice, childState(g.nodeId, { kind: "folder" }), [g.dep()]);
      const otherBefore = other.dep();
      const before = g.dep();
      const c = Log.create(alice, childState(p1.nodeId, { shares: [share(carol, "editor")] }), [p1.dep(), g.dep()]);
      g.add(alice, folderState({ shares: [share(alice, "owner")], version: 2, keyCommit: commit(2) }));
      if (crossRoot)
        other.add(alice, folderState({ shares: [share(alice, "owner")], version: 2, keyCommit: commit(2) }));
      const moveDeps = crossRoot ? [p1.dep(), otherBefore, before] : [p1.dep(), other.dep(), before];
      c.add(bob, childState(other.nodeId, { shares: [share(carol, "editor")] }), moveDeps);
      let w = world([g, p1, other, c]);
      const eff = st(w, c.nodeId).state;
      expect(eff.parentId).toBe(p1.nodeId);
      // carol, an editor through her own share, re-keys from the effective state
      c.add(carol, { ...eff, version: 2, keyCommit: commit(2) }, authorityDeps(w, c.nodeId));
      w = world([g, p1, other, c]);
      const ns = st(w, c.nodeId);
      expect(ns.status, `crossRoot ${crossRoot}`).toEqual(verified);
      expect(ns.state.version).toBe(2);
      expect(ns.state.parentId).toBe(p1.nodeId);
      expect(ns.stale).toBe(false);
    }
  });

  it("a group share somewhere above doesn't stop a removal by someone whose role is enough without it", () => {
    const g = Log.create(alice, folderState({ groupShares: [{ groupId: crypto.randomUUID(), role: "viewer" }] }));
    const p = Log.create(alice, childState(g.nodeId, { kind: "folder", shares: [share(dan, "owner")] }), [g.dep()]);
    const c = Log.create(dan, childState(p.nodeId, { shares: [share(carol, "viewer")] }), [p.dep(), g.dep()]);
    const w = world([g, p, c]);
    c.add(dan, childState(p.nodeId, { version: 2, keyCommit: commit(2) }), authorityDeps(w, c.nodeId));
    const ns = st(world([g, p, c]), c.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.version).toBe(2);
    expect(ns.state.shares).toEqual([]);
  });
});
