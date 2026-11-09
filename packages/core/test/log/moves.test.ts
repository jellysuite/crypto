import { toBase64Url } from "@jelly/crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";
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
  rootOf,
  type Snapshot,
  type State,
  snapshotHash,
  unlockAccount,
  type WorldInput,
} from "../../src/index.ts";

// Every fold goes through the spy, so a test can count how often each log is folded.
const folded = vi.hoisted(() => ({ calls: [] as string[] }));
vi.mock("../../src/log/fold.ts", async (importOriginal) => {
  const real = await importOriginal<typeof import("../../src/log/fold.ts")>();
  return {
    ...real,
    foldLog: (...args: Parameters<typeof real.foldLog>) => {
      folded.calls.push(args[1]);
      return real.foldLog(...args);
    },
  };
});
beforeEach(() => {
  folded.calls = [];
});

function user(handle: string) {
  const id = crypto.randomUUID();
  const acct = createAccount();
  const account = unlockAccount({ userId: id, handle, ak: acct.ak, bundle: acct.bundle });
  return { id, account, signPub: acct.bundle.signPub };
}
type U = ReturnType<typeof user>;

const alice = user("alice");
const bob = user("bob");
const dan = user("dan");
const everyone = [alice, bob, dan];
/** Signs validly, but this account can't resolve her key. */
const mallory = user("mallory");

const at = "2026-10-31T10:00:00.000Z";
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

const rootState = (owner: U, over: Partial<State> = {}): State => ({
  kind: "folder",
  parentId: null,
  anchor: { user: owner.id, signPub: owner.signPub },
  restricted: false,
  version: 1,
  keyCommit: commit(1),
  shares: [share(owner, "owner")],
  groupShares: [],
  links: [],
  ...over,
});

const childState = (parentId: string, over: Partial<State> = {}): State => ({
  kind: "folder",
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

/** alice's root, with bob an editor on it, and two folders in it. */
function workspace() {
  const r = Log.create(alice, rootState(alice, { shares: [share(alice, "owner"), share(bob, "editor")] }));
  const p1 = Log.create(alice, childState(r.nodeId), [r.dep()]);
  const p2 = Log.create(alice, childState(r.nodeId), [r.dep()]);
  return { r, p1, p2 };
}

describe("moves, roots and cycles", () => {
  it("an editor moves within the workspace", () => {
    const { r, p1, p2 } = workspace();
    const c = Log.create(bob, childState(p1.nodeId), [p1.dep(), r.dep()]);
    c.add(bob, childState(p2.nodeId), [p1.dep(), p2.dep(), r.dep()]);
    const w = world([r, p1, p2, c]);
    const ns = st(w, c.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.parentId).toBe(p2.nodeId);
    expect(rootOf(w, c.nodeId)).toBe(r.nodeId);
    expect(rootOf(w, p2.nodeId)).toBe(r.nodeId);
    expect(rootOf(w, r.nodeId)).toBe(r.nodeId);
    // and up to the root itself, naming every place c has sat in (§4.4): p1 is where its first move would fall back to
    const deps = authorityDeps(w, c.nodeId);
    expect(deps.map((d) => d.log).sort()).toEqual([r.nodeId, p1.nodeId, p2.nodeId].sort());
    const again = new Log(c.nodeId);
    again.entries = [...c.entries];
    again.add(bob, childState(r.nodeId), deps);
    expect(st(world([r, p1, p2, again]), c.nodeId).state.parentId).toBe(r.nodeId);
    // leaving p1 out, the earlier move can't be judged: the snapshot is skipped
    c.add(bob, childState(r.nodeId), [p2.dep(), r.dep()]);
    const short = st(world([r, p1, p2, c]), c.nodeId);
    expect(short.status).toEqual(verified);
    expect(short.state.parentId).toBe(p2.nodeId);
  });

  it("an editor can't move an item under their own root", () => {
    const { r, p1 } = workspace();
    const c = Log.create(alice, childState(p1.nodeId, { shares: [share(bob, "owner")] }), [p1.dep(), r.dep()]);
    const b = Log.create(bob, rootState(bob));
    const into = new Log(c.nodeId);
    into.entries = [...c.entries];
    into.add(bob, childState(b.nodeId, { shares: [share(bob, "owner")] }), [p1.dep(), b.dep(), r.dep()]);
    let w = world([r, p1, b, into]);
    let ns = st(w, c.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.parentId).toBe(p1.nodeId);
    expect(rootOf(w, b.nodeId)).toBe(b.nodeId);
    expect(w.role(alice.id, c.nodeId)).toBe("owner");

    // nor across two roots he edits, even into a folder of the other one
    const r2 = Log.create(alice, rootState(alice, { shares: [share(alice, "owner"), share(bob, "editor")] }));
    const q = Log.create(alice, childState(r2.nodeId), [r2.dep()]);
    const across = new Log(c.nodeId);
    across.entries = [...c.entries];
    across.add(bob, childState(q.nodeId, { shares: [share(bob, "owner")] }), [p1.dep(), q.dep(), r.dep(), r2.dep()]);
    w = world([r, p1, r2, q, across]);
    ns = st(w, c.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.parentId).toBe(p1.nodeId);
    expect(rootOf(w, q.nodeId)).toBe(r2.nodeId);
  });

  it("a root never moves", () => {
    const { r, p1 } = workspace();
    // an anchor-only personal root (no owner share): alice moves it into a folder of hers
    const mine = Log.create(alice, rootState(alice, { shares: [] }));
    mine.add(alice, rootState(alice, { shares: [], parentId: p1.nodeId }), [p1.dep(), r.dep()]);
    let ns = st(world([r, p1, mine]), mine.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.parentId).toBeNull();
    // nor under another root, nor under nothing it names
    const other = Log.create(alice, rootState(alice));
    other.add(alice, rootState(alice, { parentId: r.nodeId }), [r.dep()]);
    other.add(alice, rootState(alice, { parentId: crypto.randomUUID() }));
    ns = st(world([r, other]), other.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.parentId).toBeNull();
    // a child can't become a root either
    const c = Log.create(alice, childState(p1.nodeId), [p1.dep(), r.dep()]);
    c.add(alice, childState(p1.nodeId, { parentId: null }), [p1.dep(), r.dep()]);
    ns = st(world([r, p1, c]), c.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.parentId).toBe(p1.nodeId);
  });

  it("no move into its own subtree", () => {
    const { r, p1 } = workspace();
    const g = Log.create(alice, childState(p1.nodeId), [p1.dep(), r.dep()]);
    const gg = Log.create(alice, childState(g.nodeId), [g.dep(), p1.dep(), r.dep()]);
    const into = new Log(p1.nodeId);
    into.entries = [...p1.entries];
    into.add(alice, childState(gg.nodeId), [gg.dep(), g.dep(), r.dep()]);
    const self = new Log(p1.nodeId);
    self.entries = [...p1.entries];
    self.add(alice, childState(p1.nodeId), [p1.dep(), r.dep()]);
    for (const l of [into, self]) {
      const w = world([r, l, g, gg]);
      const ns = st(w, p1.nodeId);
      expect(ns.status).toEqual(verified);
      expect(ns.state.parentId).toBe(r.nodeId);
      expect(st(w, gg.nodeId).status).toEqual(verified);
      expect(w.role(bob.id, gg.nodeId)).toBe("editor");
    }
  });

  it("two crossing moves don't loop", () => {
    const { r, p1, p2 } = workspace();
    const a = new Log(p1.nodeId);
    a.entries = [...p1.entries];
    a.add(bob, childState(p2.nodeId), [p1.dep(), p2.dep(), r.dep()]);
    const b = new Log(p2.nodeId);
    b.entries = [...p2.entries];
    b.add(bob, childState(p1.nodeId), [p2.dep(), p1.dep(), r.dep()]);
    const t = performance.now();
    const results = [
      [a.nodeId, b.nodeId],
      [b.nodeId, a.nodeId],
    ].map((order) => {
      const w = world([r, a, b]);
      for (const id of order) st(w, id);
      return [a.nodeId, b.nodeId].map((id) => ({ status: st(w, id).status, parentId: st(w, id).state.parentId }));
    });
    expect(performance.now() - t).toBeLessThan(500);
    expect(results[0]).toEqual(results[1]);
    const [sa, sb] = results[0] ?? [];
    expect(sa?.status).toEqual(verified);
    expect(sb?.status).toEqual(verified);
    const moved = [sa?.parentId === p2.nodeId, sb?.parentId === p1.nodeId].filter(Boolean);
    expect(moved.length).toBeLessThanOrEqual(1);
  });

  it("moving into a restricted area it wasn't in needs owner on the node; within one, or out, editor", () => {
    const { r, p1, p2 } = workspace();
    // bob's own private channel (he made it with only editor on p1, §3.3), and a restricted folder alice shares
    // with him as owner
    const chan = Log.create(
      bob,
      childState(p1.nodeId, { kind: "channel", restricted: true, shares: [share(bob, "owner")] }),
      [p1.dep(), r.dep()],
    );
    const secret = Log.create(
      alice,
      childState(p1.nodeId, { restricted: true, shares: [share(alice, "owner"), share(bob, "owner")] }),
      [p1.dep(), r.dep()],
    );
    const inner = Log.create(alice, childState(secret.nodeId), [secret.dep(), p1.dep(), r.dep()]);
    const into = (by: U, node: Log, to: Log) => {
      const l = new Log(node.nodeId);
      l.entries = [...node.entries];
      const base = node.last().state;
      const deps = new Map<string, Dep>();
      for (const d of [
        ...authorityDeps(world([r, p1, p2, chan, secret, inner, node]), node.nodeId),
        ...authorityDeps(world([r, p1, p2, chan, secret, inner]), to.nodeId),
        to.dep(),
      ])
        deps.set(d.log, d);
      l.add(by, { ...base, parentId: to.nodeId }, [...deps.values()]);
      return l;
    };
    const placed = (l: Log) => {
      const w = world([r, p1, p2, chan, secret, inner, l]);
      const ns = st(w, l.nodeId);
      expect(ns.status).toEqual(verified);
      return { parentId: ns.state.parentId, w };
    };
    // alice's page in p2: bob edits it through the root, owns nothing on it
    const page = Log.create(alice, childState(p2.nodeId, { kind: "page" }), [p2.dep(), r.dep()]);

    // bob, an editor, moves it into his channel or into the folder he owns: skipped, alice keeps it
    for (const to of [chan, secret]) {
      const { parentId, w } = placed(into(bob, page, to));
      expect(parentId).toBe(p2.nodeId);
      expect(w.role(alice.id, page.nodeId)).toBe("owner");
      expect(w.role(bob.id, page.nodeId)).toBe("editor");
    }
    // alice, an owner on it, moves it into the restricted folder: applies
    expect(placed(into(alice, page, secret)).parentId).toBe(secret.nodeId);
    // bob moves an item he owns into the folder he owns: applies
    const his = Log.create(alice, childState(p2.nodeId, { kind: "page", shares: [share(bob, "owner")] }), [
      p2.dep(),
      r.dep(),
    ]);
    expect(placed(into(bob, his, secret)).parentId).toBe(secret.nodeId);

    // inside the folder: an editor's move within it, and out of it into the open, take editor as before
    const there = Log.create(alice, childState(secret.nodeId, { kind: "page", shares: [share(dan, "editor")] }), [
      secret.dep(),
      p1.dep(),
      r.dep(),
    ]);
    const danIn = Log.create(alice, childState(secret.nodeId, { shares: [share(dan, "editor")] }), [
      secret.dep(),
      p1.dep(),
      r.dep(),
    ]);
    const within = new Log(there.nodeId);
    within.entries = [...there.entries];
    within.add(dan, childState(danIn.nodeId, { kind: "page", shares: [share(dan, "editor")] }), [
      danIn.dep(),
      secret.dep(),
      p1.dep(),
      r.dep(),
    ]);
    const w = world([r, p1, p2, chan, secret, inner, danIn, within]);
    expect(st(w, there.nodeId).state.parentId).toBe(danIn.nodeId);
    expect(placed(into(bob, inner, p2)).parentId).toBe(p2.nodeId);
  });

  it("a move that would make the mover owner of the node needs owner on it already (open area too)", () => {
    const { r, p1, p2 } = workspace();
    // an open folder in p1 alice shares with bob as owner
    const mine = Log.create(alice, childState(p1.nodeId, { shares: [share(bob, "owner")] }), [p1.dep(), r.dep()]);
    const into = (by: U, node: Log, to: Log) => {
      const l = new Log(node.nodeId);
      l.entries = [...node.entries];
      const deps = new Map<string, Dep>();
      for (const d of [
        ...authorityDeps(world([r, p1, p2, mine, node]), node.nodeId),
        ...authorityDeps(world([r, p1, p2, mine]), to.nodeId),
        to.dep(),
      ])
        deps.set(d.log, d);
      l.add(by, { ...node.last().state, parentId: to.nodeId }, [...deps.values()]);
      return l;
    };
    const placed = (l: Log) => {
      const w = world([r, p1, p2, mine, l]);
      const ns = st(w, l.nodeId);
      expect(ns.status).toEqual(verified);
      return { parentId: ns.state.parentId, w };
    };
    // alice's page in p2: bob edits it through the root
    const page = Log.create(alice, childState(p2.nodeId, { kind: "page" }), [p2.dep(), r.dep()]);
    const { parentId, w } = placed(into(bob, page, mine));
    expect(parentId).toBe(p2.nodeId);
    expect(w.role(bob.id, page.nodeId)).toBe("editor");
    // alice, owner on it, may
    expect(placed(into(alice, page, mine)).parentId).toBe(mine.nodeId);
    // bob, already owner of the item, may
    const his = Log.create(alice, childState(p2.nodeId, { kind: "page", shares: [share(bob, "owner")] }), [
      p2.dep(),
      r.dep(),
    ]);
    expect(placed(into(bob, his, mine)).parentId).toBe(mine.nodeId);
    // a move that doesn't raise bob's role (editor here, editor there) still takes editor
    expect(placed(into(bob, page, p1)).parentId).toBe(p1.nodeId);
  });

  it("unrestricting needs owner on the node and editor on the parent", () => {
    const { r, p1 } = workspace();
    const p = Log.create(alice, childState(p1.nodeId, { shares: [share(dan, "editor")] }), [p1.dep(), r.dep()]);
    const q = Log.create(alice, childState(p1.nodeId), [p1.dep(), r.dep()]);
    // alice makes a restricted item dan owns, in a folder dan edits, and one in a folder he doesn't
    const closed = (parent: Log) =>
      Log.create(alice, childState(parent.nodeId, { kind: "page", restricted: true, shares: [share(dan, "owner")] }), [
        parent.dep(),
        p1.dep(),
        r.dep(),
      ]);
    const opened = (parent: Log) => childState(parent.nodeId, { kind: "page", shares: [share(dan, "owner")] });

    const c = closed(p);
    c.add(dan, opened(p), [p.dep(), p1.dep(), r.dep()]);
    let w = world([r, p1, p, c]);
    let ns = st(w, c.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.restricted).toBe(false);
    expect(w.role(alice.id, c.nodeId)).toBe("owner");

    // bob edits the folder (through the root) but doesn't own the item
    const d = closed(p);
    d.add(bob, opened(p), [p.dep(), p1.dep(), r.dep()]);
    ns = st(world([r, p1, p, d]), d.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.restricted).toBe(true);

    // dan owns the item but can't edit the folder it's in
    const e = closed(q);
    e.add(dan, opened(q), [q.dep(), p1.dep(), r.dep()]);
    w = world([r, p1, q, e]);
    ns = st(w, e.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.restricted).toBe(true);
    expect(w.role(alice.id, e.nodeId)).toBeNull();
  });

  /** The log with an entry appended that chains on but whose signature doesn't verify, placing it under `under`. */
  const withJunk = (log: Log, root: Log, under: string): Log => {
    const out = new Log(log.nodeId);
    out.entries = [...log.entries];
    out.add(alice, childState(root.nodeId));
    const last = out.entries.pop() as Snapshot;
    out.entries.push({ ...last, state: childState(under), sig: "AAAA" });
    return out;
  };

  it("entries that don't verify, or whose author doesn't resolve, don't block a move", () => {
    const { r, p1, p2 } = workspace();
    const c = Log.create(bob, childState(p1.nodeId), [p1.dep(), r.dep()]);
    c.add(bob, childState(p2.nodeId), [p1.dep(), p2.dep(), r.dep()]);
    let w = world([r, p1, withJunk(p2, r, c.nodeId), c]);
    const ns = st(w, c.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.parentId).toBe(p2.nodeId);
    expect(st(w, p2.nodeId).state.parentId).toBe(r.nodeId);
    const p2m = new Log(p2.nodeId);
    p2m.entries = [...p2.entries];
    p2m.add(mallory, childState(c.nodeId), [c.dep(), r.dep()]);
    w = world([r, p1, p2m, c]);
    expect(st(w, c.nodeId).state.parentId).toBe(p2.nodeId);
  });

  it("entries that don't verify don't undo an unrestrict", () => {
    const { r, p1 } = workspace();
    const d = Log.create(alice, childState(p1.nodeId, { restricted: true, shares: [share(alice, "owner")] }), [
      p1.dep(),
      r.dep(),
    ]);
    d.add(alice, childState(p1.nodeId, { shares: [share(alice, "owner")] }), [p1.dep(), r.dep()]);
    const ns = st(world([r, withJunk(p1, r, d.nodeId), d]), d.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.restricted).toBe(false);
  });

  it("a signed entry by someone with no say there still blocks a move into its log (it's skipped, not undone)", () => {
    // The accepted residual: whether dan's entry applies isn't known without folding p2, which would
    // recurse into c; so a resolvable signer's claim counts, and the move is refused rather than looped.
    const { r, p1, p2 } = workspace();
    const c = Log.create(bob, childState(p1.nodeId), [p1.dep(), r.dep()]);
    const p2d = new Log(p2.nodeId);
    p2d.entries = [...p2.entries];
    p2d.add(dan, childState(c.nodeId), [c.dep(), r.dep()]);
    c.add(bob, childState(p2.nodeId), [p1.dep(), p2d.dep(0), r.dep()]);
    const w = world([r, p1, p2d, c]);
    const ns = st(w, c.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.parentId).toBe(p1.nodeId);
    // dan's own entry was skipped: p2 stays in the root
    expect(st(w, p2.nodeId).status).toEqual(verified);
    expect(st(w, p2.nodeId).state.parentId).toBe(r.nodeId);
  });

  it("50 levels deep and 1,000 children fold once each", () => {
    const r = Log.create(alice, rootState(alice));
    const chain: Log[] = [r];
    for (let i = 0; i < 50; i++) {
      const parent = chain[chain.length - 1] as Log;
      chain.push(
        Log.create(
          alice,
          childState(parent.nodeId),
          chain.map((l) => l.dep()),
        ),
      );
    }
    const wide = Log.create(alice, childState(r.nodeId), [r.dep()]);
    const kids: Log[] = [];
    for (let i = 0; i < 1000; i++)
      kids.push(Log.create(alice, childState(wide.nodeId, { kind: "page" }), [wide.dep(), r.dep()]));
    const all = [...chain, wide, ...kids];
    const w = world(all);
    folded.calls = [];
    const t = performance.now();
    for (const l of [...all].reverse()) expect(st(w, l.nodeId).status).toEqual(verified);
    for (const l of all) expect(rootOf(w, l.nodeId)).toBe(r.nodeId);
    expect(performance.now() - t).toBeLessThan(2000);
    expect(folded.calls.length).toBe(all.length);
    expect(new Set(folded.calls).size).toBe(all.length);
  });

  it("a hostile parent cycle folds cheaply, whichever log is asked for first", () => {
    const n = 16;
    const nodeIds = Array.from({ length: n }, () => crypto.randomUUID());
    const leaves: LegacyLeaf[] = nodeIds.map((nodeId, i) => ({
      nodeId,
      state: childState(nodeIds[(i + 1) % n] as string, { shares: [share(alice, "owner")] }),
    }));
    const legacyRoot = merkleRoot(leaves);
    const logs = leaves.map((l) => {
      const log = new Log(l.nodeId);
      log.entries = [legacySnapshot(l, merkleProof(leaves, l.nodeId) as string[])];
      return log;
    });
    // every node then names its parent, twice
    for (const [i, log] of logs.entries()) {
      const parent = logs[(i + 1) % n] as Log;
      log.add(alice, childState(parent.nodeId, { shares: [share(alice, "owner"), share(bob, "viewer")] }), [
        parent.dep(0),
      ]);
      log.add(
        alice,
        childState(parent.nodeId, { shares: [share(alice, "owner"), share(bob, "viewer"), share(dan, "viewer")] }),
        [parent.dep(0)],
      );
    }
    const t = performance.now();
    const fwd = world(logs, { legacyRoot });
    const a = nodeIds.map((id) => st(fwd, id).status);
    const callsOnce = folded.calls.length;
    const rev = world(logs, { legacyRoot });
    const b = [...nodeIds].reverse().map((id) => st(rev, id).status);
    expect(performance.now() - t).toBeLessThan(2000);
    expect(b.reverse()).toEqual(a);
    for (const s of a) expect(s.kind).toBe("unverified");
    expect(callsOnce).toBeLessThanOrEqual(n * n);
    for (const id of nodeIds) expect(rootOf(fwd, id)).toBeNull();
    // asked again, nothing is folded again
    const before = folded.calls.length;
    for (const id of nodeIds) st(fwd, id);
    expect(folded.calls.length).toBe(before);
  });
});
