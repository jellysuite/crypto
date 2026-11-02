import { toBase64Url } from "@jelly/crypto";
import { describe, expect, it } from "vitest";
import {
  type Change,
  createAccount,
  createFirstSnapshot,
  createSnapshot,
  foldLog,
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
const LINK = crypto.randomUUID();

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

function fold(nodeId: string, entries: unknown[], over: Partial<WorldInput> = {}): NodeState {
  const world = new LogWorld({
    logs: new Map([[nodeId, entries as LogEntry[]]]),
    legacyRoot: null,
    identity: known,
    groups: noGroups,
    ...over,
  });
  const ns = world.state(nodeId);
  if (!ns) throw new Error("no state");
  return ns;
}

/** A node's log as a test builds it: each append chains onto whatever came last, applied or not. */
class Log {
  entries: unknown[] = [];
  readonly nodeId: string;
  constructor(nodeId: string) {
    this.nodeId = nodeId;
  }
  static root(state: State = rootState(), by: U = alice): Log {
    const first = createFirstSnapshot(by.account, { state, deps: [], at });
    const log = new Log(first.nodeId);
    log.entries.push(first);
    return log;
  }
  last(): Snapshot {
    return this.entries[this.entries.length - 1] as Snapshot;
  }
  add(by: U, state: State, change: Change = "change"): this {
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
        deps: [],
        at,
      }),
    );
    return this;
  }
  push(raw: unknown): this {
    this.entries.push(raw);
    return this;
  }
  fold(over: Partial<WorldInput> = {}): NodeState {
    return fold(this.nodeId, this.entries, over);
  }
}

const roleOf = (ns: NodeState, u: U) => ns.state.shares.find((s) => s.userId === u.id)?.role ?? null;
const verified = { kind: "verified" };

describe("folding one node's log", () => {
  it("a root's anchor is owner", () => {
    const log = Log.root(rootState({ shares: [] }));
    const world = new LogWorld({
      logs: new Map([[log.nodeId, log.entries as LogEntry[]]]),
      legacyRoot: null,
      identity: known,
      groups: noGroups,
    });
    const ns = world.state(log.nodeId);
    expect(ns?.status).toEqual(verified);
    expect(ns?.seq).toBe(0);
    expect(ns?.head).toBe(snapshotHash(log.last()));
    expect(world.role(alice.id, log.nodeId)).toBe("owner");
    expect(world.role(bob.id, log.nodeId)).toBeNull();
    expect(world.role(alice.id, crypto.randomUUID())).toBeNull();
    // and the anchor, with no share of its own, can add an owner
    log.add(alice, rootState({ shares: [share(bob, "owner")] }));
    expect(roleOf(log.fold(), bob)).toBe("owner");
  });

  it("additions need editor, owner shares and role changes need owner", () => {
    const base = [share(alice, "owner"), share(bob, "editor")];
    const log = Log.root(rootState({ shares: base }));
    log.add(bob, rootState({ shares: [...base, share(carol, "viewer")] }));
    expect(roleOf(log.fold(), carol)).toBe("viewer");
    const withCarol = [...base, share(carol, "viewer")];

    log.add(bob, rootState({ shares: [...withCarol, share(dan, "owner")] }));
    expect(roleOf(log.fold(), dan)).toBeNull();
    log.add(bob, rootState({ shares: [...base, share(carol, "editor")] }));
    expect(roleOf(log.fold(), carol)).toBe("viewer");

    log.add(alice, rootState({ shares: [...base, share(carol, "editor"), share(dan, "owner")] }));
    let ns = log.fold();
    expect(roleOf(ns, carol)).toBe("editor");
    expect(roleOf(ns, dan)).toBe("owner");
    expect(ns.status).toEqual(verified);

    const now = [...base, share(carol, "editor"), share(dan, "owner"), share(eve, "viewer")];
    log.add(alice, rootState({ shares: now }));
    log.add(
      eve,
      rootState({ shares: now.map((s) => (s.userId === carol.id ? { ...s, role: "viewer" as const } : s)) }),
    );
    ns = log.fold();
    expect(roleOf(ns, carol)).toBe("editor");
    // a viewer can't even make a snapshot that changes nothing but a key hint
    log.add(eve, rootState({ shares: now.map((s) => (s.userId === bob.id ? { ...s, signPub: eve.signPub } : s)) }));
    expect(log.fold().state.shares.find((s) => s.userId === bob.id)?.signPub).toBe(bob.signPub);
    // an editor may
    log.add(bob, rootState({ shares: now.map((s) => (s.userId === bob.id ? { ...s, signPub: eve.signPub } : s)) }));
    ns = log.fold();
    expect(ns.state.shares.find((s) => s.userId === bob.id)?.signPub).toBe(eve.signPub);
    expect(ns.seq).toBe(8);
    expect(ns.status).toEqual(verified);
  });

  it("a viewer adds nobody", () => {
    const base = [share(alice, "owner"), share(carol, "viewer")];
    const log = Log.root(rootState({ shares: base }));
    log.add(carol, rootState({ shares: [...base, share(dan, "viewer")] }));
    expect(roleOf(log.fold(), dan)).toBeNull();
  });

  it("a snapshot with one disallowed difference is skipped whole", () => {
    const base = [share(alice, "owner"), share(bob, "editor")];
    const log = Log.root(rootState({ shares: base }));
    log.add(bob, rootState({ shares: [...base, share(carol, "viewer"), share(dan, "owner")] }));
    const ns = log.fold();
    expect(roleOf(ns, carol)).toBeNull();
    expect(roleOf(ns, dan)).toBeNull();
    expect(ns.status).toEqual(verified);
    expect(ns.seq).toBe(1);
  });

  it("removals need owner and a re-key", () => {
    const base = [share(alice, "owner"), share(bob, "editor"), share(carol, "viewer")];
    const without = base.filter((s) => s.userId !== carol.id);

    const plain = Log.root(rootState({ shares: base }));
    plain.add(alice, rootState({ shares: without }));
    expect(roleOf(plain.fold(), carol)).toBe("viewer");

    const byEditor = Log.root(rootState({ shares: base }));
    byEditor.add(bob, rootState({ shares: without, version: 2, keyCommit: commit(2) }));
    expect(roleOf(byEditor.fold(), carol)).toBe("viewer");

    const ok = Log.root(rootState({ shares: base }));
    ok.add(alice, rootState({ shares: without, version: 2, keyCommit: commit(2) }));
    const ns = ok.fold();
    expect(roleOf(ns, carol)).toBeNull();
    expect(ns.state.version).toBe(2);
    expect(ns.stale).toBe(false);
  });

  it("a person may leave without a re-key, and only themselves", () => {
    const base = [share(alice, "owner"), share(bob, "editor"), share(carol, "viewer")];
    const left = Log.root(rootState({ shares: base }));
    left.add(carol, rootState({ shares: base.filter((s) => s.userId !== carol.id) }), "leave");
    let ns = left.fold();
    expect(roleOf(ns, carol)).toBeNull();
    expect(ns.stale).toBe(true);
    expect(ns.status).toEqual(verified);
    // the next re-key makes it fresh again
    left.add(bob, rootState({ shares: base.filter((s) => s.userId !== carol.id), version: 2, keyCommit: commit(2) }));
    expect(left.fold().stale).toBe(false);

    const other = Log.root(rootState({ shares: base }));
    other.add(carol, rootState({ shares: base.filter((s) => s.userId !== bob.id) }), "leave");
    ns = other.fold();
    expect(roleOf(ns, bob)).toBe("editor");
    expect(ns.stale).toBe(false);

    // a leave carries nothing else, not even a re-key
    const more = Log.root(rootState({ shares: base }));
    more.add(
      carol,
      rootState({ shares: base.filter((s) => s.userId !== carol.id), version: 2, keyCommit: commit(2) }),
      "leave",
    );
    expect(roleOf(more.fold(), carol)).toBe("viewer");

    // removing yourself as a plain change still needs the re-key
    const plain = Log.root(rootState({ shares: base }));
    plain.add(carol, rootState({ shares: base.filter((s) => s.userId !== carol.id) }));
    expect(roleOf(plain.fold(), carol)).toBe("viewer");
  });

  it("versions step by one with a new commit", () => {
    const base = [share(alice, "owner"), share(bob, "editor"), share(carol, "viewer")];
    const tries: Array<[string, Partial<State>, U]> = [
      ["jump", { version: 3, keyCommit: commit(3) }, alice],
      ["same version, new commit", { keyCommit: commit(9) }, alice],
      ["step, same commit", { version: 2 }, alice],
      ["step, no commit", { version: 2, keyCommit: null }, alice],
      ["backwards", { version: 0, keyCommit: commit(0) }, alice],
      ["kind", { kind: "page" }, alice],
      ["anchor", { anchor: { user: bob.id, signPub: bob.signPub } }, alice],
      ["no anchor", { anchor: null }, alice],
      ["re-key by a viewer", { version: 2, keyCommit: commit(2) }, carol],
    ];
    for (const [what, over, by] of tries) {
      const log = Log.root(rootState({ shares: base }));
      log.add(by, rootState({ shares: base, ...over }));
      const ns = log.fold();
      expect(ns.state, what).toEqual(rootState({ shares: base }));
      expect(ns.status, what).toEqual(verified);
    }
    const ok = Log.root(rootState({ shares: base }));
    ok.add(bob, rootState({ shares: base, version: 2, keyCommit: commit(2) }));
    expect(ok.fold().state.version).toBe(2);
  });

  it("share links: editor adds, owner removes with a re-key", () => {
    const base = [share(alice, "owner"), share(bob, "editor"), share(carol, "viewer")];
    const links = [{ linkId: LINK, role: "viewer" as const }];
    const log = Log.root(rootState({ shares: base }));
    log.add(carol, rootState({ shares: base, links }));
    expect(log.fold().state.links).toEqual([]);
    log.add(bob, rootState({ shares: base, links }));
    expect(log.fold().state.links).toEqual(links);
    log.add(alice, rootState({ shares: base, links: [{ linkId: LINK, role: "editor" }] }));
    expect(log.fold().state.links).toEqual([{ linkId: LINK, role: "editor" }]);
    const editorLinks = [{ linkId: LINK, role: "editor" as const }];
    log.add(bob, rootState({ shares: base, links: editorLinks.map((l) => ({ ...l, role: "viewer" as const })) }));
    expect(log.fold().state.links).toEqual(editorLinks);
    log.add(bob, rootState({ shares: base, version: 2, keyCommit: commit(2) }));
    expect(log.fold().state.links).toEqual(editorLinks);
    log.add(alice, rootState({ shares: base }));
    expect(log.fold().state.links).toEqual(editorLinks);
    log.add(alice, rootState({ shares: base, version: 2, keyCommit: commit(2) }));
    const ns = log.fold();
    expect(ns.state.links).toEqual([]);
    expect(ns.status).toEqual(verified);
  });

  it("restrict needs owner and a re-key; unrestrict needs owner", () => {
    const base = [share(alice, "owner"), share(bob, "editor")];
    const log = Log.root(rootState({ shares: base }));
    log.add(bob, rootState({ shares: base, restricted: true, version: 2, keyCommit: commit(2) }));
    expect(log.fold().state.restricted).toBe(false);
    log.add(alice, rootState({ shares: base, restricted: true }));
    expect(log.fold().state.restricted).toBe(false);
    log.add(alice, rootState({ shares: base, restricted: true, version: 2, keyCommit: commit(2) }));
    expect(log.fold().state.restricted).toBe(true);
    log.add(bob, rootState({ shares: base, restricted: false, version: 2, keyCommit: commit(2) }));
    expect(log.fold().state.restricted).toBe(true);
    log.add(alice, rootState({ shares: base, restricted: false, version: 2, keyCommit: commit(2) }));
    const ns = log.fold();
    expect(ns.state.restricted).toBe(false);
    expect(ns.status).toEqual(verified);
  });

  it("chain problems make the node unverified there, and the state up to it stands", () => {
    const base = [share(alice, "owner"), share(bob, "editor")];
    const s1 = rootState({ shares: [...base, share(carol, "viewer")] });
    const s2 = rootState({ shares: [...base, share(carol, "viewer"), share(dan, "viewer")] });
    const make = () => Log.root(rootState({ shares: base })).add(alice, s1);
    const next = (log: Log, over: Partial<Snapshot>) =>
      createSnapshot(alice.account, {
        nodeId: log.nodeId,
        seq: log.last().seq + 1,
        prev: snapshotHash(log.last()),
        state: s2,
        change: "change",
        supersedes: null,
        skipped: [],
        nonce: null,
        deps: [],
        at,
        ...over,
      });

    const badPrev = make();
    badPrev.push(next(badPrev, { prev: commit(7) }));
    const gap = make();
    gap.push(next(gap, { seq: 3 }));
    const dup = make();
    dup.push(next(dup, { seq: 1, prev: snapshotHash(dup.entries[0] as Snapshot) }));
    const firstNotZero = Log.root(rootState({ shares: base }));
    firstNotZero.entries.shift();
    firstNotZero.push(next(make(), {}));

    for (const [what, log, atSeq] of [
      ["bad prev", badPrev, 2],
      ["gap", gap, 2],
      ["duplicate seq", dup, 2],
    ] as const) {
      // a valid-looking entry after the break counts for nothing either
      log.add(alice, s2);
      const ns = log.fold();
      expect(ns.status, what).toMatchObject({ kind: "unverified", atSeq, reason: "chain" });
      expect(ns.state, what).toEqual(s1);
      expect(ns.seq, what).toBe(1);
      expect(ns.head, what).toBe(snapshotHash(log.entries[1] as Snapshot));
    }
    const ns = fold(firstNotZero.nodeId, firstNotZero.entries);
    expect(ns.status).toMatchObject({ kind: "unverified", atSeq: 0, reason: "chain" });
    expect(ns.state.shares).toEqual([]);
  });

  it("garbage is skipped and never throws", () => {
    const base = [share(alice, "owner"), share(bob, "editor")];
    const log = Log.root(rootState({ shares: base }));
    // signed, but with a role that doesn't exist
    log.add(alice, rootState({ shares: [...base, { ...share(carol, "viewer"), role: "admin" as Role }] }));
    // a bad signature
    log.add(alice, rootState({ shares: [...base, share(dan, "owner")] }));
    const forged = log.entries.pop() as Snapshot;
    log.push({ ...forged, sig: toBase64Url(new Uint8Array(64).fill(1)) });
    // a truncated signature
    log.add(alice, rootState({ shares: [...base, share(dan, "owner")] }));
    const cut = log.entries.pop() as Snapshot;
    log.push({ ...cut, sig: cut.sig.slice(0, 20) });
    // a duplicate share
    log.add(alice, rootState({ shares: [...base, share(dan, "owner"), share(dan, "viewer")] }));
    // a nonce after seq 0, an unknown change, a seq 0 kind of change later on, supersedes without a checkpoint
    log.add(alice, rootState({ shares: [...base, share(dan, "owner")] }));
    const withNonce = log.entries.pop() as Snapshot;
    log.push(createSnapshot(alice.account, { ...withNonce, nonce: commit(5) }));
    log.add(alice, rootState({ shares: [...base, share(dan, "owner")] }), "nope" as Change);
    log.add(alice, rootState({ shares: [...base, share(dan, "owner")] }), "create");
    log.add(alice, rootState({ shares: [...base, share(dan, "owner")] }));
    const sup = log.entries.pop() as Snapshot;
    log.push(createSnapshot(alice.account, { ...sup, supersedes: commit(5) }));
    // a legacy proof on a later entry
    log.add(alice, rootState({ shares: [...base, share(dan, "owner")] }));
    log.push({ ...(log.entries.pop() as Snapshot), legacyProof: [] });
    // another node's snapshot
    log.add(alice, rootState({ shares: [...base, share(dan, "owner")] }));
    const elsewhere = log.entries.pop() as Snapshot;
    log.push(createSnapshot(alice.account, { ...elsewhere, nodeId: crypto.randomUUID() }));
    expect(log.fold().state.shares).toEqual(base);

    log.add(alice, rootState({ shares: [...base, share(eve, "viewer")] }));
    const ns = log.fold();
    expect(ns.status).toEqual(verified);
    expect(ns.state.shares).toEqual([...base, share(eve, "viewer")]);
    expect(ns.seq).toBe(log.entries.length - 1);

    const junk: unknown[] = [null, 5, "x", [], {}, { seq: 0 }, { ...(log.entries[0] as object), state: 5 }];
    for (const j of junk) {
      expect(() => fold(log.nodeId, [j])).not.toThrow();
      expect(fold(log.nodeId, [j]).status).toMatchObject({ kind: "unverified", atSeq: 0 });
      const mid = [...log.entries.slice(0, 2), j, ...log.entries.slice(2)];
      expect(() => fold(log.nodeId, mid)).not.toThrow();
      expect(fold(log.nodeId, mid).status.kind).toBe("unverified");
    }
    const world = new LogWorld({ logs: new Map(), legacyRoot: null, identity: known, groups: noGroups });
    expect(foldLog(world, log.nodeId, 7 as unknown as LogEntry[]).status).toMatchObject({ kind: "unverified" });
    expect(
      new LogWorld({
        logs: new Map([["x", 7 as unknown as LogEntry[]]]),
        legacyRoot: null,
        identity: known,
        groups: noGroups,
      }).state("x"),
    ).toBeNull();
  });

  it("an empty or missing log has no state", () => {
    const world = new LogWorld({ logs: new Map([["a", []]]), legacyRoot: null, identity: known, groups: noGroups });
    expect(world.state("a")).toBeNull();
    expect(world.state("b")).toBeNull();
    expect(world.role(alice.id, "a")).toBeNull();
  });

  it("legacy origin", () => {
    const legacyId = crypto.randomUUID();
    const state = rootState({ shares: [share(alice, "owner")], keyCommit: null });
    const other: LegacyLeaf = {
      nodeId: crypto.randomUUID(),
      state: rootState({ kind: "page", parentId: crypto.randomUUID(), anchor: null }),
    };
    const v8: LegacyLeaf = { nodeId: Log.root().nodeId, state };
    const leaves: LegacyLeaf[] = [{ nodeId: legacyId, state }, other, v8];
    const root = merkleRoot(leaves);
    const entry = legacySnapshot({ nodeId: legacyId, state }, merkleProof(leaves, legacyId) as string[]);

    const log = new Log(legacyId);
    log.push(entry);
    let ns = log.fold({ legacyRoot: root });
    expect(ns.status).toEqual(verified);
    expect(ns.state).toEqual(state);
    expect(ns.head).toBe(snapshotHash(entry));
    // its owner goes on from there
    log.add(alice, {
      ...state,
      version: 2,
      keyCommit: commit(2),
      shares: [share(alice, "owner"), share(bob, "viewer")],
    });
    ns = log.fold({ legacyRoot: root });
    expect(roleOf(ns, bob)).toBe("viewer");
    expect(ns.status).toEqual(verified);

    const unverifiedAt0 = { kind: "unverified", atSeq: 0 };
    expect(log.fold().status).toMatchObject(unverifiedAt0); // no root to check against
    expect(log.fold({ legacyRoot: merkleRoot([other]) }).status).toMatchObject(unverifiedAt0);
    expect(log.fold({ legacyRoot: merkleRoot([other]) }).state.shares).toEqual([]);
    const wrongProof = { ...entry, legacyProof: merkleProof(leaves, other.nodeId) as string[] };
    expect(fold(legacyId, [wrongProof], { legacyRoot: root }).status).toMatchObject(unverifiedAt0);
    const changed = { ...entry, state: { ...state, shares: [share(bob, "owner")] } };
    expect(fold(legacyId, [changed], { legacyRoot: root }).status).toMatchObject(unverifiedAt0);
    const v8Entry = legacySnapshot(v8, merkleProof(leaves, v8.nodeId) as string[]);
    expect(fold(v8.nodeId, [v8Entry], { legacyRoot: root }).status).toMatchObject(unverifiedAt0);

    // a v8 first snapshot whose id isn't derived from it
    const first = createFirstSnapshot(alice.account, { state: rootState(), deps: [], at });
    const otherId = Log.root().nodeId;
    const renamed = createSnapshot(alice.account, { ...first, nodeId: otherId });
    expect(fold(otherId, [renamed]).status).toMatchObject({ ...unverifiedAt0, reason: "id" });
    expect(fold(first.nodeId, [first]).status).toEqual(verified);
  });

  it("a first snapshot must be a well-formed root by its anchor, or isn't checkable yet", () => {
    const unverifiedAt0 = (reason: string) => ({ kind: "unverified", atSeq: 0, reason });
    expect(Log.root(rootState(), bob).fold().status).toMatchObject(unverifiedAt0("anchor"));
    expect(Log.root(rootState({ anchor: { user: alice.id, signPub: bob.signPub } })).fold().status).toMatchObject(
      unverifiedAt0("anchor"),
    );
    expect(Log.root(rootState({ anchor: null })).fold().status).toMatchObject(unverifiedAt0("anchor"));
    expect(Log.root(rootState({ anchor: { team: crypto.randomUUID() } })).fold().status).toMatchObject(
      unverifiedAt0("needs-team"),
    );
    // a child's first snapshot must name its parent (deps.test.ts has the rest)
    expect(Log.root(rootState({ parentId: crypto.randomUUID(), anchor: null })).fold().status).toMatchObject(
      unverifiedAt0("needs-dep"),
    );
    expect(Log.root(rootState({ version: 2 })).fold().status).toMatchObject(unverifiedAt0("origin"));
    expect(Log.root(rootState({ keyCommit: null })).fold().status).toMatchObject(unverifiedAt0("origin"));
    const stranger = user("stranger");
    const strangerRoot = rootState({ anchor: { user: stranger.id, signPub: stranger.signPub }, shares: [] });
    expect(Log.root(strangerRoot, stranger).fold().status).toMatchObject(unverifiedAt0("identity"));
  });

  it("an author who doesn't resolve makes the node unverified there, and nothing after counts", () => {
    const base = [share(alice, "owner"), share(bob, "editor")];
    const log = Log.root(rootState({ shares: base }));
    log.add(alice, rootState({ shares: [...base, share(carol, "viewer")] }));
    log.add(bob, rootState({ shares: [...base, share(carol, "viewer"), share(dan, "viewer")] }));
    log.add(
      alice,
      rootState({ shares: [...base, share(carol, "viewer"), share(dan, "viewer"), share(eve, "viewer")] }),
    );
    const bobUnknown = (id: string, pub: string) => (id === bob.id ? "unknown" : known(id, pub));
    const ns = log.fold({ identity: bobUnknown });
    expect(ns.status).toMatchObject({ kind: "unverified", atSeq: 2, reason: "identity" });
    expect(ns.state.shares).toEqual([...base, share(carol, "viewer")]);
    expect(ns.seq).toBe(3);
    expect(ns.head).toBe(snapshotHash(log.last()));
    expect(ns.stretchRemovals.userIds.size).toBe(0);
  });

  it("a checkpoint on a verified node is an owner's re-key, and anything relying on another log isn't checkable yet", () => {
    const base = [share(alice, "owner"), share(bob, "editor")];
    const checkpoint = Log.root(rootState({ shares: base }));
    const prev = checkpoint.last();
    checkpoint.push(
      createSnapshot(alice.account, {
        nodeId: checkpoint.nodeId,
        seq: 1,
        prev: snapshotHash(prev),
        state: rootState({ shares: base, version: 2, keyCommit: commit(2) }),
        change: "checkpoint",
        supersedes: snapshotHash(prev),
        skipped: [],
        nonce: null,
        deps: [],
        at,
      }),
    );
    expect(checkpoint.fold().status).toEqual(verified);
    expect(checkpoint.fold().state.version).toBe(2);

    const group = crypto.randomUUID();
    const grouped = Log.root(rootState({ shares: base }));
    grouped.add(bob, rootState({ shares: base, groupShares: [{ groupId: group, role: "viewer" }] }));
    expect(grouped.fold().state.groupShares).toEqual([{ groupId: group, role: "viewer" }]);
    // a role from that group counts only where the snapshot names it (teams.test.ts has the rest)
    grouped.add(
      carol,
      rootState({ shares: [...base, share(dan, "viewer")], groupShares: [{ groupId: group, role: "viewer" }] }),
    );
    expect(grouped.fold().status).toEqual(verified);
    expect(grouped.fold().state.shares).toEqual(base);

    const moved = Log.root(rootState({ shares: base }));
    moved.add(
      alice,
      rootState({ shares: base, parentId: crypto.randomUUID(), anchor: { user: alice.id, signPub: alice.signPub } }),
    );
    // a root never moves (moves.test.ts has the rest)
    expect(moved.fold().status).toEqual(verified);
    expect(moved.fold().state.parentId).toBeNull();

    const withDeps = Log.root(rootState({ shares: base }));
    const p = withDeps.last();
    withDeps.push(
      createSnapshot(alice.account, {
        nodeId: withDeps.nodeId,
        seq: 1,
        prev: snapshotHash(p),
        state: rootState({ shares: [...base, share(carol, "viewer")] }),
        change: "change",
        supersedes: null,
        skipped: [],
        nonce: null,
        deps: [{ log: `group:${group}`, seq: 1, head: commit(1) }],
        at,
      }),
    );
    // a group the client has no verified view of
    expect(withDeps.fold().status).toMatchObject({ kind: "unverified", atSeq: 1, reason: "needs-group" });
  });

  it("a team root's authority isn't judged yet, so its admins' changes leave it unverified, not skipped", () => {
    const nodeId = crypto.randomUUID();
    const base = [share(bob, "editor"), share(carol, "viewer")];
    const state = rootState({ anchor: { team: crypto.randomUUID() }, shares: base });
    const entry = legacySnapshot({ nodeId, state }, []);
    const legacyRoot = merkleRoot([{ nodeId, state }]);
    const log = new Log(nodeId);
    log.push(entry);
    expect(log.fold({ legacyRoot }).status).toEqual(verified);
    // alice has no share: if she's an Admin, her removal with its re-key is real
    log.add(alice, { ...state, shares: [share(bob, "editor")], version: 2, keyCommit: commit(2) });
    expect(log.fold({ legacyRoot }).status).toMatchObject({ kind: "unverified", atSeq: 1, reason: "needs-team" });
  });

  it("deps and checkpoints don't make a node unverified when the snapshot would be skipped anyway", () => {
    const base = [share(alice, "owner"), share(bob, "editor")];
    const signed = (log: Log, by: U, over: Partial<Snapshot>) => {
      const p = log.last();
      return createSnapshot(by.account, {
        nodeId: log.nodeId,
        seq: p.seq + 1,
        prev: snapshotHash(p),
        state: p.state,
        change: "change",
        supersedes: null,
        skipped: [],
        nonce: null,
        deps: [],
        at,
        ...over,
      });
    };
    const dep = [{ log: crypto.randomUUID(), seq: 1, head: commit(1) }];
    const tries: Array<[string, U, Partial<Snapshot>]> = [
      ["a stranger with deps", dan, { state: rootState({ shares: [...base, share(dan, "owner")] }), deps: dep }],
      [
        "a viewer with deps",
        carol,
        { state: rootState({ shares: [...base, share(carol, "viewer"), share(dan, "viewer")] }), deps: dep },
      ],
      ["an illegal change with deps", alice, { state: rootState({ shares: base, kind: "page" }), deps: dep }],
      [
        "a removal without its re-key, with deps",
        alice,
        { state: rootState({ shares: [share(alice, "owner")] }), deps: dep },
      ],
      [
        "an unknown signer's illegal change",
        user("x"),
        { state: rootState({ shares: base, version: 5, keyCommit: commit(5) }) },
      ],
    ];
    for (const [what, by, over] of tries) {
      const start = what === "a viewer with deps" ? [...base, share(carol, "viewer")] : base;
      const log = Log.root(rootState({ shares: start }));
      log.push(signed(log, by, over));
      const ns = log.fold();
      expect(ns.status, what).toEqual(verified);
      expect(ns.state, what).toEqual(rootState({ shares: start }));
    }
    const cp = (log: Log, by: U, state: State) =>
      signed(log, by, { state, change: "checkpoint", supersedes: snapshotHash(log.last()) });
    const illegal = Log.root(rootState({ shares: base }));
    illegal.push(cp(illegal, alice, rootState({ shares: base, kind: "page", version: 2, keyCommit: commit(2) })));
    expect(illegal.fold().status).toEqual(verified);
    const byEditor = Log.root(rootState({ shares: base }));
    byEditor.push(cp(byEditor, bob, rootState({ shares: base, version: 2, keyCommit: commit(2) })));
    expect(byEditor.fold().status).toEqual(verified);
    // an owner's checkpoint that doesn't name the head it follows is skipped too
    const noHead = Log.root(rootState({ shares: base }));
    noHead.push(
      signed(noHead, alice, {
        state: rootState({ shares: base, version: 2, keyCommit: commit(2) }),
        change: "checkpoint",
      }),
    );
    expect(noHead.fold().status).toEqual(verified);
    expect(noHead.fold().state.version).toBe(1);
    // an owner's checkpoint naming it applies (checkpoint.test.ts has the rest)
    const byOwner = Log.root(rootState({ shares: base }));
    byOwner.push(cp(byOwner, alice, rootState({ shares: base, version: 2, keyCommit: commit(2) })));
    expect(byOwner.fold().status).toEqual(verified);
    expect(byOwner.fold().state.version).toBe(2);
  });

  it("a legacy origin's unsigned fields are fixed, so it has one head", () => {
    const nodeId = crypto.randomUUID();
    const state = rootState({ keyCommit: null });
    const entry = legacySnapshot({ nodeId, state }, []);
    const legacyRoot = merkleRoot([{ nodeId, state }]);
    expect(entry).toMatchObject({ authorId: "", authorSignPub: "", sig: "", at: "", nonce: null, supersedes: null });
    expect(fold(nodeId, [entry], { legacyRoot }).status).toEqual(verified);
    const variants: Array<Partial<LogEntry>> = [
      { authorId: alice.id },
      { authorSignPub: alice.signPub },
      { sig: commit(3) },
      { at },
      { at: new Date(0).toISOString() },
      { skipped: [bob.id] },
      { deps: [{ log: crypto.randomUUID(), seq: 0, head: commit(1) }] },
      { nonce: commit(4) },
      { change: "change" },
    ];
    for (const v of variants) {
      expect(fold(nodeId, [{ ...entry, ...v }], { legacyRoot }).status, JSON.stringify(v)).toMatchObject({
        kind: "unverified",
        atSeq: 0,
        reason: "legacy",
      });
    }
  });

  it("folds each log once and turns re-entry into an unverified cycle", () => {
    const log = Log.root();
    let calls = 0;
    let inner: NodeState | null = null;
    const world: LogWorld = new LogWorld({
      logs: new Map([[log.nodeId, log.entries as LogEntry[]]]),
      legacyRoot: null,
      identity: (id, pub) => {
        calls++;
        inner = world.state(log.nodeId);
        return known(id, pub);
      },
      groups: noGroups,
    });
    expect(world.state(log.nodeId)?.status).toEqual(verified);
    expect((inner as NodeState | null)?.status).toMatchObject({ kind: "unverified", reason: "cycle" });
    // a fold that read a cycle is kept only for the log asked for from outside, so results don't
    // depend on which log was folded first, and asking again folds nothing again (world.ts)
    expect(world.state(log.nodeId)?.status).toEqual(verified);
    expect(calls).toBe(1);

    let plain = 0;
    const once = new LogWorld({
      logs: new Map([[log.nodeId, log.entries as LogEntry[]]]),
      legacyRoot: null,
      identity: (id, pub) => {
        plain++;
        return known(id, pub);
      },
      groups: noGroups,
    });
    expect(once.state(log.nodeId)?.status).toEqual(verified);
    expect(once.state(log.nodeId)?.status).toEqual(verified);
    expect(plain).toBe(1);
  });
});
