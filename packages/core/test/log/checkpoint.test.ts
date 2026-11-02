import { toBase64Url } from "@jelly/crypto";
import { describe, expect, it } from "vitest";
import {
  type Change,
  canCheckpoint,
  checkpointPrefill,
  createAccount,
  createFirstSnapshot,
  createSnapshot,
  type Dep,
  type GroupView,
  type LogEntry,
  LogWorld,
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

/** A dep on a log the server never shows: the check the snapshot relied on is hidden (§8.1). */
const hidden = (): Dep => ({ log: crypto.randomUUID(), seq: 1, head: commit(9) });

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
  head(): string {
    return snapshotHash(this.last());
  }
  dep(seq = this.last().seq): Dep {
    return { log: this.nodeId, seq, head: snapshotHash(this.entries[seq] as Snapshot) };
  }
  add(by: U, state: State, deps: Dep[] = [], change: Change = "change", supersedes: string | null = null): this {
    const prev = this.last();
    this.entries.push(
      createSnapshot(by.account, {
        nodeId: this.nodeId,
        seq: prev.seq + 1,
        prev: snapshotHash(prev),
        state,
        change,
        supersedes,
        skipped: [],
        nonce: null,
        deps,
        at,
      }),
    );
    return this;
  }
  /** A checkpoint naming the head it follows. */
  checkpoint(by: U, state: State, deps: Dep[] = []): this {
    return this.add(by, state, deps, "checkpoint", this.head());
  }
  /** The log without its last `n` entries. */
  without(n: number): Log {
    const l = new Log(this.nodeId);
    l.entries = this.entries.slice(0, this.entries.length - n);
    return l;
  }
  push(e: LogEntry): this {
    this.entries.push(e);
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
const fold = (log: Log, over: Partial<WorldInput> = {}): NodeState => st(world([log], over), log.nodeId);
const verified = { kind: "verified" };
const unverifiedAt = (atSeq: number, reason?: string) =>
  reason === undefined ? { kind: "unverified", atSeq } : { kind: "unverified", atSeq, reason };
const shareIds = (ns: NodeState) => ns.state.shares.map((s) => s.userId).sort();
const ids = (...us: U[]) => us.map((u) => u.id).sort();
const roleOf = (ns: NodeState, u: U) => ns.state.shares.find((s) => s.userId === u.id)?.role ?? null;

/** alice's root: alice and dan owners, bob editor, carol viewer. */
const base = [share(alice, "owner"), share(dan, "owner"), share(bob, "editor"), share(carol, "viewer")];
const without = (...us: U[]) => base.filter((s) => !us.some((u) => u.id === s.userId));
const rekey = (over: Partial<State>, version: number): State =>
  rootState({ ...over, version, keyCommit: commit(version) });

describe("the unverified stretch (§3.5)", () => {
  it("the entry that turns the node unverified counts: a removal there is applied and remembered", () => {
    const log = Log.create(alice, rootState({ shares: base }));
    // alice removes dan, re-keying, relying on a check the server hides
    log.add(alice, rekey({ shares: without(dan) }, 2), [hidden()]);
    const ns = fold(log);
    expect(ns.status).toMatchObject(unverifiedAt(1, "stale-dependency"));
    expect(shareIds(ns)).toEqual(ids(alice, bob, carol));
    expect([...ns.stretchRemovals.userIds]).toEqual([dan.id]);
    expect(ns.stretchVersion).toBe(2);
    // the applied prefix is the state before the stretch
    expect(ns.state.version).toBe(1);
    // a removed owner isn't offered the repair
    expect(world([log]).role(dan.id, log.nodeId)).toBeNull();
    expect(world([log]).role(alice.id, log.nodeId)).toBe("owner");
  });

  it("additions and promotions in the stretch are ignored, removals and demotions by anyone are applied", () => {
    const log = Log.create(alice, rootState({ shares: base }));
    log.add(alice, rekey({ shares: base }, 2), [hidden()]);
    // an owner adds eve and promotes carol: ignored
    log.add(alice, rekey({ shares: [...without(carol), share(carol, "editor"), share(eve, "owner")] }, 2));
    let ns = fold(log);
    expect(shareIds(ns)).toEqual(ids(alice, dan, bob, carol));
    expect(roleOf(ns, carol)).toBe("viewer");
    // a viewer's snapshot leaving bob out, and demoting dan: applied to the effective state, but not counted
    log.add(carol, rekey({ shares: [share(alice, "owner"), share(dan, "editor"), share(carol, "viewer")] }, 2));
    ns = fold(log);
    expect(shareIds(ns)).toEqual(ids(alice, dan, carol));
    expect(roleOf(ns, dan)).toBe("editor");
    expect(ns.stretchRemovals.userIds.size).toBe(0);
    expect(ns.stretchRemovals.demoted.size).toBe(0);
    // an owner's removal is counted
    log.add(alice, rekey({ shares: [share(alice, "owner"), share(dan, "editor")] }, 3));
    ns = fold(log);
    expect(shareIds(ns)).toEqual(ids(alice, dan));
    expect([...ns.stretchRemovals.userIds]).toEqual([carol.id]);
    expect(ns.stretchVersion).toBe(3);
  });

  it("the version floor comes from the log bytes alone: any signed version honest re-keys could have reached", () => {
    const log = Log.create(alice, rootState({ shares: base }));
    log.add(alice, rekey({ shares: base }, 2), [hidden()]);
    const stranger = user("stranger");
    // a stranger's snapshot: well formed and signed, but this account doesn't resolve them. Its version is
    // beyond what honest re-keys could have reached by the second entry (1 + 2), so it doesn't count; nor do its removals
    log.add(stranger, rekey({ shares: [share(alice, "owner")] }, 5));
    let ns = fold(log);
    expect(shareIds(ns)).toEqual(ids(alice, dan, bob, carol));
    expect(ns.stretchVersion).toBe(2);
    // a chained entry whose signature doesn't check (its state was changed after signing) counts for nothing
    const tampered = { ...log.last(), state: rekey({ shares: [] }, 50) } as LogEntry;
    const junk = { ...tampered, seq: log.last().seq + 1, prev: log.head() } as LogEntry;
    log.push(junk);
    ns = fold(log);
    expect(ns.seq).toBe(3);
    expect(shareIds(ns)).toEqual(ids(alice, dan, bob, carol));
    expect(ns.stretchVersion).toBe(2);
    // a stranger's version within reach does count (another client may resolve them and have applied that
    // re-key; every client must compute the same floor), their removals still don't
    log.add(stranger, rekey({ shares: [share(alice, "owner")] }, 3));
    ns = fold(log);
    expect(ns.stretchVersion).toBe(3);
    expect(shareIds(ns)).toEqual(ids(alice, dan, bob, carol));
    // a resolvable never-member and a viewer likewise: in reach counts, out of reach doesn't; an editor the same
    const resolved = Log.create(alice, rootState({ shares: base }));
    resolved.add(alice, rekey({ shares: base }, 2), [hidden()]);
    resolved.add(eve, rekey({ shares: base }, 6));
    expect(fold(resolved).stretchVersion).toBe(2);
    resolved.add(carol, rekey({ shares: base }, 3));
    expect(fold(resolved).stretchVersion).toBe(3);
    resolved.add(bob, rekey({ shares: base }, 4));
    expect(fold(resolved).stretchVersion).toBe(4);
  });

  it("a leave in the stretch is counted whoever leaves", () => {
    const log = Log.create(alice, rootState({ shares: base }));
    log.add(alice, rekey({ shares: base }, 2), [hidden()]);
    log.add(bob, rekey({ shares: without(bob) }, 2), [], "leave");
    const ns = fold(log);
    expect(shareIds(ns)).toEqual(ids(alice, dan, carol));
    expect([...ns.stretchRemovals.userIds]).toEqual([bob.id]);
    // alice can't bring bob back in the checkpoint; without him it goes through
    const back = log.without(0);
    back.checkpoint(alice, rekey({ shares: base }, 3));
    expect(fold(back).status).toMatchObject(unverifiedAt(1));
    log.checkpoint(alice, rekey({ shares: without(bob) }, 3));
    expect(fold(log).status).toEqual(verified);
  });
});

describe("checkpoints (§8.1)", () => {
  it("a removal hidden by the server can't be checkpointed away", () => {
    const log = Log.create(alice, rootState({ shares: base }));
    log.add(alice, rekey({ shares: without(dan) }, 2), [hidden()]);
    const ns = fold(log);
    expect(ns.status).toMatchObject(unverifiedAt(1));

    // dan, removed by an owner in the stretch, checkpoints himself back in: skipped
    const byDan = log.without(0).checkpoint(dan, rekey({ shares: base }, 3));
    const d = fold(byDan);
    expect(d.status).toMatchObject(unverifiedAt(1));
    expect(shareIds(d)).toEqual(ids(alice, bob, carol));
    // alice's checkpoint that still names dan: skipped too
    const withDan = log.without(0).checkpoint(alice, rekey({ shares: base }, 3));
    expect(fold(withDan).status).toMatchObject(unverifiedAt(1));

    // the pre-fill is the last verified state minus the stretch's removals, at the stretch's version
    const pre = checkpointPrefill(ns);
    expect(pre.shares.map((s) => s.userId).sort()).toEqual(ids(alice, bob, carol));
    expect(pre.version).toBe(2);
    // alice checkpoints from it: the node is verified again from there
    log.checkpoint(alice, { ...pre, version: pre.version + 1, keyCommit: commit(3) });
    const after = fold(log);
    expect(after.status).toEqual(verified);
    expect(after.seq).toBe(2);
    expect(shareIds(after)).toEqual(ids(alice, bob, carol));
    expect(after.state.version).toBe(3);
    expect(after.state.keyCommit).toBe(commit(3));
    expect(after.stale).toBe(false);
    expect(after.stretchRemovals.userIds.size).toBe(0);
    expect(after.stretchVersion).toBe(3);
    // dan comes back only by a normal snapshot after it
    log.add(alice, rekey({ shares: base }, 3));
    expect(shareIds(fold(log))).toEqual(ids(alice, dan, bob, carol));
    expect(fold(log).status).toEqual(verified);
  });

  it("a demoted owner can't checkpoint themselves back", () => {
    const log = Log.create(alice, rootState({ shares: base }));
    log.add(alice, rootState({ shares: [...without(dan), share(dan, "editor")] }), [hidden()]);
    const ns = fold(log);
    expect(ns.status).toMatchObject(unverifiedAt(1));
    expect(roleOf(ns, dan)).toBe("editor");
    expect(ns.stretchRemovals.demoted.get(`u:${dan.id}`)).toBe("editor");

    const byDan = log.without(0).checkpoint(dan, rekey({ shares: base }, 2));
    expect(fold(byDan).status).toMatchObject(unverifiedAt(1));
    const asOwner = log.without(0).checkpoint(alice, rekey({ shares: base }, 2));
    expect(fold(asOwner).status).toMatchObject(unverifiedAt(1));
    const pre = checkpointPrefill(ns);
    expect(pre.shares.find((s) => s.userId === dan.id)?.role).toBe("editor");
    log.checkpoint(alice, { ...pre, version: pre.version + 1, keyCommit: commit(2) });
    const after = fold(log);
    expect(after.status).toEqual(verified);
    expect(roleOf(after, dan)).toBe("editor");
  });

  it("the root owner can always checkpoint", () => {
    const log = Log.create(alice, rootState({ shares: base }));
    // dan, an owner, removes alice's share with the server hiding the check
    log.add(dan, rekey({ shares: without(alice) }, 2), [hidden()]);
    const ns = fold(log);
    expect(ns.status).toMatchObject(unverifiedAt(1));
    expect([...ns.stretchRemovals.userIds]).toEqual([alice.id]);
    expect(world([log]).role(alice.id, log.nodeId)).toBe("owner");
    // the anchor can't be removed: her checkpoint, without her share, is applied
    const pre = checkpointPrefill(ns);
    expect(pre.shares.some((s) => s.userId === alice.id)).toBe(false);
    log.checkpoint(alice, { ...pre, version: 3, keyCommit: commit(3) });
    const after = fold(log);
    expect(after.status).toEqual(verified);
    expect(shareIds(after)).toEqual(ids(dan, bob, carol));
    // and she gives herself the share back normally
    log.add(alice, rekey({ shares: base }, 3));
    expect(shareIds(fold(log))).toEqual(ids(alice, dan, bob, carol));
  });

  it("a checkpoint's version is above the stretch's floor and at most the floor plus its seq, with a new commit", () => {
    const log = Log.create(alice, rootState({ shares: base }));
    log.add(bob, rekey({ shares: base }, 2), [hidden()]);
    log.add(bob, rekey({ shares: base }, 3));
    const stranger = user("stranger");
    log.add(stranger, rekey({ shares: base }, 7));
    const ns = fold(log);
    expect(ns.status).toMatchObject(unverifiedAt(1));
    // bob, an editor, raised the floor; the stranger didn't
    expect(ns.stretchVersion).toBe(3);
    // the checkpoint is seq 4: the window is (3, 3 + 4]
    for (const v of [1, 2, 3, 8, 20, Number.MAX_SAFE_INTEGER]) {
      const off = log.without(0).checkpoint(alice, rekey({ shares: base }, v));
      expect(fold(off).status, `version ${v}`).toMatchObject(unverifiedAt(1));
    }
    for (const v of [5, 6, 7]) {
      const inWindow = log.without(0).checkpoint(alice, rekey({ shares: base }, v));
      expect(fold(inWindow).status, `version ${v}`).toEqual(verified);
      expect(fold(inWindow).state.version, `version ${v}`).toBe(v);
    }
    const sameCommit = log.without(0).checkpoint(alice, rootState({ shares: base, version: 4, keyCommit: commit(1) }));
    expect(fold(sameCommit).status).toMatchObject(unverifiedAt(1));
    const noCommit = log.without(0).checkpoint(alice, rootState({ shares: base, version: 4, keyCommit: null }));
    expect(fold(noCommit).status).toMatchObject(unverifiedAt(1));
    const ok = log.without(0).checkpoint(alice, rekey({ shares: base }, 4));
    expect(fold(ok).status).toEqual(verified);
    expect(fold(ok).state.version).toBe(4);
    expect(checkpointPrefill(ns).version + 1).toBe(4);
  });

  it("a stranger's absurd version doesn't make repair impossible", () => {
    const log = Log.create(alice, rootState({ shares: [share(alice, "owner"), share(bob, "editor")] }));
    log.add(alice, rekey({ shares: [share(alice, "owner"), share(bob, "editor")] }, 2), [hidden()]);
    const stranger = user("stranger");
    log.add(
      stranger,
      rootState({ shares: [share(alice, "owner")], version: Number.MAX_SAFE_INTEGER, keyCommit: commit(5) }),
    );
    const ns = fold(log);
    expect(ns.stretchVersion).toBe(2);
    const pre = checkpointPrefill(ns);
    log.checkpoint(alice, { ...pre, version: pre.version + 1, keyCommit: commit(6) });
    expect(fold(log).status).toEqual(verified);
    expect(fold(log).state.version).toBe(3);
  });

  it("nothing added in the stretch counts, unless the checkpoint adds it", () => {
    const log = Log.create(alice, rootState({ shares: base }));
    log.add(alice, rekey({ shares: [...base, share(eve, "owner")] }, 2), [hidden()]);
    const ns = fold(log);
    expect(roleOf(ns, eve)).toBeNull();
    expect(world([log]).role(eve.id, log.nodeId)).toBeNull();
    // eve isn't an owner on the last verified prefix
    const byEve = log.without(0).checkpoint(eve, rekey({ shares: [...base, share(eve, "owner")] }, 3));
    expect(fold(byEve).status).toMatchObject(unverifiedAt(1));
    // the pre-fill leaves her out; the owner may add her by name
    expect(checkpointPrefill(ns).shares.some((s) => s.userId === eve.id)).toBe(false);
    const plain = log.without(0).checkpoint(alice, rekey({ shares: base }, 3));
    expect(roleOf(fold(plain), eve)).toBeNull();
    const confirmed = log.without(0).checkpoint(alice, rekey({ shares: [...base, share(eve, "owner")] }, 3));
    expect(fold(confirmed).status).toEqual(verified);
    expect(roleOf(fold(confirmed), eve)).toBe("owner");
    // someone added and removed again in the stretch was never there: no removal is counted
    const addRemove = Log.create(alice, rootState({ shares: base }));
    addRemove.add(alice, rekey({ shares: [...base, share(eve, "viewer")] }, 2), [hidden()]);
    addRemove.add(alice, rekey({ shares: base }, 3));
    expect(fold(addRemove).stretchRemovals.userIds.size).toBe(0);
  });

  it("a former member's stretch snapshot doesn't block an owner's checkpoint", () => {
    const log = Log.create(alice, rootState({ shares: base }));
    // eve was a member once, removed before the stretch
    log.add(alice, rekey({ shares: [...base, share(eve, "editor")] }, 2));
    log.add(alice, rekey({ shares: base }, 3));
    log.add(alice, rekey({ shares: base }, 4), [hidden()]);
    // eve, carol (viewer) and bob (editor) each sign a snapshot dropping people
    log.add(eve, rekey({ shares: [share(dan, "owner")] }, 4));
    log.add(carol, rekey({ shares: [share(alice, "owner")] }, 4));
    log.add(bob, rekey({ shares: [share(alice, "owner"), share(bob, "editor")] }, 4));
    const ns = fold(log);
    expect(ns.status).toMatchObject(unverifiedAt(3));
    // conservatively applied while unverified, each against the effective state before it; alice stays owner by the anchor
    expect(shareIds(ns)).toEqual([]);
    expect(world([log]).role(alice.id, log.nodeId)).toBe("owner");
    expect(ns.stretchRemovals.userIds.size).toBe(0);
    // but the owners' checkpoint, with everyone, goes through
    log.checkpoint(alice, rekey({ shares: base }, 5));
    const after = fold(log);
    expect(after.status).toEqual(verified);
    expect(shareIds(after)).toEqual(ids(alice, dan, bob, carol));
  });

  it("someone removed by a counted removal can't block the owners who stay", () => {
    const log = Log.create(alice, rootState({ shares: base }));
    // alice removes dan (hidden check), then dan removes alice's share and bob
    log.add(alice, rekey({ shares: without(dan) }, 2), [hidden()]);
    log.add(dan, rekey({ shares: [share(carol, "viewer")] }, 3));
    const ns = fold(log);
    expect([...ns.stretchRemovals.userIds]).toEqual([dan.id]);
    expect(shareIds(ns)).toEqual(ids(carol));
    log.checkpoint(alice, rekey({ shares: without(dan) }, 4));
    const after = fold(log);
    expect(after.status).toEqual(verified);
    expect(shareIds(after)).toEqual(ids(alice, bob, carol));
  });

  it("a checkpoint names the head it follows and keeps kind and anchor", () => {
    const log = Log.create(alice, rootState({ shares: base }));
    log.add(alice, rekey({ shares: base }, 2), [hidden()]);
    const noSupersedes = log.without(0).add(alice, rekey({ shares: base }, 3), [], "checkpoint", null);
    expect(fold(noSupersedes).status).toMatchObject(unverifiedAt(1));
    const wrong = log.without(0).add(alice, rekey({ shares: base }, 3), [], "checkpoint", commit(4));
    expect(fold(wrong).status).toMatchObject(unverifiedAt(1));
    const older = log
      .without(0)
      .add(alice, rekey({ shares: base }, 3), [], "checkpoint", snapshotHash(log.entries[0] as Snapshot));
    expect(fold(older).status).toMatchObject(unverifiedAt(1));
    const kind = log.without(0).checkpoint(alice, rekey({ shares: base, kind: "page" }, 3));
    expect(fold(kind).status).toMatchObject(unverifiedAt(1));
    const anchor = log
      .without(0)
      .checkpoint(alice, rekey({ shares: base, anchor: { user: dan.id, signPub: dan.signPub } }, 3));
    expect(fold(anchor).status).toMatchObject(unverifiedAt(1));
    // an editor can't checkpoint
    const byBob = log.without(0).checkpoint(bob, rekey({ shares: base }, 3));
    expect(fold(byBob).status).toMatchObject(unverifiedAt(1));
    const good = log.without(0).checkpoint(alice, rekey({ shares: base }, 3));
    expect(fold(good).status).toEqual(verified);
  });

  it("a checkpoint on a verified node is an owner's re-key, so clients that saw no stretch accept it", () => {
    const log = Log.create(alice, rootState({ shares: base }));
    log.add(alice, rekey({ shares: without(carol) }, 2));
    // alice's device couldn't check seq 1 and checkpointed; this one could, and sees a plain owner's re-key
    log.checkpoint(alice, rekey({ shares: without(carol) }, 3));
    const ns = fold(log);
    expect(ns.status).toEqual(verified);
    expect(ns.state.version).toBe(3);
    expect(shareIds(ns)).toEqual(ids(alice, dan, bob));
    // its version is exactly one up; an editor's, or one not naming the head, is skipped while the node stays verified
    const jump = Log.create(alice, rootState({ shares: base })).checkpoint(alice, rekey({ shares: base }, 4));
    expect(fold(jump).status).toEqual(verified);
    expect(fold(jump).state.version).toBe(1);
    const bricked = Log.create(alice, rootState({ shares: base })).checkpoint(
      alice,
      rekey({ shares: base }, Number.MAX_SAFE_INTEGER),
    );
    expect(fold(bricked).state.version).toBe(1);
    const byBob = Log.create(alice, rootState({ shares: base })).checkpoint(bob, rekey({ shares: base }, 2));
    expect(fold(byBob).status).toEqual(verified);
    expect(fold(byBob).state.version).toBe(1);
    const noHead = Log.create(alice, rootState({ shares: base })).add(
      alice,
      rekey({ shares: base }, 2),
      [],
      "checkpoint",
      null,
    );
    expect(fold(noHead).status).toEqual(verified);
    expect(fold(noHead).state.version).toBe(1);
  });

  it("a checkpoint's deps are no older than any dep in the stretch", () => {
    const folder = Log.create(alice, rootState({ shares: [share(alice, "owner"), share(bob, "editor")] }));
    const page = Log.create(bob, childState(folder.nodeId), [folder.dep()]);
    folder.add(alice, rootState({ shares: [share(alice, "owner"), share(bob, "editor"), share(carol, "viewer")] }));
    // bob re-keys the page naming the folder at 1, and something the server hides
    page.add(bob, childState(folder.nodeId, { version: 2, keyCommit: commit(2) }), [folder.dep(1), hidden()]);
    expect(st(world([folder, page]), page.nodeId).status).toMatchObject(unverifiedAt(1));
    const older = page
      .without(0)
      .checkpoint(alice, childState(folder.nodeId, { version: 3, keyCommit: commit(3) }), [folder.dep(0)]);
    expect(st(world([folder, older]), page.nodeId).status).toMatchObject(unverifiedAt(1));
    const newer = page
      .without(0)
      .checkpoint(alice, childState(folder.nodeId, { version: 3, keyCommit: commit(3) }), [folder.dep(1)]);
    const ns = st(world([folder, newer]), page.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.deps.get(folder.nodeId)?.seq).toBe(1);
    // a checkpoint whose own dep can't be checked isn't checkable: the node stays unverified
    const unchecked = page
      .without(0)
      .checkpoint(alice, childState(folder.nodeId, { version: 3, keyCommit: commit(3) }), [folder.dep(1), hidden()]);
    expect(st(world([folder, unchecked]), page.nodeId).status).toMatchObject(unverifiedAt(1));
  });

  it("a checkpoint's author is judged on the parent chain too, and a new parent passes the move rules", () => {
    const folder = Log.create(alice, rootState({ shares: [share(alice, "owner"), share(bob, "editor")] }));
    const other = Log.create(alice, childState(folder.nodeId, { kind: "folder" }), [folder.dep()]);
    const away = Log.create(
      dan,
      rootState({ anchor: { user: dan.id, signPub: dan.signPub }, shares: [share(dan, "owner")] }),
    );
    const page = Log.create(bob, childState(folder.nodeId), [folder.dep()]);
    page.add(bob, childState(folder.nodeId, { shares: [share(carol, "viewer")] }), [folder.dep(), hidden()]);
    const logs = () => [folder, other, away];
    expect(st(world([...logs(), page]), page.nodeId).status).toMatchObject(unverifiedAt(1));
    // alice owns the page through the folder
    const stay = page
      .without(0)
      .checkpoint(alice, childState(folder.nodeId, { version: 2, keyCommit: commit(2) }), [folder.dep()]);
    expect(st(world([...logs(), stay]), page.nodeId).status).toEqual(verified);
    // and may move it to another folder of hers, naming both
    const moved = page
      .without(0)
      .checkpoint(alice, childState(other.nodeId, { version: 2, keyCommit: commit(2) }), [folder.dep(), other.dep()]);
    const ns = st(world([...logs(), moved]), page.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.parentId).toBe(other.nodeId);
    // not to another root
    const stolen = page
      .without(0)
      .checkpoint(alice, childState(away.nodeId, { version: 2, keyCommit: commit(2) }), [folder.dep(), away.dep()]);
    expect(st(world([...logs(), stolen]), page.nodeId).status).toMatchObject(unverifiedAt(1));
    // bob, an editor, can't checkpoint
    const byBob = page
      .without(0)
      .checkpoint(bob, childState(folder.nodeId, { version: 2, keyCommit: commit(2) }), [folder.dep()]);
    expect(st(world([...logs(), byBob]), page.nodeId).status).toMatchObject(unverifiedAt(1));
  });

  it("a restriction by an owner in the stretch stands against a checkpoint", () => {
    const folder = Log.create(
      alice,
      rootState({ shares: [share(alice, "owner"), share(dan, "owner"), share(bob, "editor")] }),
    );
    const page = Log.create(alice, childState(folder.nodeId), [folder.dep()]);
    // alice restricts the page to herself; the server hides the check
    page.add(
      alice,
      childState(folder.nodeId, {
        restricted: true,
        shares: [share(alice, "owner")],
        version: 2,
        keyCommit: commit(2),
      }),
      [folder.dep(), hidden()],
    );
    const ns = st(world([folder, page]), page.nodeId);
    expect(ns.status).toMatchObject(unverifiedAt(1));
    expect(ns.stretchRemovals.restricted).toBe(true);
    // the effective place isn't changed, so the restricter (owner only through the folder) is still offered the repair
    expect(ns.state.restricted).toBe(false);
    expect(world([folder, page]).role(alice.id, page.nodeId)).toBe("owner");
    // dan, an owner only through the folder, can't checkpoint it back open
    const byDan = page
      .without(0)
      .checkpoint(dan, childState(folder.nodeId, { version: 3, keyCommit: commit(3) }), [folder.dep()]);
    expect(st(world([folder, byDan]), page.nodeId).status).toMatchObject(unverifiedAt(1));
    // alice's checkpoint keeps it restricted
    const open = page
      .without(0)
      .checkpoint(
        alice,
        childState(folder.nodeId, { shares: [share(alice, "owner")], version: 3, keyCommit: commit(3) }),
        [folder.dep()],
      );
    expect(st(world([folder, open]), page.nodeId).status).toMatchObject(unverifiedAt(1));
    // the pre-fill stays restricted; for the restricter it keeps her owner share, so the node isn't left with no owner
    const bare = checkpointPrefill(ns);
    expect(bare.restricted).toBe(true);
    expect(bare.shares).toEqual([]);
    const pre = checkpointPrefill(ns, { userId: alice.id, signPub: alice.signPub });
    expect(pre.restricted).toBe(true);
    expect(pre.shares).toEqual([share(alice, "owner")]);
    // dan isn't offered the repair; alice is
    expect(canCheckpoint(world([folder, page]), ns, dan.id)).toBe(false);
    expect(canCheckpoint(world([folder, page]), ns, alice.id)).toBe(true);
    page.checkpoint(alice, { ...pre, version: 3, keyCommit: commit(3) }, [folder.dep()]);
    const after = st(world([folder, page]), page.nodeId);
    expect(after.status).toEqual(verified);
    expect(after.state.restricted).toBe(true);
    expect(roleOf(after, alice)).toBe("owner");
  });

  it("after a checkpoint the node can go unverified again, and the next checkpoint sees only the new stretch", () => {
    const log = Log.create(alice, rootState({ shares: base }));
    log.add(alice, rekey({ shares: without(dan) }, 2), [hidden()]);
    log.checkpoint(alice, rekey({ shares: without(dan) }, 3));
    log.add(alice, rekey({ shares: base }, 3));
    expect(fold(log).status).toEqual(verified);
    // a second stretch: alice removes carol with a hidden check
    log.add(alice, rekey({ shares: without(carol) }, 4), [hidden()]);
    const ns = fold(log);
    expect(ns.status).toMatchObject(unverifiedAt(4));
    expect([...ns.stretchRemovals.userIds]).toEqual([carol.id]);
    expect(shareIds(ns)).toEqual(ids(alice, dan, bob));
    // dan is fine again: the first stretch is history
    log.checkpoint(dan, rekey({ shares: without(carol) }, 5));
    const after = fold(log);
    expect(after.status).toEqual(verified);
    expect(shareIds(after)).toEqual(ids(alice, dan, bob));
  });

  it("a checkpoint by an author this account doesn't resolve isn't checkable, and still bounds the version", () => {
    const log = Log.create(alice, rootState({ shares: base }));
    log.add(alice, rekey({ shares: base }, 2), [hidden()]);
    log.checkpoint(dan, rekey({ shares: base }, 3));
    const danUnknown = (id: string, pub: string) => (id === dan.id ? "unknown" : known(id, pub));
    const ns = fold(log, { identity: danUnknown });
    expect(ns.status).toMatchObject(unverifiedAt(1));
    expect(ns.stretchVersion).toBe(3);
    // version 3 again would give that version two commits for whoever resolves dan: skipped
    const twice = log.without(0).checkpoint(alice, rekey({ shares: base }, 3));
    expect(fold(twice, { identity: danUnknown }).status).toMatchObject(unverifiedAt(1));
    // version 4 is accepted by this account, and by one that resolves dan and applied his checkpoint
    log.checkpoint(alice, rekey({ shares: base }, 4));
    for (const identity of [danUnknown, known]) {
      const after = fold(log, { identity });
      expect(after.status).toEqual(verified);
      expect(after.state.version).toBe(4);
      expect(after.state.keyCommit).toBe(commit(4));
    }
  });
});

describe("review probes (regressions)", () => {
  const folderShares = [share(alice, "owner"), share(bob, "editor")];

  it("P1: a stretch snapshot naming a dep behind the applied floor counts for nothing", () => {
    // folder: alice anchor, dan owner; alice then removes dan (verified)
    const folder = Log.create(alice, rootState({ shares: [share(alice, "owner"), share(dan, "owner")] }));
    folder.add(alice, rekey({ shares: [share(alice, "owner")] }, 2));
    // page under the folder: bob is owner by share; its log already named folder@1
    const page = Log.create(alice, childState(folder.nodeId, { shares: [share(bob, "owner")] }), [folder.dep(0)]);
    const two = [share(bob, "owner"), share(carol, "viewer")];
    page.add(alice, childState(folder.nodeId, { shares: two }), [folder.dep(1)]);
    expect(st(world([folder, page]), page.nodeId).deps.get(folder.nodeId)?.seq).toBe(1);
    // the page goes unverified: alice re-keys with a hidden check
    page.add(alice, childState(folder.nodeId, { shares: two, version: 2, keyCommit: commit(2) }), [
      folder.dep(1),
      hidden(),
    ]);
    expect(st(world([folder, page]), page.nodeId).status).toMatchObject(unverifiedAt(2));
    // dan, removed from the folder, removes bob naming folder@0, from before his removal
    page.add(dan, childState(folder.nodeId, { shares: [share(carol, "viewer")], version: 3, keyCommit: commit(3) }), [
      folder.dep(0),
    ]);
    const ns = st(world([folder, page]), page.nodeId);
    expect(ns.stretchRemovals.userIds.has(bob.id)).toBe(false);
    // his version is within reach, so it bounds the checkpoint like anyone's
    expect(ns.stretchVersion).toBe(3);
    // the drop is still applied to the conservative state, and bob's checkpoint goes through
    expect(shareIds(ns)).toEqual(ids(carol));
    expect(canCheckpoint(world([folder, page]), ns, bob.id)).toBe(true);
    page.checkpoint(bob, childState(folder.nodeId, { shares: two, version: 4, keyCommit: commit(4) }), [folder.dep(1)]);
    const after = st(world([folder, page]), page.nodeId);
    expect(after.status).toEqual(verified);
    expect(shareIds(after)).toEqual(ids(bob, carol));
  });

  it("P1b: a stretch snapshot whose dep names a head this client doesn't have isn't counted", () => {
    const folder = Log.create(alice, rootState({ shares: [share(alice, "owner"), share(dan, "owner")] }));
    const two = [share(bob, "owner"), share(carol, "viewer")];
    const page = Log.create(alice, childState(folder.nodeId, { shares: two }), [folder.dep()]);
    page.add(alice, childState(folder.nodeId, { shares: two, version: 2, keyCommit: commit(2) }), [
      folder.dep(),
      hidden(),
    ]);
    // dan, an owner through the folder, removes bob naming a folder head this client can't check
    page.add(dan, childState(folder.nodeId, { shares: [share(carol, "viewer")], version: 3, keyCommit: commit(3) }), [
      { log: folder.nodeId, seq: 0, head: commit(8) },
    ]);
    const ns = st(world([folder, page]), page.nodeId);
    expect(ns.stretchRemovals.userIds.has(bob.id)).toBe(false);
    // naming the real head, it counts
    const real = page.without(1);
    real.add(dan, childState(folder.nodeId, { shares: [share(carol, "viewer")], version: 3, keyCommit: commit(3) }), [
      folder.dep(),
    ]);
    expect(st(world([folder, real]), page.nodeId).stretchRemovals.userIds.has(bob.id)).toBe(true);
  });

  it("P2: an unresolvable author's dep floor doesn't count; an editor's does", () => {
    const folder = Log.create(alice, rootState({ shares: folderShares }));
    const page = Log.create(bob, childState(folder.nodeId), [folder.dep()]);
    page.add(bob, childState(folder.nodeId, { version: 2, keyCommit: commit(2) }), [folder.dep(), hidden()]);
    const stranger = user("stranger");
    page.add(stranger, childState(folder.nodeId, { version: 2, keyCommit: commit(2) }), [
      { log: folder.nodeId, seq: 999, head: commit(7) },
    ]);
    expect(st(world([folder, page]), page.nodeId).status).toMatchObject(unverifiedAt(1));
    // alice, the root owner, checkpoints naming the folder's real head
    const fixed = page
      .without(0)
      .checkpoint(alice, childState(folder.nodeId, { version: 3, keyCommit: commit(3) }), [folder.dep()]);
    expect(st(world([folder, fixed]), page.nodeId).status).toEqual(verified);
    // an editor naming the folder at 1 raises the floor: a checkpoint naming it at 0 is skipped, at 1 applies
    folder.add(alice, rootState({ shares: [...folderShares, share(carol, "viewer")] }));
    const byBob = page.without(0);
    byBob.add(bob, childState(folder.nodeId, { version: 2, keyCommit: commit(2) }), [folder.dep(1)]);
    const old = new Log(page.nodeId);
    old.entries = [...byBob.entries];
    old.checkpoint(alice, childState(folder.nodeId, { version: 3, keyCommit: commit(3) }), [folder.dep(0)]);
    expect(st(world([folder, old]), page.nodeId).status).toMatchObject(unverifiedAt(1));
    byBob.checkpoint(alice, childState(folder.nodeId, { version: 3, keyCommit: commit(3) }), [folder.dep(1)]);
    expect(st(world([folder, byBob]), page.nodeId).status).toEqual(verified);
  });

  it("P4: the repair offer reads the guard, not the conservative state", () => {
    const three = [share(alice, "owner"), share(dan, "owner"), share(bob, "editor")];
    const log = Log.create(alice, rootState({ shares: three }));
    log.add(alice, rekey({ shares: three }, 2), [hidden()]);
    // eve, resolvable and never a member, drops everyone
    log.add(eve, rekey({ shares: [] }, 2));
    const w = world([log]);
    const ns = st(w, log.nodeId);
    expect(shareIds(ns)).toEqual([]);
    expect(w.role(dan.id, log.nodeId)).toBeNull();
    expect(canCheckpoint(w, ns, dan.id)).toBe(true);
    expect(canCheckpoint(w, ns, alice.id)).toBe(true);
    expect(canCheckpoint(w, ns, bob.id)).toBe(false);
    expect(canCheckpoint(w, ns, eve.id)).toBe(false);
    // a counted removal takes the offer away; a verified node offers nothing
    const removed = log.without(1);
    removed.add(alice, rekey({ shares: [share(alice, "owner"), share(bob, "editor")] }, 3));
    expect(canCheckpoint(world([removed]), fold(removed), dan.id)).toBe(false);
    expect(canCheckpoint(w, fold(Log.create(alice, rootState({ shares: three }))), alice.id)).toBe(false);
    log.checkpoint(dan, rekey({ shares: three }, 3));
    expect(fold(log).status).toEqual(verified);
    expect(shareIds(fold(log))).toEqual(ids(alice, dan, bob));
  });

  it("P5: on a verified node an editor's checkpoint can't remove, and an owner's can't move across roots", () => {
    const folder = Log.create(alice, rootState({ shares: folderShares }));
    const other = Log.create(
      dan,
      rootState({
        anchor: { user: dan.id, signPub: dan.signPub },
        shares: [share(dan, "owner"), share(alice, "editor")],
      }),
    );
    const page = Log.create(bob, childState(folder.nodeId, { shares: [share(carol, "viewer")] }), [folder.dep()]);
    const byBob = page
      .without(0)
      .checkpoint(bob, childState(folder.nodeId, { version: 2, keyCommit: commit(2) }), [folder.dep()]);
    const b = st(world([folder, other, byBob]), page.nodeId);
    expect(b.status).toEqual(verified);
    expect(b.state.version).toBe(1);
    expect(shareIds(b)).toEqual(ids(carol));
    const moved = page
      .without(0)
      .checkpoint(
        alice,
        childState(other.nodeId, { shares: [share(carol, "viewer")], version: 2, keyCommit: commit(2) }),
        [folder.dep(), other.dep()],
      );
    const m = st(world([folder, other, moved]), page.nodeId);
    expect(m.status).toEqual(verified);
    expect(m.state.parentId).toBe(folder.nodeId);
  });

  it("P6: a stretch author is judged in the now view, so an owner made after the stretch began counts, with checkable deps", () => {
    const folder = Log.create(alice, rootState({ shares: [share(alice, "owner")] }));
    const page = Log.create(alice, childState(folder.nodeId, { shares: [share(bob, "owner")] }), [folder.dep()]);
    page.add(alice, childState(folder.nodeId, { shares: [share(bob, "owner")], version: 2, keyCommit: commit(2) }), [
      folder.dep(),
      hidden(),
    ]);
    // eve becomes owner of the folder later (verified)
    folder.add(alice, rekey({ shares: [share(alice, "owner"), share(eve, "owner")] }, 2));
    // eve removes bob naming only a log this client can't see: a hidden check still counts, by her role now
    const hiddenOnly = page.without(0);
    hiddenOnly.add(eve, childState(folder.nodeId, { shares: [], version: 3, keyCommit: commit(3) }), [hidden()]);
    expect(st(world([folder, hiddenOnly]), page.nodeId).stretchRemovals.userIds.has(bob.id)).toBe(true);
    // naming the folder as it is now, she is an owner there too
    page.add(eve, childState(folder.nodeId, { shares: [], version: 3, keyCommit: commit(3) }), [folder.dep()]);
    expect(st(world([folder, page]), page.nodeId).stretchRemovals.userIds.has(bob.id)).toBe(true);
    // but not naming a folder head that contradicts the one this client has
    const fork = page.without(1);
    fork.add(eve, childState(folder.nodeId, { shares: [], version: 3, keyCommit: commit(3) }), [
      { log: folder.nodeId, seq: 1, head: commit(8) },
    ]);
    expect(st(world([folder, fork]), page.nodeId).stretchRemovals.userIds.has(bob.id)).toBe(false);
  });

  it("an editor's absurd version in the stretch doesn't block the owner's checkpoint", () => {
    const two = [share(alice, "owner"), share(bob, "editor")];
    const log = Log.create(alice, rootState({ shares: two }));
    log.add(alice, rekey({ shares: two }, 2), [hidden()]);
    // bob, an editor, re-keys far ahead of what honest re-keys could have reached by now
    log.add(bob, rekey({ shares: two }, Number.MAX_SAFE_INTEGER));
    log.add(bob, rekey({ shares: two }, 50));
    const ns = fold(log);
    expect(ns.stretchVersion).toBe(2);
    const pre = checkpointPrefill(ns);
    log.checkpoint(alice, { ...pre, version: pre.version + 1, keyCommit: commit(3) });
    expect(fold(log).status).toEqual(verified);
    expect(fold(log).state.version).toBe(3);
  });

  it("an editor's dep on a seq nobody has doesn't block the owner's checkpoint", () => {
    const folder = Log.create(alice, rootState({ shares: folderShares }));
    const page = Log.create(bob, childState(folder.nodeId), [folder.dep()]);
    page.add(bob, childState(folder.nodeId, { version: 2, keyCommit: commit(2) }), [folder.dep(), hidden()]);
    page.add(bob, childState(folder.nodeId, { version: 3, keyCommit: commit(3) }), [
      { log: folder.nodeId, seq: 999, head: commit(7) },
    ]);
    // nor a hidden log, nor a head that contradicts the one this client has
    page.add(bob, childState(folder.nodeId, { version: 4, keyCommit: commit(4) }), [
      hidden(),
      { log: folder.nodeId, seq: 0, head: commit(8) },
    ]);
    expect(st(world([folder, page]), page.nodeId).status).toMatchObject(unverifiedAt(1));
    page.checkpoint(alice, childState(folder.nodeId, { version: 5, keyCommit: commit(5) }), [folder.dep()]);
    const ns = st(world([folder, page]), page.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.deps.get(folder.nodeId)?.seq).toBe(0);
  });

  it("an honest editor re-key in the stretch raises the floor by one each time", () => {
    const two = [share(alice, "owner"), share(bob, "editor")];
    const log = Log.create(alice, rootState({ shares: two }));
    log.add(alice, rekey({ shares: two }, 2), [hidden()]);
    log.add(bob, rekey({ shares: two }, 3));
    expect(fold(log).stretchVersion).toBe(3);
    log.add(bob, rekey({ shares: two }, 4));
    const ns = fold(log);
    expect(ns.stretchVersion).toBe(4);
    // the checkpoint is seq 4: at the floor, or past floor + seq, it's skipped
    for (const v of [4, 9]) {
      const off = log.without(0).checkpoint(alice, rekey({ shares: two }, v));
      expect(fold(off).status, `version ${v}`).toMatchObject(unverifiedAt(1));
    }
    log.checkpoint(alice, rekey({ shares: two }, 5));
    expect(fold(log).status).toEqual(verified);
    expect(fold(log).state.version).toBe(5);
  });

  it("N3: clients that do and don't resolve a stretch author reach the same verdict on a checkpoint", () => {
    const two = [share(alice, "owner"), share(dan, "editor")];
    const danUnknown = (id: string, pub: string) => (id === dan.id ? "unknown" : known(id, pub));
    const log = Log.create(alice, rootState({ shares: two }));
    log.add(alice, rekey({ shares: two }, 2), [hidden()]);
    // dan, an editor, re-keys honestly in the stretch
    log.add(dan, rekey({ shares: two }, 3));
    const A = fold(log); // resolves dan
    const B = fold(log, { identity: danUnknown }); // doesn't
    expect(A.stretchVersion).toBe(3);
    expect(B.stretchVersion).toBe(3);
    // alice repairs from either kind of device; both kinds accept it
    for (const from of [A, B]) {
      const pre = checkpointPrefill(from);
      const fixed = log.without(0).checkpoint(alice, { ...pre, version: pre.version + 1, keyCommit: commit(10) });
      for (const identity of [known, danUnknown]) {
        const ns = fold(fixed, { identity });
        expect(ns.status).toEqual(verified);
        expect(ns.state.version).toBe(4);
        expect(ns.state.keyCommit).toBe(commit(10));
      }
    }
  });

  it("N3b: a plain re-key one client applies and another can't check never gets a second commit", () => {
    const two = [share(alice, "owner"), share(dan, "editor")];
    const danUnknown = (id: string, pub: string) => (id === dan.id ? "unknown" : known(id, pub));
    const log = Log.create(alice, rootState({ shares: two }));
    // dan's honest re-key: checkable for A, the start of a stretch for B
    log.add(dan, rekey({ shares: two }, 2));
    const A = fold(log);
    const B = fold(log, { identity: danUnknown });
    expect(A.status).toEqual(verified);
    expect(A.state.version).toBe(2);
    expect(B.status).toMatchObject(unverifiedAt(1, "identity"));
    expect(B.stretchVersion).toBe(2);
    const pre = checkpointPrefill(B);
    log.checkpoint(alice, { ...pre, version: pre.version + 1, keyCommit: commit(10) });
    for (const identity of [known, danUnknown]) {
      const ns = fold(log, { identity });
      expect(ns.status).toEqual(verified);
      expect(ns.state.version).toBe(3);
      expect(ns.state.keyCommit).toBe(commit(10));
    }
  });
});
