/**
 * The whole library against the world of `packages/api-client/test/key-path-rewire.test.ts` (MC-2) and the attacks
 * the design reviews found, plus the honest flows a client runs every day. Honest logs are written the way a client
 * writes them (`createFirstSnapshot` with `authorityDeps`, then `nextSnapshot`); only the attacker's snapshots and
 * the server's tampering are made by hand.
 */
import { toBase64Url } from "@jelly/crypto";
import { describe, expect, it } from "vitest";
import {
  acceptChildLink,
  acceptGrant,
  applyIntent,
  authorityDeps,
  type Change,
  type ChildLink,
  canCheckpoint,
  checkpointPrefill,
  createAccount,
  createFirstSnapshot,
  createGrant,
  createSnapshot,
  type Dep,
  type Grant,
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
  type UnlockedAccount,
  unlockAccount,
  type WorldInput,
  writable,
} from "../../src/index.ts";

function user(handle: string, id = crypto.randomUUID()) {
  const acct = createAccount();
  const account = unlockAccount({ userId: id, handle, ak: acct.ak, bundle: acct.bundle });
  const { signPub, encPub, encPubSig } = acct.bundle;
  const identity: PublicIdentity = { userId: id, handle, signPub, encPub, encPubSig };
  return { id, account, signPub, identity };
}
type U = ReturnType<typeof user>;
type Signer = { account: UnlockedAccount };

const alice = user("alice");
const bob = user("bob");
const carol = user("carol");
const dan = user("dan");
/** The server's own account: it has an identity record like anyone, and nothing else. */
const eve = user("eve");
const everyone = [alice, bob, carol, dan, eve];

const at = "2026-10-31T10:00:00.000Z";
const share = (u: U, role: Role, signPub = u.signPub) => ({ userId: u.id, role, signPub });
type Resolve = WorldInput["identity"];
const known: Resolve = (userId, signPub) => {
  const u = everyone.find((x) => x.id === userId);
  return !u ? "unknown" : u.signPub === signPub ? "ok" : "mismatch";
};

/** A node key, and the commit a state carries for it (§3.4: a v8 node's version 1 commits with an empty id). */
const key = (n: number) => new Uint8Array(32).fill(n);
const commitFor = (nodeId: string, version: number, k: Uint8Array) =>
  keyCommit(version === 1 ? "" : nodeId, version, k);
const firstCommit = (n: number) => keyCommit("", 1, key(n));
const rekeyTo = (nodeId: string, version: number, n: number, skipped?: string[]) => ({
  version,
  keyCommit: commitFor(nodeId, version, key(n)),
  ...(skipped ? { skipped } : {}),
});

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
const gdep = (g: Group, v = g.versions.length - 1): Dep => ({ log: `group:${g.id}`, seq: v, head: groupHead(g, v) });
function view(gs: Group[], teams: Record<string, { everyone: Group; admins: Group }> = {}): GroupView {
  const find = (id: string) => gs.find((g) => g.id === id);
  return {
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

/** A personal root: its anchor is owner, with the matching share, keyed with `key(n)`. */
const rootState = (owner: U, n: number, over: Partial<State> = {}): State => ({
  kind: "folder",
  parentId: null,
  anchor: { user: owner.id, signPub: owner.signPub },
  restricted: false,
  version: 1,
  keyCommit: firstCommit(n),
  shares: [share(owner, "owner")],
  groupShares: [],
  links: [],
  ...over,
});

/** A new node's state under `parentId`, keyed with `key(n)`. */
const childState = (parentId: string, n: number, over: Partial<State> = {}): State => ({
  kind: "page",
  parentId,
  anchor: null,
  restricted: false,
  version: 1,
  keyCommit: firstCommit(n),
  shares: [],
  groupShares: [],
  links: [],
  ...over,
});

/** A node's log as the test holds it: each append chains onto whatever came last, applied or not. */
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
  state(): State {
    return this.last().state;
  }
  head(): string {
    return snapshotHash(this.last());
  }
  dep(seq = this.last().seq): Dep {
    return { log: this.nodeId, seq, head: snapshotHash(this.entries[seq] as Snapshot) };
  }
  /** A hand-signed entry: the attacker's, or a writer the library doesn't have an intent for. */
  add(by: Signer, state: State, deps: Dep[] = [], change: Change = "change", supersedes: string | null = null): this {
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
  push(e: LogEntry): this {
    this.entries.push(e);
    return this;
  }
  /** A copy to tamper with, leaving the honest log as it is. */
  clone(): Log {
    const l = new Log(this.nodeId);
    l.entries = [...this.entries];
    return l;
  }
  /** The log as the server might show it: only its first `n` entries. */
  upTo(n: number): Log {
    const l = new Log(this.nodeId);
    l.entries = this.entries.slice(0, n);
    return l;
  }
}

function world(logs: Log[], over: Partial<WorldInput> = {}): LogWorld {
  return new LogWorld({
    logs: new Map(logs.map((l) => [l.nodeId, l.entries])),
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
const unverified = (atSeq: number, reason: string) => ({ kind: "unverified", atSeq, reason });
const shareIds = (ns: NodeState) => ns.state.shares.map((s) => s.userId).sort();
const ids = (...us: U[]) => us.map((u) => u.id).sort();
const people = (w: LogWorld, ns: NodeState) =>
  reissueSet(w, ns)
    .people.map((s) => s.userId)
    .sort();
/** A dep on a log the server never shows: the check the snapshot relied on is hidden (§8.1). */
const hidden = (): Dep => ({ log: crypto.randomUUID(), seq: 1, head: firstCommit(99) });

/** A child created as a client creates it: naming its parent and everything the parent's authority rests on. */
function create(by: U, w: LogWorld, parent: Log, state: State): Log {
  return Log.create(by, { ...state, parentId: parent.nodeId }, [parent.dep(), ...authorityDeps(w, parent.nodeId)]);
}

/** Applies the intent as `by` and appends the result, or throws with the refusal. */
function write(by: U, w: LogWorld, log: Log, intent: Intent, when = at): Snapshot {
  const s = nextSnapshot(by.account, w, st(w, log.nodeId), intent, when);
  if ("error" in s) throw new Error(s.error);
  log.push(s);
  return s;
}
/** The refusal `nextSnapshot` gives, or throws if it signed. */
function refused(by: U, w: LogWorld, log: Log, intent: Intent): string {
  const s = nextSnapshot(by.account, w, st(w, log.nodeId), intent, at);
  if (!("error" in s)) throw new Error("signed what should have been refused");
  return s.error;
}

const grant = (by: U, to: U, nodeId: string, keyVersion: number, nodeKey: Uint8Array, role: Role = "viewer"): Grant =>
  createGrant(by.account, { nodeId, keyVersion, nodeKey, grantee: to.identity, role });
const link = (child: Log, parent: Log, childVersion = 1): ChildLink => ({
  childId: child.nodeId,
  childVersion,
  parentId: parent.nodeId,
  parentVersion: 1,
  wrapped: "x",
});

/** Keys by node: alice's root 1, Projects 2, Plans 3, carol's root 4, M 5; re-keys count up from 20. */
const K = { R: 1, projects: 2, plans: 3, CR: 4, M: 5, BR: 6, page: 7 };

/**
 * The MC-2 world (`key-path-rewire.test.ts` `world({rewire:true})`), as logs a client would write: alice's root >
 * Projects > Plans; bob editor on Projects; carol viewer on Plans; carol's root > M, shared with bob as viewer.
 * `w()` folds whatever the logs hold now; `shown(...)` folds the logs as a lying server shows them.
 */
function mc2() {
  const R = Log.create(alice, rootState(alice, K.R));
  const logs: Log[] = [R];
  const w = (over: Partial<WorldInput> = {}) => world(logs, over);
  const projects = create(alice, w(), R, childState("", K.projects, { kind: "folder" }));
  logs.push(projects);
  const plans = create(alice, w(), projects, childState("", K.plans, { kind: "folder" }));
  logs.push(plans);
  write(alice, w(), projects, { add: share(bob, "editor") });
  write(alice, w(), plans, { add: share(carol, "viewer") });
  const CR = Log.create(carol, rootState(carol, K.CR));
  logs.push(CR);
  const M = create(carol, w(), CR, childState("", K.M, { kind: "folder" }));
  logs.push(M);
  write(carol, w(), M, { add: share(bob, "viewer") });
  /** The honest logs with some replaced by what the server shows instead (a log left out is withheld). */
  const shown = (replace: Log[], over: Partial<WorldInput> = {}, withhold: Log[] = []) =>
    world(
      logs
        .filter((l) => !withhold.some((x) => x.nodeId === l.nodeId))
        .map((l) => replace.find((x) => x.nodeId === l.nodeId) ?? l),
      over,
    );
  /** Plans' state as carol would like it: under her M. */
  const underM = (): State => ({ ...plans.state(), parentId: M.nodeId });
  return { R, projects, plans, CR, M, logs, w, shown, underM };
}

/** What a device verified of each log: its floors (§5.4). */
const floorsOf = (w: LogWorld, ...logs: Log[]) =>
  new Map(logs.map((l) => [l.nodeId, { seq: st(w, l.nodeId).seq, head: st(w, l.nodeId).head }]));

describe("MC-2: the world of key-path-rewire.test.ts as logs", () => {
  it("the honest world folds as the people in it expect", () => {
    const { R, projects, plans, CR, M, w } = mc2();
    const W = w();
    for (const l of [R, projects, plans, CR, M]) expect(st(W, l.nodeId).status).toEqual(verified);
    expect(W.role(alice.id, plans.nodeId)).toBe("owner");
    expect(W.role(bob.id, plans.nodeId)).toBe("editor");
    expect(W.role(carol.id, plans.nodeId)).toBe("viewer");
    expect(W.role(eve.id, plans.nodeId)).toBeNull();
    expect(W.role(bob.id, M.nodeId)).toBe("viewer");
    expect(W.role(carol.id, M.nodeId)).toBe("owner");
    expect(st(W, plans.nodeId).state.parentId).toBe(projects.nodeId);
    // the key reaches bob through the folder he edits, and carol through her grant
    expect(acceptChildLink(W, st(W, plans.nodeId), st(W, projects.nodeId), link(plans, projects), key(K.plans))).toBe(
      true,
    );
    expect(acceptGrant(W, st(W, plans.nodeId), grant(alice, carol, plans.nodeId, 1, key(K.plans)), key(K.plans))).toBe(
      true,
    );
    expect(people(W, st(W, plans.nodeId))).toEqual(ids(carol));
  });

  it("MC-2: Plans shown under carol's folder is not believed", () => {
    const { R, projects, plans, CR, M, w, shown, underM } = mc2();
    const honest = w();
    const under = link(plans, M);
    // carol's deps, as a mover would name them: everything about M, and about Plans' real place
    const full = [M.dep(), CR.dep(), projects.dep(), R.dep()];
    for (const deps of [full, [M.dep(), CR.dep()], [], [hidden()], [M.dep(), CR.dep(), hidden()]]) {
      const lie = plans.clone().add(carol, underM(), deps);
      const W = shown([lie]);
      const ns = st(W, plans.nodeId);
      // a viewer can't move anything: her snapshot is skipped and Plans stays where alice put it
      expect(ns.status).toEqual(verified);
      expect(ns.seq).toBe(lie.last().seq);
      expect(ns.state.parentId).toBe(projects.nodeId);
      expect(acceptChildLink(W, ns, st(W, M.nodeId), under, key(K.plans))).toBe(false);
      expect(acceptChildLink(W, ns, st(W, projects.nodeId), link(plans, projects), key(K.plans))).toBe(true);
      expect(W.role(carol.id, plans.nodeId)).toBe("viewer");
    }

    // her statements: eve let in, and herself raised. A viewer adds nobody and changes no role
    const statements = plans
      .clone()
      .add(carol, { ...plans.state(), shares: [...plans.state().shares, share(eve, "viewer")] }, full)
      .add(carol, { ...plans.state(), shares: [share(carol, "owner")] }, full)
      .add(carol, { ...plans.state(), version: 2, keyCommit: commitFor(plans.nodeId, 2, key(21)) }, full);
    let W = shown([statements]);
    let ns = st(W, plans.nodeId);
    expect(ns.status).toEqual(verified);
    expect(shareIds(ns)).toEqual(ids(carol));
    expect(ns.state.version).toBe(1);
    expect(people(W, ns)).not.toContain(eve.id);
    expect(W.role(eve.id, plans.nodeId)).toBeNull();
    // bob's re-key, built from what the fold believes, goes under Projects and seals to no one new
    const rekey = nextSnapshot(bob.account, W, ns, { rekey: rekeyTo(plans.nodeId, 2, 22) }, at);
    if ("error" in rekey) throw new Error(rekey.error);
    expect(rekey.state.parentId).toBe(projects.nodeId);
    expect(rekey.state.shares.map((s) => s.userId)).toEqual([carol.id]);

    // the real route withheld: Plans' origin named Projects, so nothing of it can be checked; it is read-only and
    // re-issues nothing
    W = shown([], {}, [projects]);
    ns = st(W, plans.nodeId);
    expect(ns.status).toEqual(unverified(0, "stale-dependency"));
    expect(writable(ns)).toBe("unverified");
    expect(acceptChildLink(W, ns, st(W, M.nodeId), under, key(K.plans))).toBe(false);
    expect(reissueSet(W, ns)).toEqual({ people: [], groups: [], links: [] });
    expect(nextSnapshot(bob.account, W, ns, { rekey: rekeyTo(plans.nodeId, 2, 22) }, at)).toMatchObject({
      error: expect.stringContaining("unverified"),
    });
    // nothing was checked, so not even the held key opens it this way (a key with no checked commit is no proof)
    expect(readOnlyKey(ns, key(K.plans))).toBe(false);
    expect(acceptGrant(W, ns, grant(alice, carol, plans.nodeId, 1, key(K.plans)), key(K.plans))).toBe(false);
    // Projects shown, but only as it was before Plans' later snapshots named it: Plans is checkable up to there
    W = shown([projects.upTo(1)]);
    ns = st(W, plans.nodeId);
    expect(ns.status).toEqual(unverified(1, "stale-dependency"));
    expect(ns.state.parentId).toBe(projects.nodeId);
    expect(writable(ns)).toBe("unverified");
    expect(readOnlyKey(ns, key(K.plans))).toBe(true);
    expect(acceptChildLink(W, ns, st(W, M.nodeId), under, key(K.plans))).toBe(false);

    // the real log withheld, a forged one in its place: Plans' id doesn't derive from carol's origin
    const forged = createFirstSnapshot(carol.account, {
      state: childState(M.nodeId, K.plans, { kind: "folder", shares: [share(eve, "viewer")] }),
      deps: [M.dep(), CR.dep()],
      at,
    });
    const fake = new Log(plans.nodeId).push(createSnapshot(carol.account, { ...forged, nodeId: plans.nodeId }));
    W = shown([fake]);
    ns = st(W, plans.nodeId);
    expect(ns.status).toEqual(unverified(0, "id"));
    expect(ns.state.shares).toEqual([]);
    expect(W.role(eve.id, plans.nodeId)).toBeNull();
    expect(W.role(carol.id, plans.nodeId)).toBeNull();
    expect(acceptChildLink(W, ns, st(W, M.nodeId), under, key(K.plans))).toBe(false);
    expect(readOnlyKey(ns, key(K.plans))).toBe(false);
    // a honest device holding Plans (floors) refuses the forgery outright
    const held = shown([fake], { floors: floorsOf(honest, plans) });
    expect(st(held, plans.nodeId).status).toEqual({ kind: "rolled-back", log: plans.nodeId });
  });

  it("MC-2, the device that held Plans", () => {
    const { projects, plans, M, w, shown, underM } = mc2();
    const honest = w();
    const floors = floorsOf(honest, plans, projects);
    // the honest log with carol's move appended extends the floor: carol's entry is skipped, Plans stays put
    const longer = plans.clone().add(carol, underM(), [M.dep()]);
    let ns = st(shown([longer], { floors }), plans.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.parentId).toBe(projects.nodeId);
    // a fork at the seq the device verified: rolled back, and nothing applies to it, a checkpoint included
    const fork = plans.upTo(1).add(carol, underM(), [M.dep()]);
    let W = shown([fork], { floors });
    ns = st(W, plans.nodeId);
    expect(ns.status).toEqual({ kind: "rolled-back", log: plans.nodeId });
    expect(writable(ns)).toBe("rolled-back");
    expect(reissueSet(W, ns)).toEqual({ people: [], groups: [], links: [] });
    expect(applyIntent(W, ns, { rekey: rekeyTo(plans.nodeId, 2, 22) }, share(bob, "editor"))).toMatchObject({
      error: "not-applicable",
      why: expect.stringContaining("rolled back"),
    });
    expect(
      applyIntent(
        W,
        ns,
        { checkpoint: { state: checkpointPrefill(ns), rekey: rekeyTo(plans.nodeId, 2, 22) } },
        share(alice, "owner"),
      ),
    ).toMatchObject({ error: "not-applicable" });
    // a shorter log too (the server rolled Plans back to before carol was shared with)
    expect(st(shown([plans.upTo(1)], { floors }), plans.nodeId).status).toEqual({
      kind: "rolled-back",
      log: plans.nodeId,
    });
    // the route withheld: Plans' origin named Projects, so nothing of Plans checks out
    W = shown([], { floors }, [projects]);
    expect(st(W, plans.nodeId).status).toEqual(unverified(0, "stale-dependency"));
    // Projects rolled back to before bob was added: Plans, which named Projects with him, can't be verified either
    W = shown([projects.upTo(1)], { floors });
    expect(st(W, projects.nodeId).status).toEqual({ kind: "rolled-back", log: projects.nodeId });
    expect(st(W, plans.nodeId).status).toEqual(unverified(1, "stale-dependency"));
    expect(W.role(bob.id, plans.nodeId)).toBeNull();
    expect(reissueSet(W, st(W, plans.nodeId))).toEqual({ people: [], groups: [], links: [] });
  });
});

describe("round 1 review: stale ancestor, move takeover, un-revoked link, crossing moves", () => {
  it("a stale ancestor log is refused: Plans named Projects with bob in it, the server shows Projects without him", () => {
    const { projects, plans, R, w, shown } = mc2();
    const s = write(bob, w(), plans, { rekey: rekeyTo(plans.nodeId, 2, 22) });
    expect(s.deps).toEqual(expect.arrayContaining([projects.dep(), R.dep()]));
    expect(st(w(), plans.nodeId).state.version).toBe(2);
    // Projects shown at seq 0 only: the deps on Projects with bob in it can't be checked, and Plans is not verified
    // past the first snapshot that named it (alice's share with carol, seq 1), let alone bob's re-key
    let W = shown([projects.upTo(1)]);
    let ns = st(W, plans.nodeId);
    expect(ns.status).toEqual(unverified(1, "stale-dependency"));
    expect(ns.state.version).toBe(1);
    expect(shareIds(ns)).toEqual([]);
    expect(writable(ns)).toBe("unverified");
    expect(readOnlyKey(ns, key(22))).toBe(false);
    // a device that verified Projects with bob also sees Projects itself rolled back
    W = shown([projects.upTo(1)], { floors: floorsOf(w(), projects) });
    expect(st(W, projects.nodeId).status).toEqual({ kind: "rolled-back", log: projects.nodeId });
    // and alice's later removal of bob from Projects can't be undone by showing Projects as it was before
    write(alice, w(), projects, { remove: bob.id, rekey: rekeyTo(projects.nodeId, 2, 23) });
    const after = w();
    expect(after.role(bob.id, plans.nodeId)).toBeNull();
    expect(st(after, plans.nodeId).stale).toBe(true);
    W = shown([projects.upTo(2)], { floors: floorsOf(after, projects, plans) });
    expect(st(W, projects.nodeId).status).toEqual({ kind: "rolled-back", log: projects.nodeId });
    expect(st(W, plans.nodeId).status).toEqual(unverified(s.seq, "needs-parent"));
    ns = st(W, plans.nodeId);
    expect(reissueSet(W, ns)).toEqual({ people: [], groups: [], links: [] });
  });

  it("move takeover: an editor can't move Plans under his own root, nor make himself its owner", () => {
    const { projects, plans, R, logs, w } = mc2();
    const BR = Log.create(bob, rootState(bob, K.BR));
    logs.push(BR);
    const W = w();
    // the client refuses before signing
    expect(refused(bob, W, plans, { move: BR.nodeId })).toContain("another root");
    // signed by hand, the fold skips it (no cycle, same root, §5.3) and Plans stays alice's
    const taken = plans
      .clone()
      .add(bob, { ...plans.state(), parentId: BR.nodeId }, [BR.dep(), projects.dep(), R.dep()]);
    const shown = world([R, projects, taken, BR]);
    const ns = st(shown, plans.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.parentId).toBe(projects.nodeId);
    expect(shown.role(bob.id, plans.nodeId)).toBe("editor");
    expect(shown.role(alice.id, plans.nodeId)).toBe("owner");
    // an owner share for himself needs owner; so does unrestricting into his root later
    const owned = plans
      .clone()
      .add(bob, { ...plans.state(), shares: [...plans.state().shares, share(bob, "owner")] }, [
        projects.dep(),
        R.dep(),
      ]);
    expect(shareIds(st(world([R, projects, owned]), plans.nodeId))).toEqual(ids(carol));
    expect(refused(bob, W, plans, { add: share(bob, "owner") })).toContain("skip");
  });

  it("an un-revoked share link opens nothing: the removal and its re-key are one fact", () => {
    const { plans, w, shown } = mc2();
    const L = crypto.randomUUID();
    write(alice, w(), plans, { addLink: { linkId: L, role: "viewer" } });
    let ns = st(w(), plans.nodeId);
    expect(ns.state.links).toEqual([{ linkId: L, role: "viewer" }]);
    expect(reissueSet(w(), ns).links).toEqual([{ linkId: L, role: "viewer" }]);
    const removal = write(alice, w(), plans, { removeLink: { linkId: L, rekey: rekeyTo(plans.nodeId, 2, 24) } });
    ns = st(w(), plans.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.version).toBe(2);
    // the server still lists the link row: the fold's state has no such link
    expect(ns.state.links).toEqual([]);
    expect(reissueSet(w(), ns).links).toEqual([]);
    // the server withholds the removal from a fresh device: it sees version 1, and the new key fits no commit it has
    const stale = shown([plans.upTo(removal.seq)]);
    const old = st(stale, plans.nodeId);
    expect(old.state.version).toBe(1);
    expect(old.state.links).toEqual([{ linkId: L, role: "viewer" }]);
    expect(readOnlyKey(old, key(24))).toBe(false);
    // a device that saw the removal refuses the shorter log
    expect(st(shown([plans.upTo(removal.seq)], { floors: floorsOf(w(), plans) }), plans.nodeId).status).toEqual({
      kind: "rolled-back",
      log: plans.nodeId,
    });
  });

  it("crossing moves don't loop, and neither node is lost", () => {
    const { projects, logs, w } = mc2();
    const A = create(alice, w(), projects, childState("", 30, { kind: "folder" }));
    const B = create(alice, w(), projects, childState("", 31, { kind: "folder" }));
    logs.push(A, B);
    const W = w();
    // from the same heads, bob moves A into B and alice moves B into A; each alone would be fine
    const aIntoB = nextSnapshot(bob.account, W, st(W, A.nodeId), { move: B.nodeId }, at);
    const bIntoA = nextSnapshot(alice.account, W, st(W, B.nodeId), { move: A.nodeId }, at);
    if ("error" in aIntoB || "error" in bIntoA) throw new Error("refused");
    A.push(aIntoB);
    B.push(bIntoA);
    for (const order of [
      [A, B],
      [B, A],
    ]) {
      const after = w();
      for (const l of order) {
        const ns = st(after, l.nodeId);
        expect(ns.status).toEqual(verified);
        expect(ns.state.parentId).toBe(projects.nodeId);
        expect(ns.seq).toBe(1);
      }
    }
    // the client's own loop rule now refuses both directions, and says so
    expect(refused(bob, w(), A, { move: B.nodeId })).toContain("loop");
    expect(refused(alice, w(), B, { move: A.nodeId })).toContain("loop");
    // everything else goes on: alice shares A, bob renames nothing but re-keys it
    write(alice, w(), A, { add: share(dan, "viewer") });
    write(bob, w(), A, { rekey: rekeyTo(A.nodeId, 2, 32) });
    expect(st(w(), A.nodeId)).toMatchObject({ status: verified, stale: false, state: { version: 2 } });
  });
});

describe("round 2 review: hidden removals, unverified nodes, uncommitted keys, alias keys, deleted accounts", () => {
  /** Plans with dan as a second owner, then alice's removal of him whose check the server hides. */
  function hiddenRemoval() {
    const m = mc2();
    const { plans, w } = m;
    write(alice, w(), plans, { add: share(dan, "owner") });
    expect(w().role(dan.id, plans.nodeId)).toBe("owner");
    const before = w();
    plans.add(
      alice,
      {
        ...plans.state(),
        shares: [share(carol, "viewer")],
        version: 2,
        keyCommit: commitFor(plans.nodeId, 2, key(40)),
      },
      [...authorityDeps(before, plans.nodeId), hidden()],
    );
    return m;
  }

  it("a removal hidden by the server can't be checkpointed away by the one removed; the owner's checkpoint resumes", () => {
    const { plans, w, shown } = hiddenRemoval();
    let W = w();
    let ns = st(W, plans.nodeId);
    expect(ns.status).toEqual(unverified(plans.last().seq, "stale-dependency"));
    // the removal is applied conservatively and remembered
    expect(shareIds(ns)).toEqual(ids(carol));
    expect([...ns.stretchRemovals.userIds]).toEqual([dan.id]);
    expect(ns.stretchVersion).toBe(2);
    expect(canCheckpoint(W, ns, dan.id)).toBe(false);
    expect(canCheckpoint(W, ns, alice.id)).toBe(true);
    expect(canCheckpoint(W, ns, bob.id)).toBe(false);
    // dan's checkpoint putting himself back: skipped, the node stays unverified
    const back = plans.clone().add(
      dan,
      {
        ...plans.state(),
        shares: [share(carol, "viewer"), share(dan, "owner")],
        version: 3,
        keyCommit: commitFor(plans.nodeId, 3, key(41)),
      },
      authorityDeps(W, plans.nodeId),
      "checkpoint",
      plans.head(),
    );
    const danW = shown([back]);
    const afterDan = st(danW, plans.nodeId);
    expect(afterDan.status.kind).toBe("unverified");
    expect(shareIds(afterDan)).toEqual(ids(carol));
    expect(danW.role(dan.id, plans.nodeId)).toBeNull();
    // the client refuses to sign it for dan too
    expect(
      nextSnapshot(
        dan.account,
        W,
        ns,
        {
          checkpoint: {
            state: { ...checkpointPrefill(ns), shares: [share(carol, "viewer"), share(dan, "owner")] },
            rekey: rekeyTo(plans.nodeId, 3, 41),
          },
        },
        at,
      ),
    ).toMatchObject({ error: expect.stringContaining("removed") });
    // alice's checkpoint from the pre-fill: verified, dan gone, a fresh key
    const cp = write(alice, W, plans, {
      checkpoint: { state: checkpointPrefill(ns), rekey: rekeyTo(plans.nodeId, ns.stretchVersion + 1, 42) },
    });
    expect(cp.change).toBe("checkpoint");
    W = w();
    ns = st(W, plans.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.version).toBe(3);
    expect(shareIds(ns)).toEqual(ids(carol));
    expect(W.role(dan.id, plans.nodeId)).toBeNull();
    expect(people(W, ns)).toEqual(ids(carol));
    expect(acceptGrant(W, ns, grant(alice, carol, plans.nodeId, 3, key(42)), key(42))).toBe(true);
    // honest work resumes: bob adds dan back as a viewer, and that is a normal snapshot after the checkpoint
    write(bob, w(), plans, { add: share(dan, "viewer") });
    expect(w().role(dan.id, plans.nodeId)).toBe("viewer");
  });

  it("an unverified node is read-only: nothing is written, re-keyed, re-issued or opened by a stretch key", () => {
    const { plans, w } = hiddenRemoval();
    const W = w();
    const ns = st(W, plans.nodeId);
    expect(writable(ns)).toBe("unverified");
    for (const intent of [
      { add: share(eve, "viewer") },
      { rekey: rekeyTo(plans.nodeId, 2, 43) },
      { move: plans.state().parentId as string },
      { leave: true },
    ] as Intent[]) {
      expect(applyIntent(W, ns, intent, share(alice, "owner"))).toMatchObject({ error: "not-applicable" });
      expect(nextSnapshot(alice.account, W, ns, intent, at)).toMatchObject({
        error: expect.stringContaining("unverified"),
      });
    }
    expect(reissueSet(W, ns)).toEqual({ people: [], groups: [], links: [] });
    expect(acceptGrant(W, ns, grant(alice, carol, plans.nodeId, 1, key(K.plans)), key(K.plans))).toBe(false);
    expect(acceptGrant(W, ns, grant(alice, carol, plans.nodeId, 2, key(40)), key(40))).toBe(false);
    // the key of the last verified state opens the content; the stretch's re-key never does
    expect(readOnlyKey(ns, key(K.plans))).toBe(true);
    expect(readOnlyKey(ns, key(40))).toBe(false);
  });

  it("a substituted key fails the commit, and a version without a commit carries no writes", () => {
    const { plans, projects, w } = mc2();
    const W = w();
    const ns = st(W, plans.nodeId);
    // the server (or anyone) hands carol another key sealed as alice: it isn't the one the log commits to
    expect(acceptGrant(W, ns, grant(alice, carol, plans.nodeId, 1, key(66)), key(66))).toBe(false);
    expect(acceptChildLink(W, ns, st(W, projects.nodeId), link(plans, projects), key(66))).toBe(false);
    // a grant at another version than the state's isn't the current key
    expect(acceptGrant(W, ns, grant(alice, carol, plans.nodeId, 2, key(K.plans)), key(K.plans))).toBe(false);
    // an uncommitted version (legacy, §5.4): opens for reading by authority alone, but is stale for writing
    const uncommitted: NodeState = { ...ns, state: { ...ns.state, keyCommit: null } };
    expect(writable(uncommitted)).toBe("stale");
    expect(readOnlyKey(uncommitted, key(K.plans))).toBe(false);
    expect(applyIntent(W, uncommitted, { add: share(dan, "viewer") }, share(alice, "owner"))).toMatchObject({
      why: expect.stringContaining("re-key first"),
    });
    expect(applyIntent(W, uncommitted, { rekey: rekeyTo(plans.nodeId, 2, 44) }, share(alice, "owner"))).toMatchObject({
      version: 2,
    });
  });

  it("an alias key acts as nobody: a snapshot signed with carol's key in alice's name isn't alice's", () => {
    const { plans, R, projects, shown } = mc2();
    const asAlice: Signer = { account: { ...carol.account, userId: alice.id } };
    const deps = [projects.dep(), R.dep()];
    // what alice could never do is skipped, whoever signed it
    const impossible = plans
      .clone()
      .add(asAlice, { ...plans.state(), version: 5, keyCommit: commitFor(plans.nodeId, 5, key(45)) }, deps);
    let ns = st(shown([impossible]), plans.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.version).toBe(1);
    // what alice could do doesn't resolve: not checkable, so nothing in it counts and eve stays out
    const plausible = plans
      .clone()
      .add(asAlice, { ...plans.state(), shares: [...plans.state().shares, share(eve, "editor")] }, deps);
    let W = shown([plausible]);
    ns = st(W, plans.nodeId);
    expect(ns.status).toEqual(unverified(plausible.last().seq, "identity"));
    expect(shareIds(ns)).toEqual(ids(carol));
    expect(W.role(eve.id, plans.nodeId)).toBeNull();
    expect(reissueSet(W, ns)).toEqual({ people: [], groups: [], links: [] });
    // the owner clears it with a checkpoint that confirms nobody new
    write(alice, W, plausible, {
      checkpoint: { state: checkpointPrefill(ns), rekey: rekeyTo(plans.nodeId, ns.stretchVersion + 1, 46) },
    });
    W = shown([plausible]);
    ns = st(W, plans.nodeId);
    expect(ns.status).toEqual(verified);
    expect(shareIds(ns)).toEqual(ids(carol));

    // a share's key hint is never a trust input: bob writes eve's key as carol's, and eve still can't act as carol
    const { plans: p2, projects: pr2, R: r2, w: w2 } = mc2();
    p2.add(bob, { ...p2.state(), shares: [share(carol, "viewer", eve.signPub)] }, [pr2.dep(), r2.dep()]);
    expect(st(w2(), p2.nodeId).status).toEqual(verified);
    const asCarol: Signer = { account: { ...eve.account, userId: carol.id } };
    // a viewer could at most leave: "carol" leaving under eve's key doesn't resolve, so carol stays
    p2.add(asCarol, { ...p2.state(), shares: [] }, [], "leave");
    ns = st(w2(), p2.nodeId);
    expect(ns.status).toEqual(unverified(p2.last().seq, "identity"));
    expect(shareIds(ns)).toEqual(ids(carol));
    // and anything beyond a leave is skipped as it would be for carol herself
    p2.entries.pop();
    p2.add(asCarol, { ...p2.state(), shares: [share(carol, "viewer", eve.signPub), share(eve, "owner")] }, [
      pr2.dep(),
      r2.dep(),
    ]);
    ns = st(w2(), p2.nodeId);
    expect(ns.status).toEqual(verified);
    expect(shareIds(ns)).toEqual(ids(carol));
  });

  it("no owner is removed on the server's word: a skipped owner stays owner", () => {
    const { plans, w } = mc2();
    write(alice, w(), plans, { add: share(dan, "owner") });
    // the server reports dan deleted; bob's re-key leaves him out of the seals but not out of the state
    const s = write(bob, w(), plans, { rekey: rekeyTo(plans.nodeId, 2, 47, [dan.id]) });
    expect(s.skipped).toEqual([dan.id]);
    const W = w();
    const ns = st(W, plans.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.stale).toBe(false);
    expect(shareIds(ns)).toEqual(ids(carol, dan));
    expect(W.role(dan.id, plans.nodeId)).toBe("owner");
    expect(people(W, ns)).toEqual(ids(carol, dan));
    // bob can't remove him either way: the client refuses, and a hand-signed removal is skipped
    expect(refused(bob, W, plans, { remove: dan.id, rekey: rekeyTo(plans.nodeId, 3, 48) })).toContain("skip");
    plans.add(
      bob,
      {
        ...plans.state(),
        shares: [share(carol, "viewer")],
        version: 3,
        keyCommit: commitFor(plans.nodeId, 3, key(48)),
      },
      authorityDeps(W, plans.nodeId),
    );
    expect(w().role(dan.id, plans.nodeId)).toBe("owner");
    expect(st(w(), plans.nodeId).state.version).toBe(2);
    // dan, back, still owns: his own removal of carol applies
    write(dan, w(), plans, { remove: carol.id, rekey: rekeyTo(plans.nodeId, 3, 49) });
    expect(shareIds(st(w(), plans.nodeId))).toEqual(ids(dan));
  });
});

/** A team: alice its only Admin; Everyone as given, version by version. */
function team(everyone: U[][] = [[alice, bob, carol]]) {
  const id = crypto.randomUUID();
  const admins = group([alice]);
  const all = group(...everyone);
  const gv = view([admins, all], { [id]: { everyone: all, admins } });
  const root = (): State => ({
    kind: "folder",
    parentId: null,
    anchor: { team: id },
    restricted: false,
    version: 1,
    keyCommit: firstCommit(50),
    shares: [],
    groupShares: [],
    links: [],
  });
  return { id, admins, all, gv, root };
}

describe("teams", () => {
  it("a teammate who leaves loses their share; a withheld membership proof voids nothing", () => {
    const t = team([
      [alice, bob, carol],
      [alice, bob],
    ]);
    // the world as it was when carol was still a member
    const all0: Group = { id: t.all.id, versions: [t.all.versions[0] as U[]] };
    const then = view([t.admins, all0], { [t.id]: { everyone: all0, admins: t.admins } });
    const TR = Log.create(alice, t.root(), [gdep(t.admins), gdep(t.all, 0)]);
    const logs = [TR];
    const w = (groups: GroupView) => world(logs, { groups });
    const page = create(bob, w(then), TR, childState("", 51));
    logs.push(page);
    expect(page.entries[0]?.deps.map((d) => d.log)).toEqual(
      expect.arrayContaining([TR.nodeId, `group:${t.admins.id}`, `group:${t.all.id}`]),
    );
    // alice shares the page with carol directly as well, and with gina, a guest
    const gina = user("gina");
    write(alice, w(then), page, { add: share(carol, "viewer") });
    let W = w(then);
    let ns = st(W, page.nodeId);
    expect(ns.status).toEqual(verified);
    expect(shareIds(ns)).toEqual(ids(carol));
    // while she's a teammate, Everyone makes her an editor anyway
    expect(W.role(carol.id, page.nodeId)).toBe("editor");
    expect(W.role(bob.id, page.nodeId)).toBe("editor");
    expect(W.role(alice.id, page.nodeId)).toBe("owner");
    expect(ns.stale).toBe(false);
    // carol leaves the team: her share is void, the page is stale, the re-issue set leaves her out
    W = w(t.gv);
    ns = st(W, page.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.stale).toBe(true);
    expect(shareIds(ns)).toEqual([]);
    expect(W.role(carol.id, page.nodeId)).toBeNull();
    expect(people(W, ns)).toEqual([]);
    expect(reissueSet(W, ns).groups).toEqual([]);
    // the server withholds the proof of her leaving: nothing is void, and nothing is stale
    const withheld = w(then);
    expect(st(withheld, page.nodeId).stale).toBe(false);
    expect(shareIds(st(withheld, page.nodeId))).toEqual(ids(carol));
    expect(withheld.role(carol.id, page.nodeId)).toBe("editor");
    // the next writer re-keys first (§5.2); the new state has no carol, and a guest would have stayed
    expect(refused(bob, W, page, { add: share(gina, "viewer") })).toContain("stale");
    write(bob, W, page, { rekey: rekeyTo(page.nodeId, 2, 52) });
    W = w(t.gv);
    ns = st(W, page.nodeId);
    expect(ns).toMatchObject({ status: verified, stale: false, state: { version: 2, shares: [] } });
    // carol's old grant on the team root, by an Everyone member, isn't a key to the new version
    expect(acceptGrant(W, ns, grant(bob, carol, page.nodeId, 2, key(52)), key(52))).toBe(false);
    // and a teammate who never left is unaffected
    write(bob, W, page, { add: share(gina, "viewer") });
    expect(shareIds(st(w(t.gv), page.nodeId))).toEqual(ids(gina));
  });
});

describe("honest flows", () => {
  it("create, share, move within the workspace and back", () => {
    const { projects, plans, logs, w } = mc2();
    // bob creates a page in Projects: it's alice's, and carol (viewer on Plans) has nothing on it
    const page = create(bob, w(), projects, childState("", K.page));
    logs.push(page);
    let W = w();
    expect(st(W, page.nodeId).status).toEqual(verified);
    expect(W.role(alice.id, page.nodeId)).toBe("owner");
    expect(W.role(bob.id, page.nodeId)).toBe("editor");
    expect(W.role(carol.id, page.nodeId)).toBeNull();
    expect(acceptChildLink(W, st(W, page.nodeId), st(W, projects.nodeId), link(page, projects), key(K.page))).toBe(
      true,
    );
    // bob moves it into Plans: carol can read it there, and the key now comes through Plans
    write(bob, W, page, { move: plans.nodeId });
    W = w();
    expect(st(W, page.nodeId)).toMatchObject({ status: verified, stale: false, state: { parentId: plans.nodeId } });
    expect(W.role(carol.id, page.nodeId)).toBe("viewer");
    expect(acceptChildLink(W, st(W, page.nodeId), st(W, plans.nodeId), link(page, plans), key(K.page))).toBe(true);
    expect(acceptChildLink(W, st(W, page.nodeId), st(W, projects.nodeId), link(page, projects), key(K.page))).toBe(
      false,
    );
    // and back; then alice shares it with dan directly
    write(bob, W, page, { move: projects.nodeId });
    W = w();
    expect(st(W, page.nodeId).state.parentId).toBe(projects.nodeId);
    expect(W.role(carol.id, page.nodeId)).toBeNull();
    write(alice, W, page, { add: share(dan, "editor") });
    W = w();
    expect(W.role(dan.id, page.nodeId)).toBe("editor");
    expect(people(W, st(W, page.nodeId))).toEqual(ids(dan));
    // dan edits the page, but a move needs editor on the destination too, and he has nothing on Plans
    expect(refused(dan, W, page, { move: plans.nodeId })).toContain("skip");
    write(dan, W, page, { add: share(eve, "viewer") });
    write(alice, w(), page, { role: { userId: dan.id, role: "viewer" } });
    W = w();
    expect(st(W, page.nodeId)).toMatchObject({ status: verified, state: { parentId: projects.nodeId } });
    expect(W.role(dan.id, page.nodeId)).toBe("viewer");
    expect(W.role(eve.id, page.nodeId)).toBe("viewer");
    expect(refused(dan, W, page, { add: share(carol, "viewer") })).toContain("skip");
  });

  it("leave: the key goes stale, the next writer re-keys, and the leaver's old grant still opens the old version", () => {
    const { plans, w } = mc2();
    write(alice, w(), plans, { add: share(dan, "editor") });
    const danGrant = grant(dan, carol, plans.nodeId, 1, key(K.plans));
    expect(acceptGrant(w(), st(w(), plans.nodeId), danGrant, key(K.plans))).toBe(true);
    const s = write(dan, w(), plans, { leave: true });
    expect(s.change).toBe("leave");
    let W = w();
    let ns = st(W, plans.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.stale).toBe(true);
    expect(W.role(dan.id, plans.nodeId)).toBeNull();
    expect(people(W, ns)).toEqual(ids(carol));
    // the key dan handed carol while he was an editor still fits this version
    expect(acceptGrant(W, ns, danGrant, key(K.plans))).toBe(true);
    // nothing but a re-key (or another leave) goes first
    expect(refused(bob, W, plans, { add: share(eve, "viewer") })).toContain("stale");
    write(bob, W, plans, { rekey: rekeyTo(plans.nodeId, 2, 53) });
    W = w();
    ns = st(W, plans.nodeId);
    expect(ns).toMatchObject({ status: verified, stale: false, state: { version: 2 } });
    expect(acceptGrant(W, ns, danGrant, key(K.plans))).toBe(false);
    expect(acceptGrant(W, ns, grant(bob, carol, plans.nodeId, 2, key(53)), key(53))).toBe(true);
  });

  it("a key change: earlier snapshots stay valid, new ones count once this account accepts the new key", () => {
    const { projects, w } = mc2();
    const bob2 = user("bob", bob.id);
    const bothKeys: Resolve = (id, pub) => (id === bob.id && pub === bob2.signPub ? "ok" : known(id, pub));
    // under his old key bob shared Projects with dan; under his new key he shares with eve
    write(bob, w(), projects, { add: share(dan, "viewer") });
    write(bob2, w({ identity: bothKeys }), projects, { add: share(eve, "viewer") });
    const W = w({ identity: bothKeys });
    const ns = st(W, projects.nodeId);
    expect(ns.status).toEqual(verified);
    expect(shareIds(ns)).toEqual(ids(bob, dan, eve));
    // a device that hasn't accepted the change yet keeps everything up to there, and nothing after
    const before = st(w(), projects.nodeId);
    expect(before.status).toEqual(unverified(projects.last().seq, "identity"));
    expect(shareIds(before)).toEqual(ids(bob, dan));
    // the client won't sign as bob2 on a device that doesn't resolve his key
    expect(
      nextSnapshot(bob2.account, w(), st(w(), projects.nodeId), { add: share(carol, "viewer") }, at),
    ).toMatchObject({
      error: expect.any(String),
    });
  });

  it("a legacy tree folds as verified from its leaves and the published root, and firms up at its first re-key", () => {
    const R = crypto.randomUUID();
    const projects = crypto.randomUUID();
    const plans = crypto.randomUUID();
    const leaf = (nodeId: string, state: State): LegacyLeaf => ({ nodeId, state });
    const leaves: LegacyLeaf[] = [
      leaf(R, rootState(alice, 0, { keyCommit: null })),
      leaf(projects, childState(R, 0, { kind: "folder", keyCommit: null, shares: [share(bob, "editor")] })),
      leaf(plans, childState(projects, 0, { kind: "folder", keyCommit: null, shares: [share(carol, "viewer")] })),
      leaf(crypto.randomUUID(), rootState(dan, 0, { keyCommit: null })),
    ];
    const legacyRoot = merkleRoot(leaves);
    const logOf = (l: LegacyLeaf) =>
      new Log(l.nodeId).push(legacySnapshot(l, merkleProof(leaves, l.nodeId) as string[]));
    const logs = leaves.slice(0, 3).map(logOf);
    const w = (over: Partial<WorldInput> = {}) => world(logs, { legacyRoot, ...over });
    let W = w();
    for (const id of [R, projects, plans]) expect(st(W, id).status).toEqual(verified);
    expect(W.role(alice.id, plans)).toBe("owner");
    expect(W.role(bob.id, plans)).toBe("editor");
    expect(W.role(carol.id, plans)).toBe("viewer");
    // a version with no commit opens by authority alone and is stale for writing (§5.4)
    const plansLog = logs[2] as Log;
    let ns = st(W, plans);
    expect(writable(ns)).toBe("stale");
    expect(acceptGrant(W, ns, grant(alice, carol, plans, 1, key(60)), key(60))).toBe(true);
    expect(readOnlyKey(ns, key(60))).toBe(false);
    expect(refused(bob, W, plansLog, { add: share(dan, "viewer") })).toContain("stale");
    // bob's first re-key gives it a commit; from then on a substituted key fails
    write(bob, W, plansLog, { rekey: rekeyTo(plans, 2, 61) });
    W = w();
    ns = st(W, plans);
    expect(ns).toMatchObject({ status: verified, stale: false, state: { version: 2 } });
    expect(ns.state.keyCommit).toBe(keyCommit(plans, 2, key(61)));
    expect(acceptGrant(W, ns, grant(alice, carol, plans, 2, key(61)), key(61))).toBe(true);
    expect(acceptGrant(W, ns, grant(alice, carol, plans, 2, key(60)), key(60))).toBe(false);
    write(bob, W, plansLog, { add: share(dan, "viewer") });
    expect(w().role(dan.id, plans)).toBe("viewer");

    // without the root nothing legacy is checkable; a leaf the server altered, or an "adoption" signed by a holder, neither
    expect(st(w({ legacyRoot: null }), plans).status).toMatchObject({ kind: "unverified", atSeq: 0 });
    const M = crypto.randomUUID();
    const altered = leaf(plans, { ...(leaves[2] as LegacyLeaf).state, parentId: M });
    const tampered = new Log(plans).push(legacySnapshot(altered, merkleProof(leaves, plans) as string[]));
    expect(st(world([logs[0] as Log, logs[1] as Log, tampered], { legacyRoot }), plans).status).toMatchObject({
      kind: "unverified",
      atSeq: 0,
    });
    const adoption = createFirstSnapshot(carol.account, { state: childState(M, 62, { kind: "folder" }), deps: [], at });
    const adopted = new Log(plans).push(createSnapshot(carol.account, { ...adoption, nodeId: plans }));
    const adoptedNs = st(world([logs[0] as Log, logs[1] as Log, adopted], { legacyRoot }), plans);
    expect(adoptedNs.status).toMatchObject({ kind: "unverified", atSeq: 0 });
    expect(adoptedNs.state.shares).toEqual([]);
  });
});

describe("review probes without a regression test of their own", () => {
  const r = () => Log.create(alice, rootState(alice, 70));
  const folder = (parent: Log, n: number, deps: Dep[], over: Partial<State> = {}) =>
    Log.create(alice, childState(parent.nodeId, n, { kind: "folder", ...over }), deps);

  it("t9r2 C: an editor on the folder a node left can't act on it by leaving the mover's role source unnamed", () => {
    const R = r();
    const P = folder(R, 71, [R.dep()], { shares: [share(dan, "editor")] });
    const X = folder(R, 72, [R.dep()]);
    const n = Log.create(alice, childState(P.nodeId, 73), [P.dep(), R.dep()]);
    const W0 = world([R, P, X, n]);
    write(alice, W0, n, { move: X.nodeId });
    const W = world([R, P, X, n]);
    expect(st(W, n.nodeId).state.parentId).toBe(X.nodeId);
    expect(W.role(dan.id, n.nodeId)).toBeNull();
    for (const deps of [
      [P.dep(), X.dep()],
      [P.dep(), X.dep(), R.dep()],
    ]) {
      const a = n.clone().add(dan, { ...n.state(), shares: [share(carol, "viewer")] }, deps);
      const ns = st(world([R, P, X, a]), n.nodeId);
      expect(ns.status).toEqual(verified);
      expect(ns.state.parentId).toBe(X.nodeId);
      expect(shareIds(ns)).toEqual([]);
    }
    expect(refused(dan, W, n, { add: share(carol, "viewer") })).toContain("skip");
  });

  it("t9r3 R0: a restriction by an owner through an unnamed ancestor stands against an editor below", () => {
    const R = r();
    const F = folder(R, 74, [R.dep()], { shares: [share(eve, "owner")] });
    const P = folder(F, 75, [F.dep(), R.dep()], { shares: [share(dan, "editor")] });
    const n = Log.create(alice, childState(P.nodeId, 76), [P.dep(), F.dep(), R.dep()]);
    write(eve, world([R, F, P, n]), n, {
      restrict: { shares: [], groups: [], links: [], rekey: rekeyTo(n.nodeId, 2, 77) },
    });
    const W = world([R, F, P, n]);
    expect(st(W, n.nodeId)).toMatchObject({ status: verified, state: { restricted: true, version: 2 } });
    expect(W.role(eve.id, n.nodeId)).toBe("owner");
    expect(W.role(dan.id, n.nodeId)).toBeNull();
    for (const deps of [[P.dep()], [P.dep(), F.dep(), R.dep()]]) {
      const a = n.clone().add(dan, { ...n.state(), shares: [...n.state().shares, share(carol, "viewer")] }, deps);
      const ns = st(world([R, F, P, a]), n.nodeId);
      expect(ns.status).toEqual(verified);
      expect(ns.state.restricted).toBe(true);
      expect(shareIds(ns)).toEqual(ids(eve));
    }
  });

  it("t9r4 B2/B3: an editor on the folder can't unrestrict or move a node restricted through a group he doesn't name", () => {
    const G = group([eve]);
    const gv = view([G]);
    const R = r();
    const P = folder(R, 78, [R.dep()], {
      shares: [share(dan, "editor")],
      groupShares: [{ groupId: G.id, role: "owner" }],
    });
    const X = folder(R, 79, [R.dep()], { shares: [share(dan, "owner")] });
    const n = Log.create(alice, childState(P.nodeId, 80, { shares: [share(carol, "editor")] }), [P.dep(), R.dep()]);
    write(eve, world([R, P, X, n], { groups: gv }), n, {
      restrict: { shares: [share(carol, "editor")], groups: [], links: [], rekey: rekeyTo(n.nodeId, 2, 81) },
    });
    const W = world([R, P, X, n], { groups: gv });
    expect(st(W, n.nodeId)).toMatchObject({ status: verified, state: { restricted: true } });
    expect(shareIds(st(W, n.nodeId))).toEqual(ids(carol, eve));
    const kept = st(W, n.nodeId).state.shares;
    for (const deps of [
      [P.dep(), R.dep(), X.dep()],
      [P.dep(), R.dep(), X.dep(), gdep(G)],
    ]) {
      for (const state of [
        { ...n.state(), restricted: false, shares: kept },
        { ...n.state(), parentId: X.nodeId, shares: kept },
        { ...n.state(), parentId: X.nodeId, restricted: false, shares: kept },
      ]) {
        const ns = st(world([R, P, X, n.clone().add(dan, state, deps)], { groups: gv }), n.nodeId);
        expect(ns.status).toEqual(verified);
        expect(ns.state.restricted).toBe(true);
        expect(ns.state.parentId).toBe(P.nodeId);
      }
    }
    for (const intent of [{ unrestrict: P.nodeId }, { move: X.nodeId }] as Intent[])
      expect(refused(dan, W, n, intent)).toContain("skip");
    // eve, the restricting owner, can open it again; then dan edits it once more
    write(eve, W, n, { unrestrict: P.nodeId });
    const W2 = world([R, P, X, n], { groups: gv });
    expect(st(W2, n.nodeId).state.restricted).toBe(false);
    expect(W2.role(dan.id, n.nodeId)).toBe("editor");
  });

  it("t9r4 J: after an honest unrestrict, a writer must name the group the unrestricter's authority came from", () => {
    const G = group([eve]);
    const gv = view([G]);
    const R = r();
    const P = folder(R, 82, [R.dep()], {
      shares: [share(dan, "editor")],
      groupShares: [{ groupId: G.id, role: "owner" }],
    });
    const n = Log.create(alice, childState(P.nodeId, 83, { shares: [share(carol, "editor")] }), [P.dep(), R.dep()]);
    write(eve, world([R, P, n], { groups: gv }), n, {
      restrict: { shares: [share(carol, "editor")], groups: [], links: [], rekey: rekeyTo(n.nodeId, 2, 84) },
    });
    write(eve, world([R, P, n], { groups: gv }), n, { unrestrict: P.nodeId });
    const W = world([R, P, n], { groups: gv });
    expect(st(W, n.nodeId)).toMatchObject({ status: verified, stale: false, state: { restricted: false } });
    // without G the lift can't be judged (eve's editor on P comes through G): it reads as restricted in dan's view
    // and he has no role (§3.3: an unproven or lapsed unrestrict reads as restricted)
    const bare = n
      .clone()
      .add(dan, { ...n.state(), shares: [...n.state().shares, share(bob, "viewer")] }, [P.dep(), R.dep()]);
    expect(shareIds(st(world([R, P, bare], { groups: gv }), n.nodeId))).toEqual(ids(carol, eve));
    // the client names it for him
    const s = write(dan, W, n, { add: share(bob, "viewer") });
    expect(s.deps.map((d) => d.log)).toContain(`group:${G.id}`);
    expect(shareIds(st(world([R, P, n], { groups: gv }), n.nodeId))).toEqual(ids(bob, carol, eve));
  });

  it("t9r3 E3: a lapsed move of an ancestor in a deep chain; an honest editor below writes with authorityDeps", () => {
    const R = r();
    const F = folder(R, 85, [R.dep()], { shares: [share(bob, "editor"), share(dan, "editor")] });
    const Z = folder(R, 86, [R.dep()], { shares: [share(bob, "editor")] });
    const Q = folder(F, 87, [F.dep(), R.dep()]);
    const P = folder(Q, 88, [Q.dep(), F.dep(), R.dep()]);
    const n = Log.create(alice, childState(P.nodeId, 89), [P.dep(), Q.dep(), F.dep(), R.dep()]);
    const logs = [R, F, Z, Q, P, n];
    // bob moves Q into Z, then alice removes bob from F: his move loses its voucher and Q falls back to F
    write(bob, world(logs), Q, { move: Z.nodeId });
    expect(st(world(logs), Q.nodeId).state.parentId).toBe(Z.nodeId);
    write(alice, world(logs), F, { remove: bob.id, rekey: rekeyTo(F.nodeId, 2, 90) });
    let W = world(logs);
    expect(st(W, Q.nodeId)).toMatchObject({ status: verified, state: { parentId: F.nodeId } });
    expect(W.role(bob.id, n.nodeId)).toBeNull();
    expect(W.role(dan.id, n.nodeId)).toBe("editor");
    expect(st(W, n.nodeId).stale).toBe(true);
    // dan's re-key, naming the whole stretch, applies and makes n fresh
    const s = write(dan, W, n, { rekey: rekeyTo(n.nodeId, 2, 91) });
    expect(s.deps.map((d) => d.log).sort()).toEqual([R, F, Z, Q, P].map((l) => l.nodeId).sort());
    W = world(logs);
    expect(st(W, n.nodeId)).toMatchObject({ status: verified, stale: false, state: { version: 2 } });
    write(dan, W, n, { add: share(carol, "viewer") });
    expect(world(logs).role(carol.id, n.nodeId)).toBe("viewer");
  });

  it("t12 P3: a grantor demoted without a re-key still vouches for the key of that version", () => {
    const { plans, w } = mc2();
    write(alice, w(), plans, { add: share(dan, "editor") });
    const g = grant(dan, carol, plans.nodeId, 1, key(K.plans));
    write(alice, w(), plans, { role: { userId: dan.id, role: "viewer" } });
    const W = w();
    const ns = st(W, plans.nodeId);
    expect(ns).toMatchObject({ status: verified, stale: false, state: { version: 1 } });
    expect(acceptGrant(W, ns, g, key(K.plans))).toBe(true);
    // a grant he makes now, as a viewer, can't be told from it and is the same key: also accepted
    expect(acceptGrant(W, ns, grant(dan, carol, plans.nodeId, 1, key(K.plans)), key(K.plans))).toBe(true);
    // a grant labelled owner from someone who was never an owner is the same key again; the label gives carol
    // nothing, since roles are the state's (`world.role`), not the grant's
    expect(acceptGrant(W, ns, grant(dan, carol, plans.nodeId, 1, key(K.plans), "owner"), key(K.plans))).toBe(true);
    expect(W.role(carol.id, plans.nodeId)).toBe("viewer");
  });
});

describe("a lift that can't be proven is a gap, not a lapse (§3.3, §4.4; addendum review A1, A4, A7, C1)", () => {
  /** alice's root R > F (bob, carol editors); bob's private channel X under F, published, re-keyed by carol who adds eve. */
  function published() {
    const R = Log.create(alice, rootState(alice, 1));
    const logs = [R];
    const w = () => world(logs);
    const F = create(
      alice,
      w(),
      R,
      childState("", 2, { kind: "folder", shares: [share(bob, "editor"), share(carol, "editor")] }),
    );
    logs.push(F);
    const X = create(
      bob,
      w(),
      F,
      childState("", 3, { kind: "channel", restricted: true, shares: [share(bob, "owner")] }),
    );
    logs.push(X);
    write(bob, w(), X, { add: share(dan, "viewer") });
    write(bob, w(), X, { unrestrict: F.nodeId });
    write(carol, w(), X, { rekey: rekeyTo(X.nodeId, 2, 30) });
    write(carol, w(), X, { add: share(eve, "viewer") });
    return { R, F, X, logs, w };
  }
  // the skipped entry still chains (seq moves on); nothing of it is applied
  const open = { status: verified, seq: 5, state: { restricted: false, version: 2 } };

  it("A1: the lifter, now an editor, can't take the channel private again by naming no deps", () => {
    const { X, w } = published();
    const s = X.state();
    // with nothing named the lift can't be judged; it must not read as lapsed, which would make him owner again
    X.add(
      bob,
      { ...s, restricted: true, ...rekeyTo(X.nodeId, 3, 40), shares: [share(bob, "owner"), share(dan, "viewer")] },
      [],
    );
    const ns = st(w(), X.nodeId);
    expect(ns).toMatchObject(open);
    expect(shareIds(ns)).toEqual(ids(dan, eve));
    expect(w().role(bob.id, X.nodeId)).toBe("editor");
    expect(w().role(alice.id, X.nodeId)).toBe("owner");
  });

  it("A4: nor by naming the folder but not the root above it", () => {
    const { F, X, w } = published();
    const s = X.state();
    X.add(
      bob,
      { ...s, restricted: true, ...rekeyTo(X.nodeId, 3, 42), shares: [share(bob, "owner"), share(dan, "viewer")] },
      [F.dep()],
    );
    expect(st(w(), X.nodeId)).toMatchObject(open);
    expect(shareIds(st(w(), X.nodeId))).toEqual(ids(dan, eve));
  });

  it("A5 (control): the same restrict naming the folder and the root is judged and skipped", () => {
    const { R, F, X, w } = published();
    const s = X.state();
    X.add(
      bob,
      { ...s, restricted: true, ...rekeyTo(X.nodeId, 3, 43), shares: [share(bob, "owner"), share(dan, "viewer")] },
      [F.dep(), R.dep()],
    );
    expect(st(w(), X.nodeId)).toMatchObject(open);
    // and the honest lift still holds in a view that names the chain: alice's write applies
    write(alice, w(), X, { add: share(bob, "editor") });
    expect(st(w(), X.nodeId)).toMatchObject({ status: verified, seq: 6, state: { restricted: false, version: 2 } });
    expect(shareIds(st(w(), X.nodeId))).toEqual(ids(bob, dan, eve));
  });

  it("A2: a removal needing owner, with no deps, is skipped too", () => {
    const { X, w } = published();
    const s = X.state();
    X.add(bob, { ...s, ...rekeyTo(X.nodeId, 3, 41), shares: s.shares.filter((x) => x.userId !== eve.id) }, []);
    expect(st(w(), X.nodeId)).toMatchObject(open);
    expect(shareIds(st(w(), X.nodeId))).toEqual(ids(dan, eve));
  });

  it("A7: a co-owner the creator added under the restriction, with no role on the folder, can't either", () => {
    const R = Log.create(alice, rootState(alice, 1));
    const logs = [R];
    const w = () => world(logs);
    const F = create(alice, w(), R, childState("", 2, { kind: "folder", shares: [share(bob, "editor")] }));
    logs.push(F);
    const X = create(
      bob,
      w(),
      F,
      childState("", 3, { kind: "channel", restricted: true, shares: [share(bob, "owner")] }),
    );
    logs.push(X);
    write(bob, w(), X, { add: share(carol, "owner") });
    const lift = write(bob, w(), X, { unrestrict: F.nodeId });
    // carol's owner share rested on bob's, which went with the restriction: both are gone from the open channel
    expect(lift.state.shares).toEqual([]);
    expect(w().role(carol.id, X.nodeId)).toBeNull();
    const s = X.state();
    X.add(
      carol,
      { ...s, restricted: true, ...rekeyTo(X.nodeId, 2, 44), shares: [share(bob, "owner"), share(carol, "owner")] },
      [],
    );
    const ns = st(w(), X.nodeId);
    expect(ns).toMatchObject({ status: verified, seq: 3, state: { restricted: false, version: 1 } });
    expect(shareIds(ns)).toEqual([]);
    expect(w().role(carol.id, X.nodeId)).toBeNull();
    expect(w().role(bob.id, X.nodeId)).toBe("editor");
  });

  it("C1: one level up: a child of a published folder, with the folder named but not what gave the lift editor", () => {
    const R = Log.create(alice, rootState(alice, 1));
    const logs = [R];
    const w = () => world(logs);
    const F = create(
      alice,
      w(),
      R,
      childState("", 2, { kind: "folder", shares: [share(bob, "editor"), share(carol, "editor")] }),
    );
    logs.push(F);
    const P = create(
      bob,
      w(),
      F,
      childState("", 3, { kind: "folder", restricted: true, shares: [share(bob, "owner")] }),
    );
    logs.push(P);
    write(bob, w(), P, { unrestrict: F.nodeId });
    const Y = create(carol, w(), P, childState("", 4, { shares: [share(dan, "editor")] }));
    logs.push(Y);
    expect(w().role(dan.id, Y.nodeId)).toBe("editor");
    // bob (editor through F) removes dan from Y naming P only: P's lift can't be judged without F, so P is a gap
    // in that view and gives him nothing; the removal (owner) is skipped
    const s = Y.state();
    Y.add(bob, { ...s, ...rekeyTo(Y.nodeId, 2, 50), shares: [] }, [P.dep()]);
    const ns = st(w(), Y.nodeId);
    expect(ns).toMatchObject({ status: verified, seq: 1, state: { version: 1 } });
    expect(shareIds(ns)).toEqual(ids(dan));
    expect(w().role(dan.id, Y.nodeId)).toBe("editor");
    // the honest write names the whole chain and applies
    write(alice, w(), Y, { remove: dan.id, rekey: rekeyTo(Y.nodeId, 2, 51) });
    expect(st(w(), Y.nodeId)).toMatchObject({ status: verified, seq: 2, state: { version: 2 } });
    expect(shareIds(st(w(), Y.nodeId))).toEqual([]);
  });
});
