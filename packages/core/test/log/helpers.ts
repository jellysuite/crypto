/**
 * Shared fixtures for the log tests: users, states, a `Log` a test appends to, a world of logs, and the MC-2 world.
 * Honest logs are written the way a client writes them (`create`, `write`); only attacks are made by hand (`Log.add`).
 */
import { toBase64Url } from "@jelly/crypto";
import {
  authorityDeps,
  type Change,
  type ChildLink,
  createAccount,
  createFirstSnapshot,
  createGrant,
  createSnapshot,
  type Dep,
  type Grant,
  type GroupView,
  type Intent,
  keyCommit,
  type LogEntry,
  LogWorld,
  type NodeState,
  nextSnapshot,
  type PublicIdentity,
  type Role,
  reissueSet,
  type Snapshot,
  type State,
  snapshotHash,
  type UnlockedAccount,
  unlockAccount,
  type WorldInput,
} from "../../src/index.ts";

export function user(handle: string, id = crypto.randomUUID()) {
  const acct = createAccount();
  const account = unlockAccount({ userId: id, handle, ak: acct.ak, bundle: acct.bundle });
  const { signPub, encPub, encPubSig } = acct.bundle;
  const identity: PublicIdentity = { userId: id, handle, signPub, encPub, encPubSig };
  return { id, account, signPub, identity };
}
export type U = ReturnType<typeof user>;
export type Signer = { account: UnlockedAccount };

export const alice = user("alice");
export const bob = user("bob");
export const carol = user("carol");
export const dan = user("dan");
/** The server's own account: it has an identity record like anyone, and nothing else. */
export const eve = user("eve");
export const everyone = [alice, bob, carol, dan, eve];

export const at = "2026-10-31T10:00:00.000Z";
export const share = (u: U, role: Role, signPub = u.signPub) => ({ userId: u.id, role, signPub });
export type Resolve = WorldInput["identity"];
export const known: Resolve = (userId, signPub) => {
  const u = everyone.find((x) => x.id === userId);
  return !u ? "unknown" : u.signPub === signPub ? "ok" : "mismatch";
};

/** A node key, and the commit a state carries for it (§3.4: a v8 node's version 1 commits with an empty id). */
export const key = (n: number) => new Uint8Array(32).fill(n);
export const commitFor = (nodeId: string, version: number, k: Uint8Array) =>
  keyCommit(version === 1 ? "" : nodeId, version, k);
export const firstCommit = (n: number) => keyCommit("", 1, key(n));
export const rekeyTo = (nodeId: string, version: number, n: number, skipped?: string[]) => ({
  version,
  keyCommit: commitFor(nodeId, version, key(n)),
  ...(skipped ? { skipped } : {}),
});

export const noGroups: GroupView = {
  latest: () => null,
  member: () => false,
  removedAt: () => null,
  removedSince: () => false,
  teamGroups: () => null,
};

/** A group's signed versions as the client verified them: the members at each version, from 0. */
export type Group = { id: string; versions: U[][] };
export const group = (...versions: U[][]): Group => ({ id: crypto.randomUUID(), versions });
export const groupHead = (g: Group, v: number) => toBase64Url(new TextEncoder().encode(`${g.id}:${v}`));
export const gdep = (g: Group, v = g.versions.length - 1): Dep => ({
  log: `group:${g.id}`,
  seq: v,
  head: groupHead(g, v),
});
export function view(
  gs: Group[],
  teams: Record<string, { everyone: Group; admins: Group; root?: string }> = {},
): GroupView {
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

/** A personal root: its anchor is owner, with the matching share, keyed with `key(n)`. */
export const rootState = (owner: U, n: number, over: Partial<State> = {}): State => ({
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
export const childState = (parentId: string, n: number, over: Partial<State> = {}): State => ({
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
export class Log {
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

export function world(logs: Log[], over: Partial<WorldInput> = {}): LogWorld {
  return new LogWorld({
    logs: new Map(logs.map((l) => [l.nodeId, l.entries])),
    legacyRoot: null,
    identity: known,
    groups: noGroups,
    ...over,
  });
}

export const st = (w: LogWorld, id: string): NodeState => {
  const ns = w.state(id);
  if (!ns) throw new Error("no state");
  return ns;
};
export const verified = { kind: "verified" };
export const unverified = (atSeq: number, reason: string) => ({ kind: "unverified", atSeq, reason });
export const shareIds = (ns: NodeState) => ns.state.shares.map((s) => s.userId).sort();
export const ids = (...us: U[]) => us.map((u) => u.id).sort();
export const people = (w: LogWorld, ns: NodeState) =>
  reissueSet(w, ns)
    .people.map((s) => s.userId)
    .sort();
/** A dep on a log the server never shows: the check the snapshot relied on is hidden (§8.1). */
export const hidden = (): Dep => ({ log: crypto.randomUUID(), seq: 1, head: firstCommit(99) });

/** A child created as a client creates it: naming its parent and everything the parent's authority rests on. */
export function create(by: U, w: LogWorld, parent: Log, state: State): Log {
  return Log.create(by, { ...state, parentId: parent.nodeId }, [parent.dep(), ...authorityDeps(w, parent.nodeId)]);
}

/** Applies the intent as `by` and appends the result, or throws with the refusal. */
export function write(by: U, w: LogWorld, log: Log, intent: Intent, when = at): Snapshot {
  const s = nextSnapshot(by.account, w, st(w, log.nodeId), intent, when);
  if ("error" in s) throw new Error(s.error);
  log.push(s);
  return s;
}
/** The refusal `nextSnapshot` gives, or throws if it signed. */
export function refused(by: U, w: LogWorld, log: Log, intent: Intent): string {
  const s = nextSnapshot(by.account, w, st(w, log.nodeId), intent, at);
  if (!("error" in s)) throw new Error("signed what should have been refused");
  return s.error;
}

export const grant = (
  by: U,
  to: U,
  nodeId: string,
  keyVersion: number,
  nodeKey: Uint8Array,
  role: Role = "viewer",
): Grant => createGrant(by.account, { nodeId, keyVersion, nodeKey, grantee: to.identity, role });
export const link = (child: Log, parent: Log, childVersion = 1): ChildLink => ({
  childId: child.nodeId,
  childVersion,
  parentId: parent.nodeId,
  parentVersion: 1,
  wrapped: "x",
});

/** Keys by node: alice's root 1, Projects 2, Plans 3, carol's root 4, M 5; re-keys count up from 20. */
export const K = { R: 1, projects: 2, plans: 3, CR: 4, M: 5, BR: 6, page: 7 };

/**
 * The MC-2 world (`key-path-rewire.test.ts` `world({rewire:true})`), as logs a client would write: alice's root >
 * Projects > Plans; bob editor on Projects; carol viewer on Plans; carol's root > M, shared with bob as viewer.
 * `w()` folds whatever the logs hold now; `shown(...)` folds the logs as a lying server shows them.
 */
export function mc2() {
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
export const floorsOf = (w: LogWorld, ...logs: Log[]) =>
  new Map(logs.map((l) => [l.nodeId, { seq: st(w, l.nodeId).seq, head: st(w, l.nodeId).head }]));
