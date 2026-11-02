import { type B64, ROLE_RANK, type Role } from "../wire.ts";
import { type Prefix, stateRole, viewOf } from "./authority.ts";
import { snapshotHash } from "./encode.ts";
import { appliedOf, foldLog, NO_STATE, originState, placesOf, prefixOf, signedEntry } from "./fold.ts";
import { teamOfAnchor } from "./groups.ts";
import { noRemovals } from "./stretch.ts";
import type { Dep, GroupView, LogEntry, NodeState, Snapshot, State } from "./types.ts";

/** Everything a client was shown or knows, from which every node's state is folded. */
export type WorldInput = {
  /** Each node's log as the server sent it, in chain order. */
  logs: Map<string, LogEntry[]>;
  /** The migration root that legacy origins are proven against (§7); null where there is none. */
  legacyRoot: B64 | null;
  /** This account's resolution of an author's key (§6.1). */
  identity: (userId: string, signPub: B64) => "ok" | "unknown" | "mismatch";
  groups: GroupView;
  /** The last `{seq, head}` this device verified per log (§5.4). */
  floors?: ReadonlyMap<string, { seq: number; head: B64 }>;
};

const isObj = (x: unknown): x is Record<string, unknown> => typeof x === "object" && x !== null && !Array.isArray(x);

/**
 * The logs a client was shown, folded on demand. Each log folds once; a fold that needs another log's
 * state asks for it here, and a log asked for while it is being folded (a cycle) comes back unverified.
 * A fold that read such a state depends on where the cycle was entered, so no result depends on which
 * log was asked for first: it's kept only for the rest of the outermost request (each log still folds
 * at most once there), and, for the log that request asked for, for that log's later requests.
 */
export class LogWorld {
  private readonly folded = new Map<string, NodeState | null>();
  private readonly chains = new Map<string, B64[]>();
  private readonly roots = new Map<string, string | null>();
  private readonly above = new Map<string, Set<string>>();
  private readonly claims = new Map<string, string[]>();
  private readonly visiting = new Set<string>();
  /** Folds on the stack when a cycle was hit: their results depend on where it was entered. */
  private readonly tainted = new Set<string>();
  /** Tainted folds, for the rest of the outermost request. */
  private readonly scratch = new Map<string, NodeState>();
  /** Tainted folds of logs asked for from outside, for when they are asked for from outside again. */
  private readonly asked = new Map<string, NodeState>();

  readonly input: WorldInput;

  constructor(input: WorldInput) {
    this.input = input;
  }

  /**
   * The node's folded state, or null if no log was shown for it. Rolled back if the log doesn't extend
   * this device's floor (§5.4); unverified if it's unrestricted and its parent chain isn't verified (§4.1).
   */
  state(nodeId: string): NodeState | null {
    const done = this.folded.get(nodeId);
    if (done !== undefined) return done;
    const entries = this.input.logs.get(nodeId);
    if (!Array.isArray(entries) || entries.length === 0) {
      this.folded.set(nodeId, null);
      return null;
    }
    return this.guarded(nodeId, () => {
      const ns = foldLog(this, nodeId, entries);
      const { parentId, restricted } = ns.state;
      if (!restricted && parentId !== null && ns.status.kind === "verified") {
        const parent = this.state(parentId);
        if (parent?.status.kind !== "verified")
          ns.status = { kind: "unverified", atSeq: Math.max(ns.seq, 0), reason: "needs-parent" };
      }
      const floor = this.input.floors?.get(nodeId);
      if (floor && this.headAt(nodeId, floor.seq) !== floor.head) ns.status = { kind: "rolled-back", log: nodeId };
      return ns;
    });
  }

  /**
   * The log as its one fold stood at `seq`: the applied state and its vouchers there (no floors, no
   * parent check), and how far it was verified then. Null if it has no such seq, or is being folded.
   */
  stateAt(nodeId: string, seq: number): Prefix | null {
    const ns = this.state(nodeId);
    return ns ? prefixOf(ns, seq) : null;
  }

  /** The hash of the shown log's entry at `seq`, if the chain holds up to it. */
  headAt(log: string, seq: number): B64 | null {
    return this.chain(log)[seq] ?? null;
  }

  /**
   * The user's effective role on the node (§4.1): its own effective state (with its groups and team
   * anchor at the newest verified group versions), then each verified ancestor while unrestricted. The
   * node's own state counts even when it isn't verified: callers must check `state(nodeId).status` (and
   * `stale`) before acting on it. It is not the test for offering "verify and re-key" on an unverified
   * node: that state has every resolvable author's stretch removals applied (§3.5), so a non-owner may
   * have dropped a legitimate owner from it. Use `canCheckpoint` (accept.ts) for the offer.
   */
  role(userId: string, nodeId: string): Role | null {
    return this.roleSource(userId, nodeId)?.role ?? null;
  }

  /** The user's effective role and the log it comes from (the node itself, or the nearest ancestor giving it). */
  roleSource(userId: string, nodeId: string): { role: Role; source: string } | null {
    const ns = this.state(nodeId);
    if (!ns) return null;
    const now = viewOf("now");
    const own = stateRole(this, now, ns.state, userId);
    let best = own ? { role: own, source: nodeId } : null;
    const seen = new Set([nodeId]);
    let cur = ns.state;
    while (!cur.restricted && cur.parentId !== null && !seen.has(cur.parentId)) {
      const id = cur.parentId;
      seen.add(id);
      const p = this.state(id);
      if (p?.status.kind !== "verified") break;
      const r = stateRole(this, now, p.state, userId);
      if (r && (!best || ROLE_RANK[r] > ROLE_RANK[best.role])) best = { role: r, source: id };
      cur = p.state;
    }
    return best;
  }

  /**
   * The id of the root the node's origin chain ends at (§5.3), or null if it loops or a log on the way
   * wasn't shown or doesn't start with its genuine origin (fold.ts `originState`). A root never moves
   * and every move stays in its root, so this is where every place the node ever had ends too.
   */
  rootOf(nodeId: string): string | null {
    const path: string[] = [];
    const onPath = new Set<string>();
    let found: string | null = null;
    for (let id: string | null = nodeId; id !== null; ) {
      const known = this.roots.get(id);
      if (known !== undefined) {
        found = known;
        break;
      }
      if (onPath.has(id)) break;
      path.push(id);
      onPath.add(id);
      const s = originState(this, id);
      if (s === null) break;
      if (s.parentId === null) {
        found = s.anchor === null ? null : id;
        break;
      }
      id = s.parentId;
    }
    for (const id of path) this.roots.set(id, found);
    return found;
  }

  /**
   * Whether `to` is the node, or might be below it: some signed entry of `to`'s log, or of a log it
   * names as its parent in one (and so on up), names the node as its parent (`claimedParents`). Every place a
   * node can ever have, a lapsed move's fallback included, is in its log, so a move this lets through
   * never closes a loop with anything shown (§5.3). Read without folding, so it never recurses.
   */
  mayBeBelow(to: string, nodeId: string): boolean {
    let up = this.above.get(to);
    if (!up) {
      up = new Set([to]);
      const queue = [to];
      for (let id = queue.pop(); id !== undefined; id = queue.pop())
        for (const p of this.claimedParents(id))
          if (!up.has(p)) {
            up.add(p);
            queue.push(p);
          }
      this.above.set(to, up);
    }
    return up.has(nodeId);
  }

  /**
   * Every parent the shown log's chained entries name, counting only entries their author could have
   * signed (fold.ts `signedEntry`): one the server made up, or whose author doesn't resolve, says
   * nothing. A resolvable author's entry counts whether or not it applies (that needs the fold).
   */
  private claimedParents(log: string): string[] {
    const done = this.claims.get(log);
    if (done) return done;
    const entries = this.input.logs.get(log);
    const n = this.chain(log).length;
    const out: string[] = [];
    for (let i = 0; i < n; i++) {
      const e: unknown = (entries as unknown[])[i];
      if (!signedEntry(this, log, i, e)) continue;
      const p = (e as Snapshot).state.parentId;
      if (typeof p === "string") out.push(p);
    }
    this.claims.set(log, out);
    return out;
  }

  private guarded(nodeId: string, run: () => NodeState): NodeState {
    if (this.visiting.has(nodeId)) {
      this.taintAll();
      return cycle(nodeId);
    }
    const outer = this.visiting.size === 0;
    const kept = outer ? this.asked.get(nodeId) : this.scratch.get(nodeId);
    if (kept) {
      if (!outer) this.taintAll();
      return kept;
    }
    this.visiting.add(nodeId);
    try {
      const ns = run();
      if (!this.tainted.has(nodeId)) this.folded.set(nodeId, ns);
      else if (outer) this.asked.set(nodeId, ns);
      else this.scratch.set(nodeId, ns);
      return ns;
    } finally {
      this.visiting.delete(nodeId);
      if (this.visiting.size === 0) {
        this.tainted.clear();
        this.scratch.clear();
      } else this.tainted.delete(nodeId);
    }
  }

  /** Everything on the stack now depends on where a cycle was entered. */
  private taintAll(): void {
    for (const v of this.visiting) this.tainted.add(v);
  }

  /** The shown log's hashes for as long as it chains (seq = index, prev = the hash before). */
  private chain(log: string): B64[] {
    const done = this.chains.get(log);
    if (done) return done;
    const out: B64[] = [];
    const entries = this.input.logs.get(log);
    if (Array.isArray(entries)) {
      for (const e of entries as unknown[]) {
        const i = out.length;
        if (!isObj(e) || e.seq !== i || e.prev !== (i === 0 ? null : out[i - 1])) break;
        try {
          out.push(snapshotHash(e as Snapshot));
        } catch {
          break;
        }
      }
    }
    this.chains.set(log, out);
    return out;
  }
}

/**
 * The deps a writer names for a snapshot on the node (§3.3, §4.4): every parent the node has held (the
 * one it is under now, the applied one, and each place a lapsed move falls back to), each ancestor
 * above every one of them, and each ancestor's held parents in turn, every log where it is now; with
 * every group shared with along the way and the root's team groups (Admins, Everyone), at the client's
 * newest verified versions. A role, a share someone vouched for, a move's voucher, or a void team share
 * may come from any of them (a place left unnamed is a gap, §4.4), and naming one that isn't needed
 * costs nothing but freshness. The same for every writer: who is writing doesn't change what is named.
 */
export function authorityDeps(world: LogWorld, nodeId: string): Dep[] {
  const ns = world.state(nodeId);
  if (!ns) return [];
  const out = new Map<string, Dep>();
  const groups = world.input.groups;
  const group = (groupId: string) => {
    const l = groups.latest(groupId);
    if (l !== null) out.set(`group:${groupId}`, { log: `group:${groupId}`, seq: l.version, head: l.head });
  };
  const groupsOf = (s: State) => {
    for (const g of s.groupShares) group(g.groupId);
    const team = teamOfAnchor(s);
    const tg = team === null ? null : groups.teamGroups(team);
    if (tg) {
      group(tg.admins);
      group(tg.everyone);
    }
  };
  // Every place a log has held, and where each one is now: a writer names the whole stretch, as a
  // move anywhere on it is judged by them (§4.4).
  const places = (s: NodeState): string[] => {
    const held = placesOf(s);
    return s.state.parentId === null || held.includes(s.state.parentId) ? held : [s.state.parentId, ...held];
  };
  const seen = new Set([nodeId]);
  const todo = places(ns);
  for (let next = todo.pop(); next !== undefined; next = todo.pop()) {
    if (seen.has(next)) continue;
    seen.add(next);
    const s = world.state(next);
    if (!s || s.seq < 0) continue;
    out.set(next, { log: next, seq: s.seq, head: s.head });
    groupsOf(s.state);
    todo.push(...places(s));
  }
  groupsOf(ns.state);
  const appliedHere = appliedOf(ns);
  if (appliedHere) groupsOf(appliedHere);
  return [...out.values()];
}

/** What a log asked for while it is being folded looks like: nothing in it, not checkable. Not memoised. */
const cycle = (nodeId: string): NodeState => ({
  nodeId,
  state: NO_STATE,
  stale: false,
  head: "",
  seq: -1,
  status: { kind: "unverified", atSeq: 0, reason: "cycle" },
  deps: new Map(),
  stretchRemovals: noRemovals(),
  stretchVersion: 0,
});

/** The root a node's chain ends at (§5.3); null on a loop or a chain that can't be checked. Memoised per world. */
export const rootOf = (world: LogWorld, nodeId: string): string | null => world.rootOf(nodeId);
