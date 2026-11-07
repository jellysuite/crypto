import { atLeast, type B64, ROLE_RANK, type Role } from "../wire.ts";
import {
  authorityIn,
  chainOf,
  chainRole,
  lifting,
  ownAuthorityIn,
  type Prefix,
  type Settled,
  settleIn,
  type View,
  type Vouched,
  viewOf,
  vouch,
} from "./authority.ts";
import { type Diff, diffStates, hasOwner, isRemoval, needs } from "./diff.ts";
import { snapshotHash, verifySnapshotSig, wellFormedSnapshot, wellFormedState } from "./encode.ts";
import { GROUP_REASONS, groupDepOk, teamRole } from "./groups.ts";
import { firstIdMatches } from "./ids.ts";
import { verifyLegacy } from "./legacy.ts";
import { isStale, type KeyTrack } from "./stale.ts";
import {
  countDrops,
  dropsOf,
  fitsRemovals,
  noRemovals,
  ownsGuard,
  type Stretch,
  startStretch,
  tighten,
} from "./stretch.ts";
import type { Dep, LogEntry, NodeState, Snapshot, State } from "./types.ts";
import type { LogWorld } from "./world.ts";

export { ownRole } from "./authority.ts";

/** The state of a node nothing could be checked for: nobody has a role, nothing comes from a parent. */
export const NO_STATE: State = {
  kind: "",
  parentId: null,
  anchor: null,
  restricted: true,
  version: 0,
  keyCommit: null,
  shares: [],
  groupShares: [],
  links: [],
};

/**
 * How a snapshot is applied: `origin` for a root or legacy state (its own say), `creator` for a child's
 * first. `viaChain`: the author's role came from the chain above, not from the node itself (stale.ts).
 */
type Verdict =
  | { kind: "apply"; diffs: Diff[]; by: "author" | "origin" | "creator"; viaChain: boolean }
  | { kind: "skip" }
  | { kind: "unchecked"; reason: string };

const SKIP: Verdict = { kind: "skip" };
const unchecked = (reason: string): Verdict => ({ kind: "unchecked", reason });
const isObj = (x: unknown): x is Record<string, unknown> => typeof x === "object" && x !== null && !Array.isArray(x);

/**
 * A fold in progress: the node state, the last applied snapshot's state with its vouchers, the
 * current key and the removals since it (stale.ts), the log as it stood at each seq so far, and,
 * while the node is unverified, what the stretch since did (stretch.ts).
 */
type Fold = { ns: NodeState; v: Vouched; track: KeyTrack; history: Prefix[]; st: Stretch | null };

/** Each fold's per-seq history, its last applied vouched state and its stretch (if unverified), kept beside its result. */
const folds = new WeakMap<NodeState, { history: Prefix[]; v: Vouched; st: Stretch | null }>();

/** The stretch of a folded log that ended unverified (an empty one if nothing followed), or null while verified or unknown. */
export function stretchOf(ns: NodeState): Stretch | null {
  const kept = folds.get(ns);
  if (!kept || ns.status.kind === "verified") return null;
  return kept.st ?? startStretch(kept.v);
}

/** The last applied state of a folded log (before lapse shaped it), or null. */
export const appliedOf = (ns: NodeState): State | null => folds.get(ns)?.v.applied ?? null;

/** The log as its fold stood at `seq`: its applied state and vouchers there, and how far it was verified. */
export const prefixOf = (ns: NodeState, seq: number): Prefix | null => folds.get(ns)?.history[seq] ?? null;

/**
 * Every parent a folded log has held (§3.3), newest first: the applied one, then each place a lapsed
 * move falls back to. A writer names them all, each with its chain (§4.4, `authorityDeps`).
 */
export function placesOf(ns: NodeState): string[] {
  const out: string[] = [];
  for (let h = folds.get(ns)?.v.place?.parent ?? null; h; h = h.fallback) if (h.value !== null) out.push(h.value);
  return out;
}

/**
 * Folds one node's log into its effective state (§3.5). Malformed or disallowed snapshots are skipped;
 * one that can't be checked yet, or a broken chain, makes the node unverified there. Never throws.
 */
export function foldLog(world: LogWorld, nodeId: string, entries: LogEntry[]): NodeState {
  const ns: NodeState = {
    nodeId,
    state: NO_STATE,
    stale: false,
    head: "",
    seq: -1,
    status: { kind: "verified" },
    deps: new Map(),
    stretchRemovals: noRemovals(),
    stretchVersion: 0,
  };
  if (!Array.isArray(entries) || entries.length === 0) return unverify(ns, 0, "empty");
  const f: Fold = {
    ns,
    v: { applied: NO_STATE, recs: new Map(), place: null, deps: new Map(), removed: new Map() },
    track: { key: null, dropped: false },
    history: [],
    st: null,
  };
  for (const e of entries as unknown[]) {
    const hash = chainsOn(ns, e);
    if (hash === null) {
      unverify(ns, ns.seq + 1, "chain");
      break;
    }
    const s = e as LogEntry;
    ns.seq = s.seq;
    ns.head = hash;
    if (ns.status.kind !== "verified") stretch(world, f, s);
    else
      try {
        const v = s.seq === 0 ? judgeOrigin(world, nodeId, s) : judge(world, f, s);
        if (v.kind === "apply") applySnapshot(world, f, s, v);
        else if (v.kind === "unchecked") {
          unverify(ns, s.seq, v.reason);
          // The entry that turns the node unverified is the first of the stretch (already judged).
          stretch(world, f, s, true);
        }
      } catch {
        unverify(ns, s.seq, "error");
      }
    f.history.push({ status: { ...ns.status }, vouched: f.v });
  }
  settle(world, f);
  return ns;
}

/**
 * The effective state, from the newest verified states (§3.3), and whether it is stale (stale.ts,
 * §5.2). While unverified, it is read from the last verified prefix minus what the stretch removed.
 */
function settle(world: LogWorld, f: Fold): void {
  const { ns } = f;
  folds.set(ns, { history: f.history, v: f.v, st: f.st });
  try {
    const s = settleIn(world, viewOf("now"), ns.nodeId, f.st?.ceil ?? f.v);
    ns.state = s.state;
    ns.stale = isStale(world, ns.nodeId, f.track, s);
  } catch {
    ns.state = NO_STATE;
    unverify(ns, Math.max(ns.seq, 0), "error");
  }
}

/** Marks the node unverified from `atSeq`, unless it already is from earlier. */
function unverify(ns: NodeState, atSeq: number, reason: string): NodeState {
  if (ns.status.kind === "verified") ns.status = { kind: "unverified", atSeq, reason };
  return ns;
}

/** The entry's hash if it is the next link of the chain (the next seq, naming the head as `prev`), else null. */
function chainsOn(ns: NodeState, e: unknown): B64 | null {
  if (!isObj(e) || e.seq !== ns.seq + 1 || e.prev !== (ns.seq < 0 ? null : ns.head)) return null;
  try {
    return snapshotHash(e as Snapshot);
  } catch {
    return null;
  }
}

/**
 * A snapshot after the node went unverified (§3.5, §8.1). A checkpoint that counts resumes the fold
 * (`judged`: it was judged already, as the entry that turned the node unverified). Any other chained,
 * well-formed snapshot signed by an author this account resolves:
 * - raises the floors a checkpoint must meet (version, deps) if the author has at least editor on the
 *   last verified prefix as it reads now, the version is one honest re-keys could have reached and the
 *   dep's head is one this client has: one gate, so neither a stranger nor one editor can make repair
 *   impossible;
 * - has what it takes away (against the effective state so far) applied to the effective state;
 * - has that counted against a checkpoint if its deps are no older than the applied floors and
 *   contradict nothing this client has (§4.4; a log it can't see still counts, that is the hidden
 *   check), and the author is an owner on the guard, or it is their own leave.
 * Additions are ignored. Never throws.
 */
function stretch(world: LogWorld, f: Fold, e: LogEntry, judged = false): void {
  const ns = f.ns;
  try {
    const st = (f.st ??= startStretch(f.v));
    st.seen += 1;
    if (e.legacyProof !== undefined || !wellFormedSnapshot(e) || e.nodeId !== ns.nodeId) return;
    if (e.change === "create" || !sigOk(e)) return;
    if (e.change === "checkpoint" && !judged) {
      const v = judge(world, f, e);
      if (v.kind === "apply") {
        resume(world, f, e, v);
        return;
      }
    }
    // The version floor (`ns.stretchVersion`) depends on the log bytes alone (a signed entry, a version
    // honest re-keys could have reached: one step per entry), so every client computes the same one and
    // a checkpoint one client accepts isn't skipped by another, nor a version given two commits.
    if (e.state.version <= f.v.applied.version + st.seen)
      ns.stretchVersion = Math.max(ns.stretchVersion, e.state.version);
    if (!authorResolves(world, e)) return;
    if (atLeast(authorityIn(settleIn(world, viewOf("now"), ns.nodeId, f.v), e.authorId), "editor")) {
      // The dep floor: a dep this client has the head of.
      for (const d of e.deps) {
        const shown = d.log.startsWith("group:")
          ? groupDepOk(world, d) === "ok"
          : world.headAt(d.log, d.seq) === d.head;
        if (shown) st.deps.set(d.log, Math.max(st.deps.get(d.log) ?? -1, d.seq));
      }
    }
    const drops = dropsOf(diffStates(st.ceil.applied, e.state));
    if (drops.length === 0) return;
    const deps = depsOf(e);
    const views = [viewOf("now"), viewOf("deps", deps)];
    const counted = !depsHold(world, ns, e)
      ? []
      : ownsGuard(world, ns.nodeId, st, ns.stretchRemovals.restricted, e.authorId, views)
        ? drops
        : e.change === "leave"
          ? drops.filter((d) => d.kind === "remove-share" && d.userId === e.authorId)
          : [];
    // The place isn't changed while unverified (an owner restricting keeps their offer of repair); a
    // counted restrict closes the guard to the chain instead (`ownsGuard`).
    const entries = (ds: Diff[]) => ds.filter((d) => d.kind !== "restrict");
    st.ceil = tighten(st.ceil, entries(drops));
    if (counted.length === 0) return;
    st.guard = tighten(st.guard, entries(counted));
    countDrops(ns.stretchRemovals, counted);
    if (counted.some((d) => d.kind === "restrict")) st.restrictedBy.add(e.authorId);
  } catch {
    // What can't be read while unverified counts for nothing.
  }
}

/**
 * Whether a stretch snapshot's deps could be honest (§4.4): none older than a dep an applied snapshot
 * named (a removed editor can't rely on an ancestor state from before their removal), and none naming,
 * at a seq this client has, another head than the one it has (a fork). A log or seq this client wasn't
 * shown passes: that is what a hidden check looks like.
 */
function depsHold(world: LogWorld, ns: NodeState, e: Snapshot): boolean {
  return e.deps.every((d) => {
    if (d.seq < (ns.deps.get(d.log)?.seq ?? -1)) return false;
    if (d.log.startsWith("group:")) {
      const latest = world.input.groups.latest(d.log.slice("group:".length));
      return latest === null || d.seq !== latest.version || d.head === latest.head;
    }
    const head = world.headAt(d.log, d.seq);
    return head === null || head === d.head;
  });
}

/** A checkpoint that counts: the node is verified again from it, and the stretch is over (§8.1). */
function resume(world: LogWorld, f: Fold, s: LogEntry, v: Verdict & { kind: "apply" }): void {
  f.ns.status = { kind: "verified" };
  f.ns.stretchRemovals = noRemovals();
  f.st = null;
  applySnapshot(world, f, s, v);
}

/**
 * Whether this account resolves the author's key to the author (§6.1): through its pins (earlier keys
 * included, so a key change leaves older snapshots valid), a team vouch, or first sight, never through
 * the log. A share's `signPub` is only a hint (`keyHints`), so no state can make a key act as anyone.
 */
const authorResolves = (world: LogWorld, s: Snapshot): boolean =>
  world.input.identity(s.authorId, s.authorSignPub) === "ok";

/**
 * Whether a root's personal anchor key resolves to its user (§6.1): the root's identity, so the one
 * key in a state that isn't just a hint. A signed root's anchor is its author's key, which already
 * had to resolve; this is for a legacy root. A team anchor or a child has no key to resolve.
 */
const anchorResolves = (world: LogWorld, s: State): boolean =>
  s.parentId !== null ||
  s.anchor === null ||
  !("user" in s.anchor) ||
  world.input.identity(s.anchor.user, s.anchor.signPub) === "ok";

/** The snapshot's deps, by log (a node id or `group:<id>`). */
const depsOf = (s: Snapshot): Map<string, Dep> => new Map(s.deps.map((d) => [d.log, d]));

/**
 * Why a dep the snapshot names can't be checked (§4.4): its log wasn't shown, or was shown older than
 * it or forked from it ("stale-dependency"); for a group, the client's verified group view is older
 * than it or has another head there ("stale-dependency"), or has no such group ("needs-group").
 * Null: all fine.
 */
function staleDep(world: LogWorld, s: Snapshot): string | null {
  for (const d of s.deps) {
    if (d.log.startsWith("group:")) {
      const ok = groupDepOk(world, d);
      if (ok !== "ok") return ok;
    } else if (world.headAt(d.log, d.seq) !== d.head) return "stale-dependency";
  }
  return null;
}

/**
 * Whether a creation's state has an owner entry only an owner above may give (§3.2, §3.3): a person at
 * owner, unless it is the creator of a restricted child (their private channel or DM), or any group or
 * link at owner. The restriction anchors the creator's share (`vouch`), so it counts without them.
 */
const ownersFromAbove = (s: State, author: string): boolean =>
  s.shares.some((x) => x.role === "owner" && !(s.restricted && s.parentId !== null && x.userId === author)) ||
  s.groupShares.some((x) => x.role === "owner") ||
  s.links.some((x) => x.role === "owner");

/** Whether `nodeId` may be the team's root: the one the group view names, or any when it names none (or throws). */
function isTeamRoot(world: LogWorld, teamId: string, nodeId: string): boolean {
  try {
    const pinned = world.input.groups.teamRoot?.(teamId) ?? null;
    return pinned === null || pinned === nodeId;
  } catch {
    return false;
  }
}

/** Seq 0: a legacy origin proven against the migration root, a signed root by its own anchor, or a child by an editor of its parent (§3.2, §3.4, §4.2, §7). */
function judgeOrigin(world: LogWorld, nodeId: string, e: LogEntry): Verdict {
  const origin: Verdict = { kind: "apply", diffs: [], by: "origin", viaChain: false };
  const fault = originFault(world, nodeId, e);
  if (fault !== null) return unchecked(fault);
  // A legacy proof vouches for the server's state, not for the anchor's key (§6.1, §7).
  if (e.legacyProof !== undefined) return anchorResolves(world, e.state) ? origin : unchecked("identity");
  if (!sigOk(e)) return unchecked("origin");
  if (!authorResolves(world, e)) return unchecked("identity");
  const { parentId, anchor } = e.state;
  // A restricted child with no owner of its own could never be re-keyed by anyone: not a valid origin.
  if (parentId !== null && e.state.restricted && !hasOwner(e.state)) return unchecked("owner");
  if (parentId !== null) {
    const deps = depsOf(e);
    if (!deps.has(parentId)) return unchecked("needs-dep");
    const stale = staleDep(world, e);
    if (stale) return unchecked(stale);
    const view = viewOf("deps", deps);
    const chain = chainOf(world, view, nodeId, parentId);
    // Creating needs editor on the parent; an owner in the new node, owner there (§3.2, §3.3).
    const min: Role = ownersFromAbove(e.state, e.authorId) ? "owner" : "editor";
    if (atLeast(chainRole(chain, e.authorId), min)) return { kind: "apply", diffs: [], by: "creator", viaChain: true };
    return unchecked(view.partial ?? "origin");
  }
  if (anchor === null) return unchecked("anchor");
  if ("team" in anchor) {
    // The team's root is the one a verified team key named (the client's pin): a second root anchored to the
    // team, however its genesis is signed, isn't the team's (Task 6b).
    if (!isTeamRoot(world, anchor.team, nodeId)) return unchecked("anchor");
    // A team root is started by a member of Everyone; an owner in it needs an Admin (§4.2).
    // A seq 0 can't be skipped, so a dep that can't be checked is the reason first.
    const stale = staleDep(world, e);
    if (stale) return unchecked(stale);
    const view = viewOf("deps", depsOf(e));
    const min: Role = ownersFromAbove(e.state, e.authorId) ? "owner" : "editor";
    if (!atLeast(teamRole(world, view, anchor.team, e.authorId), min)) return unchecked(view.partial ?? "origin");
    return { kind: "apply", diffs: [], by: "creator", viaChain: false };
  }
  if (anchor.user !== e.authorId || anchor.signPub !== e.authorSignPub) return unchecked("anchor");
  // The anchor is the author: their owner share stands on it (`anchorImplies`); anything else they put in is theirs.
  return { kind: "apply", diffs: [], by: "creator", viaChain: false };
}

/**
 * An unsigned legacy entry: nothing but a state, vouched for by its proof (v4 ids only, checked by `verifyLegacy`).
 * Every other field is fixed, since they all go into its hash: one origin, one head.
 */
function legacyOrigin(world: LogWorld, nodeId: string, e: LogEntry): boolean {
  const root = world.input.legacyRoot;
  const proof: unknown = e.legacyProof;
  return (
    root !== null &&
    Array.isArray(proof) &&
    proof.every((p) => typeof p === "string") &&
    wellFormedState(e.state) &&
    e.prev === null &&
    e.change === "create" &&
    e.supersedes === null &&
    e.nonce === null &&
    e.authorId === "" &&
    e.authorSignPub === "" &&
    e.sig === "" &&
    e.at === "" &&
    Array.isArray(e.skipped) &&
    e.skipped.length === 0 &&
    Array.isArray(e.deps) &&
    e.deps.length === 0 &&
    verifyLegacy({ nodeId, state: e.state }, proof, root)
  );
}

/** A removal or a tighter role: what leaving out a lapsed entry, or a lapsed looser role, looks like. */
const mayDrop = (d: Diff): boolean =>
  d.kind === "remove-share" ||
  d.kind === "remove-group" ||
  d.kind === "remove-link" ||
  ((d.kind === "role" || d.kind === "group-role" || d.kind === "link-role") && ROLE_RANK[d.to] < ROLE_RANK[d.from]);

/** Whether a difference only takes away something (an entry, or a looser role) that doesn't count at `still`. */
function dropsLapsed(d: Diff, still: Map<string, Role>): boolean {
  const key =
    d.kind === "remove-share" || d.kind === "role"
      ? `u:${d.userId}`
      : d.kind === "remove-group" || d.kind === "group-role"
        ? `g:${d.groupId}`
        : d.kind === "remove-link" || d.kind === "link-role"
          ? `l:${d.linkId}`
          : null;
  if (key === null) return false;
  if (d.kind === "role" || d.kind === "group-role" || d.kind === "link-role")
    return ROLE_RANK[d.to] < ROLE_RANK[d.from] && still.get(key) === d.to;
  return !still.has(key);
}

/** Whether a difference only moves the node back to where it is in a view (a writer restoring a lapsed move, §3.3). */
const restoresPlace = (d: Diff, next: State, s: Settled): boolean =>
  d.kind === "move" && next.parentId === s.state.parentId;

/**
 * A later snapshot, judged by its difference from the applied state, in the view its own deps name
 * (§3.2, §3.3): the author's role here and through the ancestors it names, each read as its effective
 * state at the deps named. Leaving out what has lapsed in the "lapse" view, or putting the place back
 * to what it is there, isn't a change. Everything that can only skip it comes first, so a snapshot
 * nobody could have been allowed to make never makes the node unverified.
 */
function judge(world: LogWorld, f: Fold, e: LogEntry): Verdict {
  const v = judgeIn(world, f, e);
  if (v.kind !== "apply" || e.change !== "checkpoint" || f.st === null) return v;
  // §8.1: also owner on the prefix minus the counted removals, in its own deps view, so nobody they
  // removed or demoted checkpoints themselves back.
  const views = [viewOf("deps", depsOf(e))];
  return ownsGuard(world, f.ns.nodeId, f.st, f.ns.stretchRemovals.restricted, e.authorId, views) ? v : SKIP;
}

/** `judge` without the checkpoint's guard check. */
function judgeIn(world: LogWorld, f: Fold, e: LogEntry): Verdict {
  const ns = f.ns;
  const prev = f.v.applied;
  if (e.legacyProof !== undefined) return SKIP;
  if (!wellFormedSnapshot(e) || e.nodeId !== ns.nodeId || e.change === "create" || !sigOk(e)) return SKIP;
  let base = prev;
  if (e.change === "checkpoint") {
    // §8.1: it names the head it follows; its version is above the stretch's floor and at most the
    // floor plus its seq (a window: devices whose floors differ by whom they resolve still accept the
    // same checkpoint, and no version can jump out of reach; writers use floor + 1), with a new commit,
    // which then shows as a re-key; and its state fits the counted removals. A client that saw no
    // stretch judges it as an owner's re-key from the state it has.
    // The floor is the state's own version while verified (`applySnapshot`), the stretch's while not.
    const bound = ns.stretchVersion;
    if (e.supersedes !== e.prev || e.state.version <= bound || e.state.version > bound + e.seq) return SKIP;
    if (!fitsRemovals(e.state, ns.stretchRemovals)) return SKIP;
    base = { ...prev, version: e.state.version - 1 };
  }
  // Monotonic deps (§4.4): never older than one an applied snapshot named, nor, for a checkpoint, one in the stretch (§8.1).
  for (const d of e.deps) {
    const had = Math.max(ns.deps.get(d.log)?.seq ?? -1, f.st?.deps.get(d.log) ?? -1);
    if (d.seq < had) return SKIP;
  }
  const diffs = diffStates(base, e.state);
  if (diffs.some((d) => d.kind === "illegal")) return SKIP;

  const deps = depsOf(e);
  const leave = e.change === "leave";
  const view = viewOf("deps", deps);
  const here = settleIn(world, view, ns.nodeId, f.v);
  const role = authorityIn(here, e.authorId);
  // How the author's role, what the view couldn't judge (`partial`) and what the difference needs decide
  // (`judgeDiffs`):
  //   role >= needed, anything partial   -> apply        (an owner reads everything; nothing named could add to it)
  //   role <  needed, partial === null   -> skip         (every log named was read, and it isn't enough)
  //   role <  needed, partial !== null   -> unchecked    (a log named couldn't be read; it might have been enough)
  //   leave                              -> no role needed, so never partial
  // `couldBe`: whether an unreadable log could make the snapshot apply at all; false means it skips, since a
  // snapshot nobody could have been allowed to make never makes the node unverified.
  const partial = role === "owner" ? null : view.partial;
  const couldBe = leave || atLeast(role, "editor") || partial !== null;
  const viaChain = !atLeast(ownAuthorityIn(here, e.authorId), "editor");

  const decide = (ds: Diff[]) => judgeDiffs(world, f, e, ds, view, role, partial, viaChain);
  if (diffs.some((d) => mayDrop(d) || d.kind === "move" || d.kind === "restrict" || d.kind === "unrestrict")) {
    // What the snapshot leaves out that has lapsed or is void in the "lapse" view isn't a change. Lifting a
    // restriction takes its anchors with it: an owner share only the restriction vouched for is lapsed in the
    // lifted reading (`lifting`), so an unrestrict that leaves it out removes nothing.
    const lifts = diffs.some((d) => d.kind === "unrestrict");
    const reading = (loose: boolean) => {
      const lv = viewOf("lapse", deps, loose);
      const there = settleIn(world, lv, ns.nodeId, lifts ? lifting(f.v) : f.v);
      const filtered = diffs.filter((d) => !dropsLapsed(d, there.counted) && !restoresPlace(d, e.state, there));
      const groupsOnly = [...lv.reasons].every((r) => GROUP_REASONS.has(r));
      return { partial: lv.partial, groupsOnly, filtered };
    };
    const strict = reading(false);
    if (strict.partial === null) return decide(strict.filtered);
    if (!strict.groupsOnly) return couldBe ? unchecked(strict.partial) : SKIP;
    // A group or team it names that the client can't check: judged with it giving nothing and with it
    // giving everything. If both readings agree, so does every one in between.
    const loose = reading(true);
    if (!loose.groupsOnly && loose.partial !== null) return couldBe ? unchecked(loose.partial) : SKIP;
    const a = decide(strict.filtered);
    return a.kind === decide(loose.filtered).kind ? a : unchecked(strict.partial);
  }
  return decide(diffs);
}

/** The rest of `judge`, for one reading of the difference. */
function judgeDiffs(
  world: LogWorld,
  f: Fold,
  e: LogEntry,
  diffs: Diff[],
  view: View,
  role: Role | null,
  partial: string | null,
  viaChain: boolean,
): Verdict {
  const ns = f.ns;
  const leave = e.change === "leave";
  if (leave) {
    const own = diffs.length === 1 && diffs[0]?.kind === "remove-share" && diffs[0].userId === e.authorId;
    if (!own) return SKIP;
  } else if (diffs.some(isRemoval) && !diffs.some((d) => d.kind === "rekey")) return SKIP;

  // A leave needs no role: it only takes the author's own share away.
  let min: Role | null = leave ? null : e.change === "checkpoint" ? "owner" : "editor";
  let elsewhere: string | null = null;
  for (const d of diffs) {
    const n = needs(d);
    if (n === null) return SKIP;
    if (min !== null && ROLE_RANK[n] > ROLE_RANK[min]) min = n;
    // A move into a restricted area the node wasn't in swaps every role it inherits for the area's: removing
    // people and granting owner, so it needs owner on the node, as a restrict does (§3.2, §5.3).
    if (d.kind === "move" && min !== null && entersRestricted(world, view, ns.nodeId, e.state, d.from, d.to))
      min = "owner";
    // A move, and unrestricting below a parent, also need editor on that parent, in the same root (§3.2, §5.3).
    const place =
      d.kind === "move"
        ? placeCheck(world, view, ns.nodeId, d.from, d.to, e.authorId)
        : d.kind === "unrestrict" && e.state.parentId !== null
          ? placeCheck(world, view, ns.nodeId, e.state.parentId, e.state.parentId, e.authorId)
          : null;
    if (place?.kind === "skip") return SKIP;
    if (place?.kind === "unchecked") elsewhere ??= place.reason;
  }
  const enough = min === null || atLeast(role, min);
  if (!enough && partial === null) return SKIP;

  if (!authorResolves(world, e)) return unchecked("identity");
  const stale = staleDep(world, e);
  if (stale) return unchecked(stale);
  if (!enough) return unchecked(partial as string);
  return elsewhere ? unchecked(elsewhere) : { kind: "apply", diffs, by: "author", viaChain };
}

/**
 * The restricted area a chain ends in: its nearest restricted node, null when it reaches the root with none, or
 * undefined when it stops short of both (a gap in the logs named).
 */
function areaOf(chain: { ids: string[]; states: State[] }): string | null | undefined {
  const last = chain.states.at(-1);
  if (last === undefined) return undefined;
  if (last.restricted) return chain.ids.at(-1);
  return last.parentId === null ? null : undefined;
}

/**
 * Whether moving the (open) node from `from` to `to` takes it into a restricted area it wasn't in, read in the
 * snapshot's view. One the view can't tell counts as entering: the move then needs owner, never less.
 */
function entersRestricted(
  world: LogWorld,
  view: View,
  nodeId: string,
  next: State,
  from: string | null,
  to: string | null,
): boolean {
  if (next.restricted || to === null) return false;
  const into = areaOf(chainOf(world, view, nodeId, to));
  if (into === null) return false;
  return into === undefined || into !== areaOf(chainOf(world, view, nodeId, from));
}

/**
 * Placing the node under `to`, coming from `from` (the same for an unrestrict): editor on `to`, named
 * in the deps and read in the snapshot's view (§3.2), and the place rules (§5.3). What can only skip
 * comes first. Null: allowed as far as this goes.
 */
function placeCheck(
  world: LogWorld,
  view: View,
  nodeId: string,
  from: string | null,
  to: string | null,
  author: string,
): Verdict | null {
  const rules = placeRules(world, nodeId, from, to);
  if (rules === SKIP) return SKIP;
  if (to === null || !view.deps.has(to)) return unchecked("needs-parent");
  const before = view.partial;
  const chain = chainOf(world, view, nodeId, to);
  if (!atLeast(chainRole(chain, author), "editor"))
    return view.partial !== before && view.partial !== null ? unchecked(view.partial) : SKIP;
  return rules;
}

/**
 * The place rules (§5.3): a root never moves, and nothing becomes one; `to` is in the same root as the
 * node and the place it comes from (every place it ever had, so also the one a lapsed move falls back
 * to, §3.3); and `to` isn't the node or anything that was ever placed below it (`mayBeBelow`), so no
 * two moves make a loop. A root that can't be found yet (a log not shown) can't be checked.
 */
function placeRules(world: LogWorld, nodeId: string, from: string | null, to: string | null): Verdict | null {
  if (from === null || to === null) return SKIP;
  if (world.mayBeBelow(to, nodeId)) return SKIP;
  const root = world.rootOf(nodeId);
  // Redundant with `from === null` (a root's applied parent is always null), kept as a guard.
  if (root === nodeId) return SKIP;
  const roots = [world.rootOf(to), world.rootOf(from)];
  if (root !== null && roots.some((r) => r !== null && r !== root)) return SKIP;
  return root === null || roots.includes(null) ? unchecked("needs-parent") : null;
}

/**
 * Why an entry isn't a well-formed origin of the node, or null: its id, nonce, version and key
 * commit as a seq 0 needs them (§3.4), and a parent or an anchor but not both (§4.2); a legacy one
 * by its proof (§7). Signature and author aren't checked here.
 */
function originFault(world: LogWorld, nodeId: string, e: unknown): string | null {
  if (!isObj(e) || e.nodeId !== nodeId) return "origin";
  const s = e as LogEntry;
  if (s.legacyProof !== undefined) return legacyOrigin(world, nodeId, s) ? null : "legacy";
  if (!wellFormedSnapshot(s)) return "origin";
  if (s.change !== "create" || s.nonce === null || s.state.version !== 1 || s.state.keyCommit === null) return "origin";
  if (!firstIdMatches(s)) return "id";
  if (s.state.parentId !== null && s.state.anchor !== null) return "anchor";
  return null;
}

/**
 * The entry keys a root's anchor itself implies (§4.2): a team root's shares with the team's Everyone at editor
 * and Admins at owner (as the client's verified team view names them), a personal root's own owner share. Nothing
 * for a root whose team the view can't name; a share of those groups at any other role is the author's.
 */
function anchorImplies(world: LogWorld, s: State): Set<string> {
  const out = new Set<string>();
  const a = s.anchor;
  if (a === null) return out;
  if ("user" in a) {
    if (s.shares.some((x) => x.userId === a.user && x.role === "owner")) out.add(`u:${a.user}`);
    return out;
  }
  let tg: { everyone: string; admins: string } | null = null;
  try {
    tg = world.input.groups.teamGroups(a.team);
  } catch {
    tg = null;
  }
  if (tg === null) return out;
  // Exactly Admins at owner and Everyone at editor (§4.2): the same group at another role is the author's entry.
  for (const g of s.groupShares)
    if ((g.groupId === tg.admins && g.role === "owner") || (g.groupId === tg.everyone && g.role === "editor"))
      out.add(`g:${g.groupId}`);
  return out;
}

/**
 * The state a node's seq 0 gives it, if that entry is a well-formed origin of it (`originFault`).
 * Who signed it isn't checked: only where the node started is asked, and the id or proof fixes that.
 * Null if the log wasn't shown or its first entry isn't its origin.
 */
export function originState(world: LogWorld, nodeId: string): State | null {
  const entries = world.input.logs.get(nodeId);
  const e: unknown = Array.isArray(entries) ? entries[0] : undefined;
  try {
    return originFault(world, nodeId, e) === null ? (e as LogEntry).state : null;
  } catch {
    return null;
  }
}

/** Signature verdicts, per entry object: the fold and `signedEntry` check the same entries. */
const sigs = new WeakMap<object, boolean>();
const sigOk = (e: Snapshot): boolean => {
  let ok = sigs.get(e);
  if (ok === undefined) {
    ok = verifySnapshotSig(e);
    sigs.set(e, ok);
  }
  return ok;
};

/**
 * Whether an entry at `seq` of the log is one its author could have made: well formed, of this log,
 * validly signed by a key this account resolves to its author (§6.1); at seq 0 also a well-formed
 * origin, and a legacy one only by a valid proof and an anchor key that resolves (as `judgeOrigin`
 * asks). Whether the author was allowed isn't asked.
 */
export function signedEntry(world: LogWorld, log: string, seq: number, e: unknown): boolean {
  if (!isObj(e) || e.seq !== seq) return false;
  const s = e as LogEntry;
  try {
    if (seq === 0)
      return (
        originFault(world, log, s) === null &&
        (s.legacyProof !== undefined ? anchorResolves(world, s.state) : sigOk(s) && authorResolves(world, s))
      );
    return (
      s.legacyProof === undefined && wellFormedSnapshot(s) && s.nodeId === log && sigOk(s) && authorResolves(world, s)
    );
  } catch {
    return false;
  }
}

/**
 * Applies a snapshot: its state becomes the applied one and every entry, and its place, gain its
 * author as a voucher (§3.3); its judged removals and demotions (not what it left out as lapsed) are
 * kept against a lift, for when that lapses. A creation or a re-key becomes the current key; a removal
 * without one (a leave, or a lapsed or void entry left out) is remembered against it, for `isStale`.
 */
function applySnapshot(world: LogWorld, f: Fold, s: Snapshot, v: Verdict & { kind: "apply" }): void {
  // Leaving out a lapsed or void entry isn't a removal, but whoever it was may still have the key.
  const removes = diffStates(f.v.applied, s.state).some(isRemoval);
  const ns = f.ns;
  ns.stretchVersion = s.state.version;
  for (const d of s.deps) {
    const had = ns.deps.get(d.log);
    if (!had || d.seq > had.seq) ns.deps.set(d.log, { seq: d.seq, head: d.head });
  }
  // A root's genesis: the entries its anchor implies (a team root's Everyone and Admins, a personal root's owner)
  // stand on the anchor, not on the creator's vouching, who may leave the team (§4.2); anything else the creator
  // put in the genesis is theirs, and lapses with them (§3.3). The key is still the creator's (`track`, stale.ts).
  const genesis = s.seq === 0 && s.state.parentId === null && v.by !== "origin";
  const v2 = vouch(
    f.v,
    s.state,
    v.by === "origin" ? "" : s.authorId,
    v.diffs,
    genesis ? anchorImplies(world, s.state) : undefined,
  );
  f.v = { ...v2, deps: new Map([...ns.deps].map(([log, d]) => [log, d.seq])) };
  const t = f.track;
  if (v.by !== "author" || v.diffs.some((d) => d.kind === "rekey")) {
    const by = v.by === "origin" ? null : s.authorId;
    f.track = { key: { state: s.state, by, viaChain: v.viaChain, since: depsOf(s) }, dropped: false };
  } else if (t.key) {
    // Only a log this snapshot brings in gets a floor from it: a later dep on one the key had says
    // nothing about where it stood when the key was made (a removal in between still counts).
    const since = new Map(t.key.since);
    const deps = depsOf(s);
    const bring = (log: string) => {
      const d = deps.get(log);
      if (d && !since.has(log)) since.set(log, d);
    };
    // A move brings in its whole new chain: every log it names that the key didn't.
    if (v.diffs.some((d) => d.kind === "move")) for (const log of deps.keys()) bring(log);
    for (const d of v.diffs) if (d.kind === "add-group") bring(`group:${d.groupId}`);
    f.track = { key: { ...t.key, since }, dropped: t.dropped || removes || s.change === "leave" };
  }
}
