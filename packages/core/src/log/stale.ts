import { atLeast } from "../wire.ts";
import { chainRole, entriesOf, namedIn, type Settled, stillHolds, viewOf } from "./authority.ts";
import { diffStates, isRemoval } from "./diff.ts";
import { teamOfAnchor } from "./groups.ts";
import type { Dep, NodeState, State } from "./types.ts";
import type { LogWorld } from "./world.ts";

/**
 * What a fold remembers of the node's current key: the state of the snapshot that made it (a creation
 * or the last re-key), who made it (null: the origin's own say, a root by its anchor or a legacy
 * state), whether their role came from the chain above rather than the node itself (`viaChain`), and,
 * per log (a node id or `group:<id>`), its floor: the dep the key named, or, for a log a later snapshot
 * brought in (a group share it added, every log its own move named), the dep that one named. A log
 * with no floor is compared from its start.
 */
export type KeyMark = { state: State; by: string | null; viaChain: boolean; since: Map<string, Dep> };

/** What `isStale` reads of a fold: its key, and whether a removal was applied since without a re-key. */
export type KeyTrack = { key: KeyMark | null; dropped: boolean };

const samePlace = (a: State, b: State): boolean => a.parentId === b.parentId && a.restricted === b.restricted;

/**
 * Whether the node needs a new key before anyone writes (§3.3, §5.2), from its settled state in the
 * "now" view. Every rule is here:
 * - a removal applied since the key without stepping the version: a `leave`, or a lapsed or void entry
 *   left out (whoever it was may still have the key);
 * - a version with no key commit (a legacy state, §5.4);
 * - the key's maker no longer has editor authority now (§3.3), or had it from the chain above and the
 *   chain no longer gives it: a restriction they made is not undone and may keep them owner, but the key
 *   they made on the folder's authority is re-keyed at the next write ("an item an editor made honestly
 *   before leaving");
 * - a void team share still in the applied state (§4.2);
 * - the place fell back (a lapsed move or restrict) from the one the key was made under;
 * - a group shared with here lost a member since the version named at the key;
 * - while unrestricted: a move (the node's or an ancestor's) into a restricted area it wasn't in; or an
 *   ancestor that removed a person, group or link, or restricted, after its floor (seq 0 if the key
 *   didn't name it), or one of whose groups lost a member since.
 * A node nothing was applied to isn't stale: it's unverified, and nobody writes to it anyway.
 */
export function isStale(world: LogWorld, nodeId: string, t: KeyTrack, s: Settled): boolean {
  const key = t.key;
  if (key === null) return false;
  if (t.dropped) return true;
  if (s.state.keyCommit === null) return true;
  if (key.by !== null && !stillHolds(s, key.by, "editor")) return true;
  if (key.by !== null && key.viaChain && !atLeast(chainRole(s.chain, key.by), "editor")) return true;
  if (s.voided.size > 0) return true;
  if (!samePlace(s.state, s.applied) && !samePlace(s.state, key.state)) return true;
  if (groupsLost(world, s.state, key.since)) return true;
  if (s.state.restricted) return false;
  return ancestorsLost(world, nodeId, key, s);
}

/** Whether a group shared with on the state (or its team's groups, on a team root) lost a member since the key. */
function groupsLost(world: LogWorld, state: State, since: Map<string, Dep>): boolean {
  const groups = world.input.groups;
  const ids = state.groupShares.map((g) => g.groupId);
  const team = teamOfAnchor(state);
  const tg = team === null ? null : groups.teamGroups(team);
  if (tg) ids.push(tg.everyone, tg.admins);
  // A group no snapshot since the key named: the key's version is unknown, so any removal counts.
  return ids.some((id) => groups.removedSince(id, since.get(`group:${id}`)?.seq ?? 0));
}

/** Per folded log, the highest seq whose applied state removed something (or restricted) from the one before; -1 if none. */
const lastRemovals = new WeakMap<NodeState, number>();

function lastRemoval(world: LogWorld, id: string): number | null {
  const ns = world.state(id);
  if (!ns) return null;
  let last = lastRemovals.get(ns);
  if (last === undefined) {
    last = -1;
    let prev = world.stateAt(id, 0)?.vouched.applied ?? null;
    for (let seq = 1; seq <= ns.seq; seq++) {
      const cur = world.stateAt(id, seq)?.vouched.applied ?? null;
      if (cur === null) break;
      if (prev !== null && cur !== prev && diffStates(prev, cur).some(isRemoval)) last = seq;
      prev = cur;
    }
    lastRemovals.set(ns, last);
  }
  return last;
}

/**
 * The ancestor rules for an unrestricted node. The chain now is the settled one (newest verified
 * states, up to the first restricted ancestor or the root). Each ancestor in it is compared from its
 * floor: its dep at the key (or the one the snapshot that brought it in named), else its seq 0, since
 * nothing says where it stood when the key was made. Stale if it removed or restricted anything after
 * the floor, if its effective state at the floor has an entry the newest one doesn't, or if one of its
 * groups lost a member since. The chain then is walked from the place the key was made under, each
 * ancestor at its floor; one with none is "unknown where it stood", so ending at a restricted
 * ancestor now is stale. An ancestor's floor state that the key's deps can't fully judge (a gap: its
 * lenient reading differs, or its place was cut) is stale too, rather than read with fewer entries.
 */
function ancestorsLost(world: LogWorld, nodeId: string, key: KeyMark, s: Settled): boolean {
  const view = viewOf("deps", key.since);
  const lenient = viewOf("lapse", key.since);
  const at = (id: string): State | null | undefined => {
    const d = key.since.get(id);
    return d ? namedIn(world, view, id, d) : undefined;
  };
  const gap = (id: string, then: State): boolean => {
    const d = key.since.get(id);
    if (!d) return false;
    if (view.cut.has(id)) return true;
    const open = namedIn(world, lenient, id, d);
    if (open === null) return true;
    const keys = new Set(entriesOf(then).map((x) => x.key));
    return (
      open.parentId !== then.parentId ||
      open.restricted !== then.restricted ||
      entriesOf(open).some((x) => !keys.has(x.key))
    );
  };
  const { ids, states } = s.chain;
  const stop = states[states.length - 1];
  if (stop?.restricted && stop.parentId !== null && !key.state.restricted) {
    // A move into a restricted area: the people above it lose the node.
    const then = new Set<string>();
    const seen = new Set([nodeId]);
    let unknown = false;
    for (let id = key.state.parentId; id !== null && !seen.has(id); ) {
      seen.add(id);
      then.add(id);
      const named = at(id);
      if (named === undefined) unknown = true;
      if (named === undefined || named === null) break;
      id = named.restricted ? null : named.parentId;
    }
    if (unknown || !then.has(ids[ids.length - 1] as string)) return true;
  }
  for (const [i, id] of ids.entries()) {
    const now = states[i] as State;
    const named = at(id);
    if (named === null) return true;
    const floor = key.since.get(id)?.seq ?? 0;
    const then = named ?? world.stateAt(id, 0)?.vouched.applied ?? null;
    const last = lastRemoval(world, id);
    if (then === null || last === null || last > floor) return true;
    if (named && gap(id, named)) return true;
    if (!then.restricted && now.restricted) return true;
    const left = new Set(entriesOf(now).map((x) => x.key));
    if (entriesOf(then).some((x) => !left.has(x.key))) return true;
    if (groupsLost(world, now, key.since)) return true;
  }
  return false;
}
