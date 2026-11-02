import { ROLE_RANK, type Role } from "../wire.ts";
import {
  authorityIn,
  type Held,
  ORIGIN,
  type Recs,
  removedSince,
  sameVoucher,
  settleIn,
  type View,
  type Vouched,
  type Voucher,
} from "./authority.ts";
import type { Diff } from "./diff.ts";
import type { State, StretchRemovals } from "./types.ts";
import type { LogWorld } from "./world.ts";

/**
 * What a fold keeps of the stretch after the node went unverified (§3.5, §8.1), on top of the last
 * verified prefix's vouched state, which stays as it was:
 * - `ceil`: the prefix tightened by every removal and demotion a signed, resolvable author made, whatever
 *   their authority: the effective state while unverified is read from it (conservative, read-only);
 * - `guard`: the prefix tightened by the counted removals only (an owner's, judged on the guard so far,
 *   or someone's own leave). A checkpoint's author must be owner on it, so nobody a counted removal
 *   removed or demoted can checkpoint themselves back;
 * - `restrictedBy`: the owners whose counted snapshot restricted the node. Then the chain gives no
 *   authority on the guard, except to them: their restrict and their own share are one fact;
 * - `deps`: the dep floor per log, from snapshots by a resolvable author with at least editor on the
 *   prefix, and only where this client has that head (one gate, so neither a stranger nor one editor
 *   can make repair impossible). The version floor lives on the node state (`NodeState.stretchVersion`,
 *   fold.ts `stretch`): it rises from any signed entry, to a version honest re-keys could have reached
 *   (at most the prefix's version plus the entry's 1-based position, `seen`). A checkpoint is above it
 *   by at most its seq (fold.ts `judgeIn`) and no older than the dep floors.
 */
export type Stretch = {
  ceil: Vouched;
  guard: Vouched;
  restrictedBy: Set<string>;
  deps: Map<string, number>;
  /** Chained entries seen in the stretch so far. */
  seen: number;
};

export const noRemovals = (): StretchRemovals => ({
  userIds: new Set(),
  groupIds: new Set(),
  linkIds: new Set(),
  demoted: new Map(),
  restricted: false,
});

export const startStretch = (prefix: Vouched): Stretch => ({
  ceil: prefix,
  guard: prefix,
  restrictedBy: new Set(),
  deps: new Map(),
  seen: 0,
});

/**
 * Whether the author is an owner on the guard (§8.1): the last verified prefix minus the counted
 * removals, read in any of `views`. After a counted restrict the chain gives nothing, except to whoever
 * restricted: their restrict and their own share are one fact.
 */
export function ownsGuard(
  world: LogWorld,
  nodeId: string,
  st: Stretch,
  restricted: boolean,
  author: string,
  views: View[],
): boolean {
  const owner = (g: Vouched): boolean =>
    views.some((view) => authorityIn(settleIn(world, view, nodeId, g), author) === "owner");
  if (!owner(st.guard)) return false;
  if (!restricted || st.restrictedBy.has(author)) return true;
  return owner(tighten(st.guard, [{ kind: "restrict" }]));
}

/** The parts of a difference that only take something away: an entry, a looser role, or the chain (a restrict). */
export const dropsOf = (diffs: Diff[]): Diff[] =>
  diffs.filter(
    (d) =>
      d.kind === "remove-share" ||
      d.kind === "remove-group" ||
      d.kind === "remove-link" ||
      d.kind === "restrict" ||
      ((d.kind === "role" || d.kind === "group-role" || d.kind === "link-role") && ROLE_RANK[d.to] < ROLE_RANK[d.from]),
  );

const keyOf = (d: Diff): string | null =>
  d.kind === "remove-share" || d.kind === "role"
    ? `u:${d.userId}`
    : d.kind === "remove-group" || d.kind === "group-role"
      ? `g:${d.groupId}`
      : d.kind === "remove-link" || d.kind === "link-role"
        ? `l:${d.linkId}`
        : null;

/** Every voucher an entry has had, at its role now and the roles before: what a tighter role keeps (authority.ts `vouch`). */
function allVouchers(h: Held<Role>): Voucher[] {
  const out: Voucher[] = [];
  for (let r: Held<Role> | null = h; r; r = r.fallback)
    for (const v of r.vouchers) if (!out.some((x) => sameVoucher(x, v))) out.push(v);
  return out;
}

/**
 * The vouched state with `drops` taken out of it: removed entries are gone, a demoted entry keeps every
 * voucher it had at its lower role (as applying a tighter role does), and a restrict stands on the
 * origin's say, so it can't fall back; the drops count against a lift too (`Vouched.removed`). A drop
 * of something that isn't there changes nothing.
 */
export function tighten(v: Vouched, drops: Diff[]): Vouched {
  if (drops.length === 0) return v;
  const applied: State = {
    ...v.applied,
    shares: [...v.applied.shares],
    groupShares: [...v.applied.groupShares],
    links: [...v.applied.links],
  };
  const recs: Recs = new Map(v.recs);
  let place = v.place;
  const lower = <T extends { role: Role }>(list: T[], id: (x: T) => string, who: string, to: Role): T[] =>
    list.map((x) => (id(x) === who && ROLE_RANK[x.role] > ROLE_RANK[to] ? { ...x, role: to } : x));
  const demote = (key: string, to: Role) => {
    const old = recs.get(key);
    if (old && ROLE_RANK[old.value] > ROLE_RANK[to])
      recs.set(key, { value: to, vouchers: allVouchers(old), fallback: null });
  };
  for (const d of drops) {
    switch (d.kind) {
      case "remove-share":
        applied.shares = applied.shares.filter((x) => x.userId !== d.userId);
        recs.delete(`u:${d.userId}`);
        break;
      case "remove-group":
        applied.groupShares = applied.groupShares.filter((x) => x.groupId !== d.groupId);
        recs.delete(`g:${d.groupId}`);
        break;
      case "remove-link":
        applied.links = applied.links.filter((x) => x.linkId !== d.linkId);
        recs.delete(`l:${d.linkId}`);
        break;
      case "role":
        applied.shares = lower(applied.shares, (x) => x.userId, d.userId, d.to);
        demote(`u:${d.userId}`, d.to);
        break;
      case "group-role":
        applied.groupShares = lower(applied.groupShares, (x) => x.groupId, d.groupId, d.to);
        demote(`g:${d.groupId}`, d.to);
        break;
      case "link-role":
        applied.links = lower(applied.links, (x) => x.linkId, d.linkId, d.to);
        demote(`l:${d.linkId}`, d.to);
        break;
      case "restrict":
        applied.restricted = true;
        if (place) place = { ...place, restricted: { value: true, vouchers: [ORIGIN], fallback: place.restricted } };
        break;
      default:
        break;
    }
  }
  return { applied, recs, place, deps: v.deps, removed: removedSince(v.removed, drops) };
}

/** Remembers counted drops for the checkpoint rules and the pre-fill (§8.1). */
export function countDrops(into: StretchRemovals, drops: Diff[]): void {
  for (const d of drops) {
    if (d.kind === "remove-share") into.userIds.add(d.userId);
    else if (d.kind === "remove-group") into.groupIds.add(d.groupId);
    else if (d.kind === "remove-link") into.linkIds.add(d.linkId);
    else if (d.kind === "restrict") into.restricted = true;
    else {
      const key = keyOf(d);
      if (key === null || (d.kind !== "role" && d.kind !== "group-role" && d.kind !== "link-role")) continue;
      const had = into.demoted.get(key);
      if (had === undefined || ROLE_RANK[d.to] < ROLE_RANK[had]) into.demoted.set(key, d.to);
    }
  }
}

/** The state with the counted removals taken out: what a checkpoint may contain at most (§8.1). */
export function minusRemovals(s: State, r: StretchRemovals): State {
  const cap = <T extends { role: Role }>(x: T, key: string): T => {
    const c = r.demoted.get(key);
    return c !== undefined && ROLE_RANK[c] < ROLE_RANK[x.role] ? { ...x, role: c } : x;
  };
  return {
    ...s,
    restricted: s.restricted || r.restricted,
    shares: s.shares.filter((x) => !r.userIds.has(x.userId)).map((x) => cap(x, `u:${x.userId}`)),
    groupShares: s.groupShares.filter((x) => !r.groupIds.has(x.groupId)).map((x) => cap(x, `g:${x.groupId}`)),
    links: s.links.filter((x) => !r.linkIds.has(x.linkId)).map((x) => cap(x, `l:${x.linkId}`)),
  };
}

/** Whether a checkpoint's state contains nobody a counted removal removed, nobody above their counted role, and keeps a counted restriction. */
export function fitsRemovals(s: State, r: StretchRemovals): boolean {
  const m = minusRemovals(s, r);
  return (
    m.restricted === s.restricted &&
    m.shares.length === s.shares.length &&
    m.groupShares.length === s.groupShares.length &&
    m.links.length === s.links.length &&
    m.shares.every((x, i) => x.role === s.shares[i]?.role) &&
    m.groupShares.every((x, i) => x.role === s.groupShares[i]?.role) &&
    m.links.every((x, i) => x.role === s.links[i]?.role)
  );
}
