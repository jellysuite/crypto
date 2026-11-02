import { ROLE_RANK, type Role } from "../wire.ts";
import type { View } from "./authority.ts";
import type { Dep, State } from "./types.ts";
import type { LogWorld } from "./world.ts";

/** Reasons a view couldn't read a group or team: the reading is open between "gives nothing" and "gives everything". */
export const GROUP_REASONS = new Set(["needs-group", "needs-team"]);

/** Notes that something the view names couldn't be judged; the first reason is the one reported. */
export function flag(view: View, reason: string): void {
  view.partial ??= reason;
  view.reasons.add(reason);
}

const higher = (a: Role | null, b: Role | null): Role | null =>
  a === null ? b : b === null ? a : ROLE_RANK[a] >= ROLE_RANK[b] ? a : b;

/** Whether the client's verified view of a group can answer for a dep on it (§4.4): shown, not older, same head. */
export function groupDepOk(world: LogWorld, d: Dep): "ok" | "needs-group" | "stale-dependency" {
  const latest = world.input.groups.latest(d.log.slice("group:".length));
  if (latest === null) return "needs-group";
  if (d.seq > latest.version || (d.seq === latest.version && d.head !== latest.head)) return "stale-dependency";
  return "ok";
}

/**
 * The group version a view reads (§4.1, §4.4): "now", the newest verified one; judging a snapshot,
 * the one it names, and none if it names none (a role from a group must be named). In the "lapse"
 * view a group not named is open: the snapshot can't call anything lapsed through it. A named version
 * the client can't check is open in a loose view and gives nothing in a strict one.
 */
function groupAt(world: LogWorld, view: View, groupId: string): number | "open" | null {
  if (view.mode === "now") return world.input.groups.latest(groupId)?.version ?? null;
  const d = view.deps.get(`group:${groupId}`);
  if (!d) return view.mode === "lapse" ? "open" : null;
  if (groupDepOk(world, d) !== "ok") {
    flag(view, "needs-group");
    return view.loose ? "open" : null;
  }
  return d.seq;
}

/** Whether the user is a member of the group at the version the view reads. */
export function inGroup(world: LogWorld, view: View, groupId: string, userId: string): boolean {
  const v = groupAt(world, view, groupId);
  if (v === "open") return true;
  return v !== null && world.input.groups.member(groupId, v, userId) === true;
}

/** A team anchor's role for the user (§4.2): owner for Admins members, editor for Everyone members. */
export function teamRole(world: LogWorld, view: View, teamId: string, userId: string): Role | null {
  const tg = world.input.groups.teamGroups(teamId);
  if (tg === null) {
    if (view.mode === "now") return null;
    flag(view, "needs-team");
    return view.loose ? "owner" : null;
  }
  if (inGroup(world, view, tg.admins, userId)) return "owner";
  if (inGroup(world, view, tg.everyone, userId)) return "editor";
  return null;
}

export const teamOfAnchor = (s: State): string | null =>
  s.parentId === null && s.anchor !== null && "team" in s.anchor ? s.anchor.team : null;

/** The role from the root's team anchor and the groups shared with, given the roles those group shares count at. */
export function groupRole(
  world: LogWorld,
  view: View,
  s: State,
  groups: Iterable<[string, Role]>,
  userId: string,
  from: Role | null,
): Role | null {
  let r = from;
  const team = teamOfAnchor(s);
  if (team !== null && r !== "owner") r = higher(r, teamRole(world, view, team, userId));
  for (const [groupId, role] of groups)
    if ((r === null || ROLE_RANK[role] > ROLE_RANK[r]) && inGroup(world, view, groupId, userId)) r = role;
  return r;
}

/** The team a node belongs to: its root's team anchor, found through the newest states above it. */
export function teamOf(world: LogWorld, nodeId: string, s: State): string | null {
  if (s.parentId === null) return teamOfAnchor(s);
  const seen = new Set([nodeId]);
  for (let next: string | null = s.parentId; next !== null; ) {
    if (seen.has(next)) return null;
    seen.add(next);
    const ns = world.state(next);
    if (!ns) return null;
    if (ns.state.parentId === null) return teamOfAnchor(ns.state);
    next = ns.state.parentId;
  }
  return null;
}

/**
 * The people whose shares on a team item are void (§4.2): a signed Everyone version, no newer than the
 * client's verified one and strictly newer than the node's own dep on Everyone, removes them. So a share
 * given while naming a version that already showed them gone (a guest share) stands. In the "deps"
 * view only a removal at or before the Everyone version the snapshot names counts, and an Everyone it
 * doesn't name counts as the newest (leaving it out is no way to backdate); in the "lapse" view one it
 * doesn't name voids nothing. A missing proof voids nothing, and people who were never members aren't affected.
 */
export function voided(
  world: LogWorld,
  view: View,
  nodeId: string,
  applied: State,
  deps: ReadonlyMap<string, number>,
): Set<string> {
  const out = new Set<string>();
  if (applied.shares.length === 0) return out;
  const team = teamOf(world, nodeId, applied);
  const tg = team === null ? null : world.input.groups.teamGroups(team);
  if (tg === null) return out;
  const latest = world.input.groups.latest(tg.everyone);
  if (latest === null) return out;
  const key = `group:${tg.everyone}`;
  let upTo = latest.version;
  if (view.mode !== "now") {
    const d = view.deps.get(key);
    if (!d) {
      if (view.mode === "lapse") return out;
    } else if (groupDepOk(world, d) !== "ok") {
      flag(view, "needs-group");
      if (view.loose) return out;
    } else upTo = d.seq;
  }
  const floor = deps.get(key) ?? -1;
  for (const s of applied.shares) {
    const r = world.input.groups.removedAt(tg.everyone, s.userId, floor);
    if (typeof r === "number" && r > floor && r <= latest.version && r <= upTo) out.add(s.userId);
  }
  return out;
}
