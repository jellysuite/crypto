import type { Bytes } from "@jelly/crypto";
import type { Grant } from "../grants.ts";
import type { ChildLink } from "../nodes.ts";
import type { GroupGrant } from "../teams.ts";
import { atLeast, type B64, type Role } from "../wire.ts";
import { authorityIn, settleIn, stateRole, type Vouched, viewOf } from "./authority.ts";
import { prefixOf, stretchOf } from "./fold.ts";
import { teamOfAnchor } from "./groups.ts";
import { isLegacyId, keyCommit } from "./ids.ts";
import { minusRemovals, ownsGuard } from "./stretch.ts";
import type { Dep, NodeState, ShareEntry, State } from "./types.ts";
import type { LogWorld, WorldInput } from "./world.ts";

/**
 * The commit a key gives at a version of the node (§3.4): version 1 of a self-certifying node commits
 * with an empty id, since the id is derived from the snapshot that carries the commit.
 */
export const commitOf = (nodeId: string, version: number, key: Bytes): B64 =>
  keyCommit(version === 1 && !isLegacyId(nodeId) ? "" : nodeId, version, key);

/**
 * Whether the key is the one the effective state commits to. A version with no commit (legacy, §5.4)
 * can't be checked here and passes: the grant, group grant or link is still checked for who gave it
 * and to whom, and `writable` calls the node stale, so the first write re-keys it under a commit.
 * `readOnlyKey` is the opposite on null: it has nothing else to go on (an unverified node's prefix
 * state is all it reads), so a version with no commit opens nothing that way.
 */
function matchesCommit(ns: NodeState, key: Bytes): boolean {
  if (ns.state.keyCommit === null) return true;
  try {
    return ns.state.keyCommit === commitOf(ns.nodeId, ns.state.version, key);
  } catch {
    return false;
  }
}

/**
 * Whether the user has `need` on the node at its current version (§5.4, "at that version"): on the
 * effective state now, or on an earlier applied state of the same version, read now or at the deps the
 * node's applied snapshots named (groups at the versions they named), so a grantor who left since (a
 * `leave` steps no version) or whom a group has dropped since (the node is stale, the key the version's)
 * still vouches for the key they legitimately held. Nobody who never had authority at the version does.
 */
function heldAtVersion(world: LogWorld, ns: NodeState, userId: string, need: Role): boolean {
  const named = new Map<string, Dep>();
  for (const [log, d] of ns.deps) named.set(log, { log, seq: d.seq, head: d.head });
  const views = [viewOf("now"), viewOf("deps", named)];
  let last: Vouched | null = null;
  for (let seq = ns.seq; seq >= 0; seq--) {
    const p = prefixOf(ns, seq);
    if (p?.status.kind !== "verified") break;
    if (p.vouched === last) continue;
    last = p.vouched;
    if (p.vouched.applied.version !== ns.state.version) break;
    for (const view of views) {
      try {
        if (atLeast(authorityIn(settleIn(world, view, ns.nodeId, p.vouched), userId), need)) return true;
      } catch {
        // A prefix that can't be read in this view vouches for nobody there.
      }
    }
  }
  return false;
}

/**
 * The authority a grantor needs for a grant to count: share authority, editor (§5.4). The grant's role decides
 * nothing here: the grantee's role is the state's (`world.role`), and the server refuses a grant whose role exceeds
 * what its maker may give. An editor re-keying a node (§5.2) re-seals the owner's share too, with the owner's role on it.
 */
const SHARE_AUTHORITY: Role = "editor";

/**
 * Whether the key may be used to **read** the node's content (§8.2): it matches the commit of the
 * effective state, which on an unverified node is the last verified prefix minus what the stretch
 * removed, so a stretch re-key's commit is never trusted. A version with no commit can't be checked and
 * opens nothing this way. Reading only: writes, re-keys, children, links and shares go through the
 * acceptance checks and `writable`.
 */
export function readOnlyKey(ns: NodeState, key: Bytes): boolean {
  if (ns.state.keyCommit === null) return false;
  try {
    return ns.state.keyCommit === commitOf(ns.nodeId, ns.state.version, key);
  } catch {
    return false;
  }
}

/**
 * Whether the user has a role on the node's own state now: a share, a group share, or a root's anchor
 * (person or team). A group view that throws gives no role: the key helpers never throw.
 */
function hasRole(world: LogWorld, ns: NodeState, userId: string): boolean {
  try {
    return stateRole(world, viewOf("now"), ns.state, userId) !== null;
  } catch {
    return false;
  }
}

/**
 * The team groups a root's anchor reads (§4.2), with the roles they give; empty off a team root, and
 * empty when the group view can't name them (it threw): nothing is accepted or re-issued on a guess.
 */
function anchorGroups(world: LogWorld, s: State): { groupId: string; role: Role }[] {
  const team = teamOfAnchor(s);
  let tg: { everyone: string; admins: string } | null;
  try {
    tg = team === null ? null : world.input.groups.teamGroups(team);
  } catch {
    return [];
  }
  return tg === null
    ? []
    : [
        { groupId: tg.everyone, role: "editor" },
        { groupId: tg.admins, role: "owner" },
      ];
}

/**
 * Whether a grant's key may be used (§5.4): the node is verified, the grant is for it at its current
 * version, the grantee has a role on the effective state (a share, a group, or the root's anchor), the
 * grantor had share authority at that version (editor, also at a version with no commit), and the key
 * matches the commit. The grant's signature is the caller's to check against the grantor's resolved key;
 * the state's `signPub` is only a hint (§6.1). The grant's role isn't compared with the share's, nor does
 * it raise what the grantor needs: roles are the state's, and change without a re-key.
 */
export function acceptGrant(world: LogWorld, ns: NodeState, g: Grant, key: Bytes): boolean {
  if (ns.status.kind !== "verified" || g.nodeId !== ns.nodeId || g.keyVersion !== ns.state.version) return false;
  if (!hasRole(world, ns, g.granteeId)) return false;
  if (!heldAtVersion(world, ns, g.grantorId, SHARE_AUTHORITY)) return false;
  return matchesCommit(ns, key);
}

/** `acceptGrant` for a group's key: the group is in the effective group shares, or is a team root's Everyone or Admins (§4.2). */
export function acceptGroupGrant(world: LogWorld, ns: NodeState, g: GroupGrant, key: Bytes): boolean {
  if (ns.status.kind !== "verified" || g.nodeId !== ns.nodeId || g.keyVersion !== ns.state.version) return false;
  const groups = [...ns.state.groupShares, ...anchorGroups(world, ns.state)];
  if (!groups.some((s) => s.groupId === g.groupId)) return false;
  if (!heldAtVersion(world, ns, g.grantorId, SHARE_AUTHORITY)) return false;
  return matchesCommit(ns, key);
}

/**
 * Whether a child key unwrapped from a link may be used (§5.4): the child is verified, the link names
 * the child at its current version and the parent its effective state places it under, and the key
 * matches the child's commit. A restricted child's key never comes from its parent (§4.1: the parent only
 * says where it is shown). The parent's status isn't asked: whoever holds the parent key gets the
 * child's by the child's own say, and an unrestricted child under an unverified parent is unverified itself.
 */
export function acceptChildLink(
  _world: LogWorld,
  child: NodeState,
  parent: NodeState,
  link: ChildLink,
  key: Bytes,
): boolean {
  if (child.status.kind !== "verified" || child.state.restricted) return false;
  if (link.childId !== child.nodeId || link.parentId !== parent.nodeId) return false;
  if (child.state.parentId !== parent.nodeId || link.childVersion !== child.state.version) return false;
  return matchesCommit(child, key);
}

/** Whether a key unwrapped through a share link may be used (§5.4): the node is verified, the link is in its effective links, and the key matches the commit. */
export function acceptShareLink(ns: NodeState, linkId: string, key: Bytes): boolean {
  if (ns.status.kind !== "verified") return false;
  if (!ns.state.links.some((l) => l.linkId === linkId)) return false;
  return matchesCommit(ns, key);
}

/**
 * Who a re-key seals the new key to (§5.7): everyone in the effective shares and group shares (the
 * effective state already leaves out void team shares, §4.2), a team root's Everyone at editor and
 * Admins at owner, a personal root's anchor at owner (with the anchor's key), and the share links to
 * re-wrap. Empty on a node that isn't verified: nothing is re-issued on its strength (§8.2); a
 * checkpoint seals to its own state instead.
 */
export function reissueSet(
  world: LogWorld,
  ns: NodeState,
): { people: ShareEntry[]; groups: { groupId: string; role: Role }[]; links: { linkId: string; role: Role }[] } {
  if (ns.status.kind !== "verified") return { people: [], groups: [], links: [] };
  const s = ns.state;
  const people = [...s.shares];
  const a = s.anchor;
  if (s.parentId === null && a !== null && "user" in a && !people.some((x) => x.userId === a.user))
    people.push({ userId: a.user, role: "owner", signPub: a.signPub });
  const groups = [...s.groupShares];
  for (const g of anchorGroups(world, s)) if (!groups.some((x) => x.groupId === g.groupId)) groups.push(g);
  return { people, groups, links: [...s.links] };
}

/**
 * Whether the node takes writes (§8.2): "stale" means a re-key comes first (§5.2; a version with no
 * commit counts, §5.4); "unverified" and "rolled-back" take nothing but, for owners, a checkpoint or
 * "accept the server's state".
 */
export function writable(ns: NodeState): "ok" | "stale" | "unverified" | "rolled-back" {
  if (ns.status.kind === "rolled-back") return "rolled-back";
  if (ns.status.kind === "unverified") return "unverified";
  return ns.stale || ns.state.keyCommit === null ? "stale" : "ok";
}

/**
 * The node's effective share entries whose `signPub` hint this account resolves to someone else (§6.1),
 * so the app can show a notice and offer to verify them. The fold never reads a hint, so this changes
 * nothing about who may do what. Only a "mismatch" counts: an "unknown" person is one this account has
 * no resolution for at all (not even first sight), so there is nothing for the hint to disagree with.
 * A resolution that throws reports nothing for that entry.
 */
export function keyHints(ns: NodeState, identity: WorldInput["identity"]): { userId: string; hint: B64 }[] {
  const out: { userId: string; hint: B64 }[] = [];
  for (const s of ns.state.shares) {
    let r: string;
    try {
      r = identity(s.userId, s.signPub);
    } catch {
      continue;
    }
    if (r === "mismatch") out.push({ userId: s.userId, hint: s.signPub });
  }
  return out;
}

/**
 * Whether the user may be offered "verify and re-key" on a node that isn't verified (§8.1, §8.2): an
 * owner on the last verified prefix minus the counted stretch removals (by share, group, anchor or the
 * chain as it reads now), not someone a counted removal removed or demoted, and after a counted
 * restrict only by share or anchor unless they restricted. The app must use this, not `role()`, for
 * the offer: the effective state of an unverified node has every resolvable author's removals applied,
 * so a non-owner's stretch snapshot may have dropped a legitimate owner from it. False on a verified node.
 */
export function canCheckpoint(world: LogWorld, ns: NodeState, userId: string): boolean {
  const st = stretchOf(ns);
  if (st === null) return false;
  try {
    return ownsGuard(world, ns.nodeId, st, ns.stretchRemovals.restricted, userId, [viewOf("now")]);
  } catch {
    return false;
  }
}

/**
 * What "verify and re-key" starts from on an unverified node (§8.1): the last verified state minus
 * everything the stretch removed, demoted or restricted, at the highest version the stretch carried.
 * The caller sets `version` + 1 with a new `keyCommit`, signs it as `change: "checkpoint"` with
 * `supersedes` = `ns.head`, and adds anyone else the server lists only as the owner confirms them by name.
 * With the `author` given, a state that stays restricted keeps their owner share (they may be owner
 * only through the chain, which a restricted node doesn't read), so the node isn't left with no owner.
 */
export function checkpointPrefill(ns: NodeState, author?: { userId: string; signPub: B64 }): State {
  const s: State = { ...minusRemovals(ns.state, ns.stretchRemovals), version: ns.stretchVersion };
  if (author && s.restricted) {
    const others = s.shares.filter((x) => x.userId !== author.userId);
    s.shares = [...others, { userId: author.userId, role: "owner", signPub: author.signPub }];
  }
  return s;
}
