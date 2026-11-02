import { toBase64Url } from "@jelly/crypto";
import type { UnlockedAccount } from "../account.ts";
import type { B64, Role } from "../wire.ts";
import { writable } from "./accept.ts";
import { settleIn, viewOf, vouch } from "./authority.ts";
import { hasOwner } from "./diff.ts";
import { createSnapshot, snapshotHash, stateFields } from "./encode.ts";
import { appliedOf, prefixOf, stretchOf } from "./fold.ts";
import { fitsRemovals } from "./stretch.ts";
import type { Dep, NodeState, ShareEntry, Snapshot, State } from "./types.ts";
import { authorityDeps, LogWorld } from "./world.ts";

/**
 * The new key a removal, restrict, re-key or checkpoint brings (§3.2): its version (the effective one
 * plus one; for a checkpoint the stretch's floor plus one, §8.1), its commit (`commitOf`, accept.ts), and
 * the members the server reports deleted, left in the state but not sealed to (§5.5).
 */
export type RekeyInput = { version: number; keyCommit: B64; skipped?: string[] };

/** What a client asks of a node (§3.6); never a state it holds. */
export type Intent =
  | { add: ShareEntry }
  | { remove: string; rekey: RekeyInput }
  | { leave: true }
  | { role: { userId: string; role: Role } }
  | { addGroup: { groupId: string; role: Role } }
  | { removeGroup: { groupId: string; rekey: RekeyInput } }
  | { addLink: { linkId: string; role: Role } }
  | { removeLink: { linkId: string; rekey: RekeyInput } }
  | { move: string }
  | { restrict: Restriction }
  | { unrestrict: string }
  | { rekey: RekeyInput }
  | { checkpoint: { state: State; rekey: RekeyInput } };

/**
 * A restriction as one signed change (§3.3): the restricted state shares with exactly these people, groups and
 * links. Someone new is added and a role changed in the same snapshot, judged on the restrictor's authority (an
 * owner), so nobody is ever on the open item first; the author is made owner. A link is only kept, never added:
 * one the state no longer carries stays gone.
 */
export type Restriction = {
  shares: ShareEntry[];
  groups: { groupId: string; role: Role }[];
  links: string[];
  rekey: RekeyInput;
};

/**
 * Why an intent doesn't apply. `code` names the cases an app acts on without reading `why`: "sole_owner" (the change
 * would leave a restricted node with no owner: the app offers a hand-over).
 */
export type NotApplicable = { error: "not-applicable"; why: string; code?: NotApplicableCode };
export type NotApplicableCode = "sole_owner";

/** Who is writing: their id and the signing key the snapshot will carry. */
export type Author = { userId: string; signPub: B64 };

const no = (why: string, code?: NotApplicableCode): NotApplicable =>
  code ? { error: "not-applicable", why, code } : { error: "not-applicable", why };

/** The re-key an intent carries, if any. */
function rekeyOf(intent: Intent): RekeyInput | null {
  if ("rekey" in intent) return intent.rekey;
  if ("removeGroup" in intent) return intent.removeGroup.rekey;
  if ("removeLink" in intent) return intent.removeLink.rekey;
  if ("restrict" in intent) return intent.restrict.rekey;
  if ("checkpoint" in intent) return intent.checkpoint.rekey;
  return null;
}

/** The state one version up with the new commit, or why the re-key doesn't fit it. */
function stepKey(s: State, from: number, rekey: RekeyInput): State | string {
  if (rekey.version !== from + 1) return `version: the node is at ${from}, the re-key must be ${from + 1}`;
  if (typeof rekey.keyCommit !== "string" || rekey.keyCommit === "" || rekey.keyCommit === s.keyCommit)
    return "commit: a re-key needs a new key commit";
  return { ...s, version: rekey.version, keyCommit: rekey.keyCommit };
}

/** Why the node can't be placed under `to` (§5.3), as far as the client can tell; the fold checks the rest. */
function placeFault(world: LogWorld, nodeId: string, to: string): string | null {
  if (to === nodeId) return "move: a node can't be its own parent";
  if (world.mayBeBelow(to, nodeId)) return "move: that would make a loop (the new parent was placed below this node)";
  const root = world.rootOf(nodeId);
  const dest = world.rootOf(to);
  if (root !== null && dest !== null && root !== dest) return "move: the new parent is in another root";
  return null;
}

/** Whether `next` takes the last owner from a restricted node (diff.ts `illegal("owner")`): a restrict keeps one; one already without (legacy data) isn't held to it. */
const dropsLastOwner = (prev: State, next: State): boolean =>
  next.restricted && next.parentId !== null && !hasOwner(next) && (hasOwner(prev) || !prev.restricted);

/** The checkpoint's state (§8.1): the caller's (from `checkpointPrefill` and what the owner confirmed) at the floor plus one, with its new commit. */
function checkpoint(ns: NodeState, c: { state: State; rekey: RekeyInput }): State | NotApplicable {
  const s = stepKey(c.state, ns.stretchVersion, c.rekey);
  if (typeof s === "string") return no(`checkpoint ${s.replace("the node is at", "the stretch reached")}`);
  if (s.kind !== ns.state.kind) return no("checkpoint: kind can't change");
  if (!fitsRemovals(s, ns.stretchRemovals))
    return no("checkpoint: names someone the stretch removed, above their role, or unrestricts");
  if (dropsLastOwner(ns.state, s)) return no("checkpoint: a restricted node keeps an owner", "sole_owner");
  return s;
}

/**
 * The state an intent asks for, from the node's **effective** state only (§3.6), or why it doesn't
 * apply: the person is already there or already gone, the version moved on (the caller makes a new key
 * and re-key input), the node is unverified (only a checkpoint applies then), rolled back (nothing
 * does), or stale (only a re-key, a removal carrying one, or a leave, §5.2). A restricted state keeps
 * an owner: a restrict makes the author one (their restrict and their share are one fact), and a
 * removal, demotion or leave that would leave none is refused, as the fold skips it. The place rules
 * the client can check before signing (§5.3, the conservative loop rule) are checked here too. An
 * unrestrict drops the owner entries only the restriction vouched for (§3.3): the fold reads them as
 * lapsed with it, not removed, and brings them back should the lift lapse.
 */
export function applyIntent(world: LogWorld, ns: NodeState, intent: Intent, author: Author): State | NotApplicable {
  const w = writable(ns);
  if ("checkpoint" in intent) {
    if (ns.status.kind !== "unverified")
      return no(`checkpoint: the node is ${w === "rolled-back" ? "rolled back" : "verified"}`);
    return checkpoint(ns, intent.checkpoint);
  }
  // A rolled-back node takes nothing, a checkpoint included: the server showed an older state than this device
  // verified (§5.4), so the head to chain on isn't trusted until the user accepts it and the floor is reset.
  if (w === "rolled-back") return no("rolled back: accept the server's state first");
  if (w === "unverified") return no("unverified: only an owner's checkpoint applies");
  const rekey = rekeyOf(intent);
  if (w === "stale" && rekey === null && !("leave" in intent)) return no("stale: re-key first");
  const s = ns.state;
  let next: State = { ...s, shares: [...s.shares], groupShares: [...s.groupShares], links: [...s.links] };
  if (rekey !== null) {
    const r = stepKey(next, s.version, rekey);
    if (typeof r === "string") return no(r);
    next = r;
  }
  const shareOf = (userId: string) => next.shares.find((x) => x.userId === userId);
  if ("add" in intent) {
    if (shareOf(intent.add.userId)) return no("already shared with them");
    next.shares.push({ userId: intent.add.userId, role: intent.add.role, signPub: intent.add.signPub });
  } else if ("remove" in intent) {
    if (!shareOf(intent.remove)) return no("they are not shared with any more");
    next.shares = next.shares.filter((x) => x.userId !== intent.remove);
  } else if ("leave" in intent) {
    if (!shareOf(author.userId)) return no("no share of yours here to leave");
    next.shares = next.shares.filter((x) => x.userId !== author.userId);
  } else if ("role" in intent) {
    const had = shareOf(intent.role.userId);
    if (!had) return no("they are not shared with any more");
    if (had.role === intent.role.role) return no(`they are already ${had.role}`);
    next.shares = next.shares.map((x) => (x.userId === intent.role.userId ? { ...x, role: intent.role.role } : x));
  } else if ("addGroup" in intent) {
    if (next.groupShares.some((x) => x.groupId === intent.addGroup.groupId))
      return no("already shared with that group");
    next.groupShares.push({ groupId: intent.addGroup.groupId, role: intent.addGroup.role });
  } else if ("removeGroup" in intent) {
    const id = intent.removeGroup.groupId;
    if (!next.groupShares.some((x) => x.groupId === id)) return no("not shared with that group any more");
    next.groupShares = next.groupShares.filter((x) => x.groupId !== id);
  } else if ("addLink" in intent) {
    if (next.links.some((x) => x.linkId === intent.addLink.linkId)) return no("that link already exists");
    next.links.push({ linkId: intent.addLink.linkId, role: intent.addLink.role });
  } else if ("removeLink" in intent) {
    const id = intent.removeLink.linkId;
    if (!next.links.some((x) => x.linkId === id)) return no("that link is gone already");
    next.links = next.links.filter((x) => x.linkId !== id);
  } else if ("move" in intent) {
    if (next.parentId === null) return no("move: a root doesn't move");
    if (intent.move === next.parentId) return no("move: already there");
    const fault = placeFault(world, ns.nodeId, intent.move);
    if (fault !== null) return no(fault);
    next.parentId = intent.move;
  } else if ("restrict" in intent) {
    if (next.restricted) return no("already restricted");
    const r = intent.restrict;
    const once = <T>(xs: T[], id: (x: T) => string) => new Set(xs.map(id)).size === xs.length;
    if (!once(r.shares, (x) => x.userId)) return no("restrict: each person is named once");
    if (!once(r.groups, (x) => x.groupId)) return no("restrict: each group is named once");
    next.restricted = true;
    // Someone already on it keeps the key the state names them by (a hint only, §6.1); the role is the one asked.
    next.shares = r.shares.map((x) => {
      const had = shareOf(x.userId);
      return { userId: x.userId, role: x.role, signPub: had ? had.signPub : x.signPub };
    });
    next.groupShares = r.groups.map((x) => ({ groupId: x.groupId, role: x.role }));
    const links = new Set(r.links);
    next.links = next.links.filter((x) => links.has(x.linkId));
    const mine = shareOf(author.userId);
    if (!mine) next.shares.push({ userId: author.userId, role: "owner", signPub: author.signPub });
    else if (mine.role !== "owner") next.shares = next.shares.map((x) => (x === mine ? { ...x, role: "owner" } : x));
  } else if ("unrestrict" in intent) {
    if (!next.restricted) return no("not restricted");
    if (next.parentId === null) return no("unrestrict: a root has no parent to open to");
    if (intent.unrestrict !== next.parentId) {
      const fault = placeFault(world, ns.nodeId, intent.unrestrict);
      if (fault !== null) return no(fault);
      next.parentId = intent.unrestrict;
    }
    next.restricted = false;
    // The owners the restriction alone vouched for go with it (§3.3): on the open node they count only if someone
    // with owner authority through the parent (the lifter included) vouches for them. Settling the lift as the fold
    // will drops or lowers exactly those; the fold reads them as lapsed with the restriction, not removed.
    const v = prefixOf(ns, ns.seq)?.vouched;
    if (v) {
      const { counted } = settleIn(world, viewOf("now"), ns.nodeId, vouch(v, next, author.userId));
      const keep = <T extends { role: Role }>(xs: T[], key: (x: T) => string): T[] =>
        xs.flatMap((x) => {
          if (x.role !== "owner") return [x];
          const r = counted.get(key(x));
          return r === undefined ? [] : r === x.role ? [x] : [{ ...x, role: r }];
        });
      next.shares = keep(next.shares, (x) => `u:${x.userId}`);
      next.groupShares = keep(next.groupShares, (x) => `g:${x.groupId}`);
    }
  }
  if (dropsLastOwner(s, next)) return no("a restricted node keeps an owner", "sole_owner");
  return next;
}

/**
 * The deps the snapshot names (§3.3, §4.4): `authorityDeps` (every place the node has held with its
 * chain, and every group along the way: where the author's role, every voucher and the lapsed or void
 * entries it leaves out are judged), the new parent of a move or unrestrict with its chain, and a
 * group it newly shares with (so the key's floor on it is known, §5.2). For a checkpoint, each must be
 * no older than the stretch's floor on that log (§8.1), else the writer refreshes first.
 */
function depsFor(world: LogWorld, ns: NodeState, intent: Intent): Dep[] | { error: string } {
  const out = new Map<string, Dep>();
  const add = (d: Dep) => {
    const had = out.get(d.log);
    if (!had || d.seq > had.seq) out.set(d.log, d);
  };
  for (const d of authorityDeps(world, ns.nodeId)) add(d);
  const to =
    "move" in intent
      ? intent.move
      : "unrestrict" in intent
        ? intent.unrestrict
        : "checkpoint" in intent && intent.checkpoint.state.parentId !== ns.state.parentId
          ? intent.checkpoint.state.parentId
          : null;
  if (to !== null) {
    const t = world.state(to);
    if (t && t.seq >= 0) add({ log: to, seq: t.seq, head: t.head });
    for (const d of authorityDeps(world, to)) add(d);
  }
  const groupDep = (id: string) => {
    const l = world.input.groups.latest(id);
    if (l !== null) add({ log: `group:${id}`, seq: l.version, head: l.head });
  };
  if ("addGroup" in intent) groupDep(intent.addGroup.groupId);
  if ("restrict" in intent)
    for (const g of intent.restrict.groups)
      if (!ns.state.groupShares.some((x) => x.groupId === g.groupId)) groupDep(g.groupId);
  const st = stretchOf(ns);
  if (st)
    for (const [log, seq] of st.deps) {
      const have = out.get(log)?.seq ?? -1;
      if (have < seq)
        return {
          error: `refresh ${log}: the stretch names it at ${seq}, this client has ${have < 0 ? "nothing" : have}`,
        };
    }
  return [...out.values()];
}

const sameState = (a: State, b: State): boolean => JSON.stringify(stateFields(a)) === JSON.stringify(stateFields(b));

/**
 * The next snapshot of the node for an intent (§3.6), signed by the account: `applyIntent`, then the seq
 * and `prev` from the fold, deps from `depsFor`, `change` from the intent (`leave`, `checkpoint`, else
 * `change`), `supersedes` the head for a checkpoint, `skipped` from the re-key. Before returning it, the
 * candidate is folded here, appended to the log this client has: it is returned only if the fold
 * applies it (not skipped, not left unchecked), verifies the node, and reaches exactly its state. So
 * nothing is ever signed that other clients would skip, which is what a writer whose role source
 * isn't in its deps, or whose move the loop rule refuses, would otherwise do silently.
 *
 * Writers use only this. On a refused append (another snapshot won the race) they refetch, fold, and
 * call it again on the new head, which re-applies the intent to what the winner left (a `leave` isn't
 * undone) or reports that it no longer applies. Before a checkpoint, the caller refreshes every log the
 * stretch names (core can't fetch): a dep older than another client's view makes them skip it (§11).
 * `ns` must be `world.state(ns.nodeId)`; the account's own key must resolve "ok" in `world.input.identity`.
 */
export function nextSnapshot(
  account: UnlockedAccount,
  world: LogWorld,
  ns: NodeState,
  intent: Intent,
  at: string,
): Snapshot | { error: string; code?: NotApplicableCode } {
  const author: Author = { userId: account.userId, signPub: toBase64Url(account.signing.publicKey) };
  const state = applyIntent(world, ns, intent, author);
  if ("error" in state) return { error: `${state.error}: ${state.why}`, ...(state.code ? { code: state.code } : {}) };
  if (ns.seq < 0 || ns.head === "") return { error: "nothing to chain on: the log has no checkable entry" };
  const deps = depsFor(world, ns, intent);
  if ("error" in deps) return deps;
  const isCheckpoint = "checkpoint" in intent;
  let candidate: Snapshot;
  try {
    candidate = createSnapshot(account, {
      nodeId: ns.nodeId,
      seq: ns.seq + 1,
      prev: ns.head,
      state,
      change: "leave" in intent ? "leave" : isCheckpoint ? "checkpoint" : "change",
      supersedes: isCheckpoint ? ns.head : null,
      skipped: [...(rekeyOf(intent)?.skipped ?? [])],
      nonce: null,
      deps,
      at,
    });
  } catch (e) {
    return { error: `can't sign: ${e instanceof Error ? e.message : String(e)}` };
  }
  return foldsAsMeant(world, ns, candidate);
}

/** The candidate, if the fold of this client's logs with it appended applies it and verifies the node at exactly its state; else why not. */
function foldsAsMeant(world: LogWorld, ns: NodeState, candidate: Snapshot): Snapshot | { error: string } {
  try {
    const logs = new Map(world.input.logs);
    const shown = logs.get(ns.nodeId) ?? [];
    logs.set(ns.nodeId, [...shown.slice(0, ns.seq + 1), candidate]);
    const after = new LogWorld({ ...world.input, logs }).state(ns.nodeId);
    if (!after) return { error: "refused: the fold shows no state" };
    if (after.seq !== candidate.seq || after.head !== snapshotHash(candidate))
      return { error: "refused: it doesn't chain on the head" };
    if (after.status.kind !== "verified") {
      const why = after.status.kind === "unverified" ? ` (${after.status.reason})` : "";
      return { error: `refused: the fold would leave the node ${after.status.kind}${why}` };
    }
    const applied = appliedOf(after);
    if (!applied || !sameState(applied, candidate.state)) return { error: "refused: the fold would skip it" };
    if (!sameState(after.state, candidate.state)) return { error: "refused: part of it lapses at once" };
    return candidate;
  } catch (e) {
    return { error: `refused: ${e instanceof Error ? e.message : String(e)}` };
  }
}

/**
 * Who made each share link a node's log (as held) carries: the author of the earliest entry that names it (§3.3). A
 * restriction keeps the links of the people who stay (the restrictor and the owners it keeps) and turns off the
 * rest; reading the maker from the signed log, not the server's row, means nobody else can claim one. A link
 * whose earliest entry has no signed author (a legacy seq 0, §7: `authorId` "") has no maker anyone stays as, so
 * a restriction turns it off: fail closed (and such data is wiped at the switch).
 */
export function linkMakers(log: readonly Snapshot[]): Map<string, string> {
  const out = new Map<string, string>();
  for (const e of log) {
    const links = (e as Partial<Snapshot>).state?.links;
    if (!Array.isArray(links)) continue;
    for (const l of links) if (typeof l?.linkId === "string" && !out.has(l.linkId)) out.set(l.linkId, e.authorId);
  }
  return out;
}
