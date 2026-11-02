import { atLeast, ROLE_RANK, type Role } from "../wire.ts";
import type { Diff } from "./diff.ts";
import { flag, groupRole, voided } from "./groups.ts";
import type { Dep, State, Status } from "./types.ts";
import type { LogWorld } from "./world.ts";

/**
 * Who vouches for a value (§3.3): the author of an applied snapshot that contained it, and the role
 * they needed for it. An empty author is the origin's own say (a root by its anchor, a legacy state),
 * which always holds. With `restriction`, the voucher is the restriction that made the node restricted:
 * the owner entries of that snapshot count while the node is restricted (§3.3, "A restriction anchors
 * its owners"), whatever their authors' standing above. With `before`, the voucher lifted a restriction:
 * their owner authority is read on the state they lifted (`lifted`), whose anchors their own share may
 * have come from, and which the lift may have dropped; if the lift lapses, the node reads as that state.
 */
export type Voucher = { author: string; need: Role; restriction?: true; before?: Vouched };
/** A value, who vouched for it, and the value before it, for when none of them holds any more. */
export type Held<T> = { value: T; vouchers: Voucher[]; fallback: Held<T> | null };
/** Entries' roles by key (`u:`, `g:`, `l:` + id). Never mutated once a fold has moved on. */
export type Recs = Map<string, Held<Role>>;
/**
 * Where the node sits, vouched for like entries, and whether it's restricted. A restriction is not undone
 * (§3.3): it keeps its history of values here, but only the newest counts, and `holds` reads it as the
 * applied state's `restricted`.
 */
export type Place = { parent: Held<string | null>; restricted: Held<boolean> };
/**
 * What a fold keeps of a log at one seq, to read it in any view: the applied state, its vouchers, the
 * highest seq per log its applied snapshots named (a team item's floor on Everyone, §4.2), and, since
 * the newest lift, the entries applied snapshots removed (null) or demoted (to the role): removals never
 * lapse, so a lapsed lift reads as the state it lifted minus these (§3.3, `settleIn`). Empty while restricted.
 */
export type Vouched = {
  applied: State;
  recs: Recs;
  place: Place | null;
  deps: ReadonlyMap<string, number>;
  removed: ReadonlyMap<string, Role | null>;
};
/** A log as its fold stood at one seq. */
export type Prefix = { status: Status; vouched: Vouched };

export const ORIGIN: Voucher = { author: "", need: "viewer" };

export const sameVoucher = (a: Voucher, b: Voucher): boolean =>
  a.author === b.author && a.need === b.need && a.restriction === b.restriction && a.before === b.before;

export const entriesOf = (s: State): { key: string; role: Role }[] => [
  ...s.shares.map((x) => ({ key: `u:${x.userId}`, role: x.role })),
  ...s.groupShares.map((x) => ({ key: `g:${x.groupId}`, role: x.role })),
  ...s.links.map((x) => ({ key: `l:${x.linkId}`, role: x.role })),
];

const higher = (a: Role | null, b: Role | null): Role | null =>
  a === null ? b : b === null ? a : ROLE_RANK[a] >= ROLE_RANK[b] ? a : b;

const lower = (a: Role, b: Role): Role => (ROLE_RANK[a] <= ROLE_RANK[b] ? a : b);

const anchorUser = (s: State): string | null =>
  s.parentId === null && s.anchor !== null && "user" in s.anchor ? s.anchor.user : null;

/** The role a state gives a user by itself, without groups: a root's personal anchor is owner (§4.2), then their share. */
export function ownRole(state: State, userId: string): Role | null {
  if (anchorUser(state) === userId) return "owner";
  return state.shares.find((s) => s.userId === userId)?.role ?? null;
}

/**
 * How other logs are read (§3.3, §4.4):
 * - "now": each ancestor's newest effective state, while verified.
 * - "deps" (judging a snapshot): the chain follows named ancestors only, each at its effective state
 *   in this same view (its applied state at the dep, its vouchers checked at the deps named), whose
 *   parent there is the next one; it ends at the first ancestor not named (§4.4: deps name the whole
 *   stretch up to where the role comes from), so nothing above a gap counts. A place whose move can
 *   be judged neither way through the logs named is a gap too (`settleIn`, `cut`): what the snapshot
 *   left unnamed only ever takes authority away, never adds it.
 * - "lapse" (whether a snapshot may call something lapsed): as "deps", but an ancestor or group not
 *   named may grant anything, since the snapshot can't call anything lapsed through it.
 * Groups are read at the version the view names (groups.ts). `loose`: a named group the client can't
 * check grants everything (else nothing), to bound what it could change. `partial`: the first reason
 * something named couldn't be judged; `reasons`: all of them. `cut`: the logs whose chain, settled in
 * this view, ends at a gap, so a chain through them stops there. `lenient`: the "lapse" reading of the
 * same deps, made when a "deps" view first needs it.
 */
export type View = {
  mode: "now" | "deps" | "lapse";
  deps: Map<string, Dep>;
  loose: boolean;
  named: Map<string, State | null>;
  partial: string | null;
  reasons: Set<string>;
  cut: Set<string>;
  lenient?: View;
};

export const viewOf = (mode: View["mode"], deps: Map<string, Dep> = new Map(), loose = false): View => ({
  mode,
  deps,
  loose,
  named: new Map(),
  partial: null,
  reasons: new Set(),
  cut: new Set(),
});

/** The ancestors whose roles count in a view, nearest first. `open`: one may grant anything. */
export type Chain = { ids: string[]; states: State[]; open: boolean; world: LogWorld; view: View };

/** The chain above a node from `parentId` (pass null for a restricted node, when that's what's asked). */
export function chainOf(world: LogWorld, view: View, nodeId: string, parentId: string | null): Chain {
  const c: Chain = { ids: [], states: [], open: false, world, view };
  const visited = new Set([nodeId]);
  const judged = view.mode !== "now";
  let next = parentId;
  while (next !== null) {
    const id = next;
    if (visited.has(id)) {
      if (judged) flag(view, "needs-parent");
      return c;
    }
    visited.add(id);
    const d = judged ? view.deps.get(id) : undefined;
    let s: State | null;
    if (d) {
      s = namedIn(world, view, id, d);
      if (s === null) return c;
      c.ids.push(id);
      c.states.push(s);
      // Its own place couldn't be judged through the logs named: nothing above it counts.
      if (view.cut.has(id)) return c;
    } else if (view.mode === "lapse") {
      c.open = true;
      return c;
    } else if (judged) {
      // Deps name every ancestor up to where the role comes from (§4.4): nothing beyond a gap counts.
      return c;
    } else {
      const ns = world.state(id);
      if (ns?.status.kind !== "verified") return c;
      s = ns.state;
      c.ids.push(id);
      c.states.push(s);
    }
    next = s.restricted ? null : s.parentId;
  }
  return c;
}

/** A named ancestor's effective state in the view: its applied state at the dep, settled in the same view. */
export function namedIn(world: LogWorld, view: View, id: string, d: Dep): State | null {
  if (view.named.has(id)) {
    const s = view.named.get(id) ?? null;
    if (s === null) flag(view, "needs-parent");
    return s;
  }
  if (world.headAt(id, d.seq) !== d.head) {
    flag(view, "stale-dependency");
    return null;
  }
  const pre = world.stateAt(id, d.seq);
  if (pre?.status.kind !== "verified") {
    flag(view, "needs-parent");
    return null;
  }
  view.named.set(id, null);
  const s = settleIn(world, view, id, pre.vouched).state;
  view.named.set(id, s);
  return s;
}

/** A state's own role for the user in a view: anchor (personal or team), share, and the groups shared with (§4.1). */
export const stateRole = (world: LogWorld, view: View, s: State, userId: string): Role | null =>
  groupRole(
    world,
    view,
    s,
    s.groupShares.map((g) => [g.groupId, g.role]),
    userId,
    ownRole(s, userId),
  );

export const chainRole = (c: Chain, userId: string): Role | null =>
  c.open ? "owner" : c.states.reduce<Role | null>((r, s) => higher(r, stateRole(c.world, c.view, s, userId)), null);

/** The user's role from the node itself: its anchor, and their counted share and counted group shares. */
function hereRole(c: Chain, applied: State, counted: Map<string, Role>, userId: string): Role | null {
  const own = anchorUser(applied) === userId ? "owner" : (counted.get(`u:${userId}`) ?? null);
  const groups: [string, Role][] = [];
  for (const [k, r] of counted) if (k.startsWith("g:")) groups.push([k.slice(2), r]);
  return groupRole(c.world, c.view, applied, groups, userId, own);
}

/**
 * Whether a voucher's authority holds: from the anchor, their own entry or a group here (which must
 * count itself), or the chain above (read regardless of restriction: the authority they had when vouching).
 * A restriction holds while the node is restricted: once applied it is never undone (§3.3), so the
 * owners it anchors count whoever stands above, until an owner lifts it.
 */
function holds(v: Voucher, applied: State, counted: Map<string, Role>, chain: Chain): boolean {
  if (v.restriction) return applied.restricted;
  if (v.author === "") return true;
  if (anchorUser(applied) === v.author) return true;
  return atLeast(higher(hereRole(chain, applied, counted, v.author), chainRole(chain, v.author)), v.need);
}

/**
 * Which entries count, and at which role (§3.3): an entry counts at the newest role one of whose
 * vouchers holds, else the one before, else not at all. The least fixed point, so vouchers can't hold
 * each other up. A void share (`voidIds`, §4.2) never counts.
 */
export function standing(applied: State, recs: Recs, chain: Chain, voidIds: Set<string>): Map<string, Role> {
  const counted = new Map<string, Role>();
  const entries = entriesOf(applied).filter((x) => !(x.key.startsWith("u:") && voidIds.has(x.key.slice(2))));
  for (let changed = true; changed; ) {
    changed = false;
    for (const { key, role } of entries) {
      const rec = recs.get(key);
      let got: Role | null = rec ? null : role;
      for (let r: Held<Role> | null = rec ?? null; r && got === null; r = r.fallback)
        if (r.vouchers.some((v) => holds(v, applied, counted, chain))) got = r.value;
      const had = counted.get(key) ?? null;
      if (got !== null && (had === null || ROLE_RANK[got] > ROLE_RANK[had])) {
        counted.set(key, got);
        changed = true;
      }
    }
  }
  return counted;
}

/**
 * The vouched state read as if its restriction were lifted: the anchors a restriction gave its owners
 * are off (`holds`), so an owner share only the restriction vouched for doesn't count. What an
 * unrestrict leaves out that is lapsed in this reading is not a removal (fold.ts `judgeIn`), and a
 * writer lifting a restriction drops exactly that (write.ts `applyIntent`).
 */
export const lifting = (v: Vouched): Vouched => ({
  ...v,
  applied: { ...v.applied, restricted: false },
  place: v.place ? { ...v.place, restricted: { value: false, vouchers: [ORIGIN], fallback: null } } : null,
});

/** The state a lapsed lift lifted (`Voucher.before`), if the lift's voucher remembers one. */
const liftedState = (lift: Held<boolean> | null): Vouched | null =>
  lift?.vouchers.find((x) => x.before !== undefined)?.before ?? null;

/**
 * What counts once a lift has lapsed (§3.3, "A lapsed lift reads as the state it lifted"): the entries of
 * the state it lifted (`before`), read restricted with its anchors on, minus what applied snapshots removed
 * or demoted since (`removed`, removals never lapse); plus what was added since, judged as usual on the
 * applied state read restricted (`counted`, newer and looser roles win). Without a remembered state (a
 * legacy or origin lift), the applied state read restricted is all there is.
 */
function asLifted(
  v: Vouched,
  counted: Map<string, Role>,
  before: Vouched | null,
  then: (b: Vouched) => Map<string, Role>,
): Map<string, Role> {
  if (before === null) return counted;
  const out = new Map(counted);
  for (const [key, was] of then(before)) {
    const cap = v.removed.get(key);
    if (cap === null) continue;
    const role = cap === undefined ? was : lower(was, cap);
    const had = out.get(key);
    if (had === undefined || ROLE_RANK[role] > ROLE_RANK[had]) out.set(key, role);
  }
  return out;
}

/** The applied state with the entries of the state a lapsed lift lifted that it no longer has (`effective` keeps only what counts). */
function withLifted(applied: State, before: Vouched | null): State {
  if (before === null) return applied;
  const add = <T>(have: T[], then: T[], id: (x: T) => string): T[] => {
    const seen = new Set(have.map(id));
    return [...have, ...then.filter((x) => !seen.has(id(x)))];
  };
  return {
    ...applied,
    shares: add(applied.shares, before.applied.shares, (x) => x.userId),
    groupShares: add(applied.groupShares, before.applied.groupShares, (x) => x.groupId),
    links: add(applied.links, before.applied.links, (x) => x.linkId),
  };
}

/** A node settled in a view: its effective state, which entries count, the chain above its effective parent, and its void shares. */
export type Settled = { state: State; counted: Map<string, Role>; chain: Chain; applied: State; voided: Set<string> };

/** The "lapse" reading of a judged view's deps: every unnamed log or group open. Made once per view. */
const lenientOf = (view: View): View => (view.lenient ??= viewOf("lapse", view.deps, view.loose));

/** What the lenient reading couldn't check, the judged view couldn't either: a dep met only beyond a gap still counts. */
function carry(view: View, lv: View): void {
  for (const r of lv.reasons) flag(view, r);
}

/** Whether a move's voucher holds: editor on the node where it falls back to (`from`, `counted`), and editor on the new parent (`to`). */
const moves = (h: Held<string | null>, applied: State, counted: Map<string, Role>, from: Chain, to: Chain): boolean =>
  h.vouchers.some(
    (x) =>
      x.author === "" ||
      (holds(x, applied, counted, from) &&
        (anchorUser(applied) === x.author || atLeast(chainRole(to, x.author), "editor"))),
  );

/**
 * Whether an unrestrict's voucher holds: owner on the node (the lifter on the state they lifted, with
 * its anchors on, `before`; a later voucher of the open state on it as it counts now) and editor on the
 * parent (`chain`, the view's chain above it); a root's lift has no parent to ask. Mirrors `moves`.
 */
function lifted(
  h: Held<boolean>,
  applied: State,
  counted: Map<string, Role>,
  chain: Chain,
  then: (b: Vouched) => Map<string, Role>,
): boolean {
  return h.vouchers.some((x) => {
    if (x.author === "") return true;
    const owner = x.before ? holds(x, x.before.applied, then(x.before), chain) : holds(x, applied, counted, chain);
    return (
      owner &&
      (applied.parentId === null || anchorUser(applied) === x.author || atLeast(chainRole(chain, x.author), "editor"))
    );
  });
}

/**
 * The effective state of a node in a view (§3.3): its parent at the newest value whose vouchers hold,
 * else the one before (the first one stands if none does); its restriction, asymmetric: a restriction
 * stands once applied (falling back would open private content to the folder), while a lift counts only
 * while its author still has owner on the node, judged on the state they lifted with its anchors on
 * (the authority they had under it), and editor on the parent in this view, as a move needs (`lifted`);
 * a lapsed lift reads as the state it lifted, with the restriction's owners counting again, minus
 * removals made since, plus additions judged as usual (`asLifted`). And only the entries that count,
 * leaving out void team shares (§4.2).
 *
 * Judging ("deps"), a later parent stands if a voucher of it holds through the logs named, and falls
 * back if none would hold even with every unnamed log or group granting everything (the "lapse"
 * reading of the same deps). Otherwise the move can't be judged: the place is a gap (§4.4), the chain
 * ends there with nothing above it counting, and the node is `cut` in the view. A lift is judged the
 * same way: one that fails through the logs named but might hold with every unnamed one open is a gap
 * too, read open with nothing above counting, never lapsed (else leaving the parent out of the deps
 * would hand the lifter the restriction's owners back). So a place the snapshot left unnamed, or a
 * voucher it left unprovable, never adds authority: not through the destination of a move that may
 * have lapsed, nor through the place a move that may have held would fall back to, nor through the
 * restricted state a lift that may hold lifted. Whatever the lenient reading couldn't check is flagged
 * on the view too.
 */
export function settleIn(world: LogWorld, view: View, nodeId: string, v: Vouched): Settled {
  const { applied, recs, place } = v;
  const voidIds = voided(world, view, nodeId, applied, v.deps);
  let parentId = applied.parentId;
  const none = (): Chain => ({ ids: [], states: [], open: false, world, view });
  let chain: Chain = place ? none() : chainOf(world, view, nodeId, parentId);
  let counted = place ? new Map<string, Role>() : standing(applied, recs, chain, voidIds);
  let restricted = applied.restricted;
  let before: Vouched | null = null;
  if (place) {
    // Bottom up: the first parent stands; each later one counts if a voucher of it held editor on the
    // node where it falls back to, and holds editor on it (§3.2: a move needs both).
    const stack: Held<string | null>[] = [];
    for (let h: Held<string | null> | null = place.parent; h; h = h.fallback) stack.unshift(h);
    for (const [i, h] of stack.entries()) {
      const to = chainOf(world, view, nodeId, h.value);
      if (i > 0 && !moves(h, applied, counted, chain, to)) {
        if (view.mode !== "deps") continue;
        const lv = lenientOf(view);
        const from = chainOf(world, lv, nodeId, parentId);
        const might = moves(
          h,
          applied,
          standing(applied, recs, from, voidIds),
          from,
          chainOf(world, lv, nodeId, h.value),
        );
        carry(view, lv);
        if (!might) continue;
        chain = none();
        counted = standing(applied, recs, chain, voidIds);
        view.cut.add(nodeId);
        break;
      }
      parentId = h.value;
      chain = to;
      counted = standing(applied, recs, to, voidIds);
    }
    if (!applied.restricted) {
      // The standing of a lifted state (its anchors on), once per chain it is read against.
      const thenIn = (c: Chain, memo: Map<Vouched, Map<string, Role>>) => (b: Vouched) => {
        let got = memo.get(b);
        if (!got) {
          got = standing(b.applied, b.recs, c, voided(world, view, nodeId, b.applied, b.deps));
          memo.set(b, got);
        }
        return got;
      };
      const then = thenIn(chain, new Map());
      // Newest first: a lift stands while a voucher of it holds; else the restriction it lifted stands, and the
      // node reads as the state that lift lifted. Judging, a lift that can't be proven is a gap, not a lapse.
      let lift: Held<boolean> | null = null;
      let gap = false;
      for (let r: Held<boolean> | null = place.restricted; r; r = r.fallback) {
        restricted = r.value;
        if (r.value || r.fallback === null || lifted(r, applied, counted, chain, then)) break;
        if (view.mode === "deps") {
          const lv = lenientOf(view);
          const lc = chainOf(world, lv, nodeId, parentId);
          const might = lifted(r, applied, standing(applied, recs, lc, voidIds), lc, thenIn(lc, new Map()));
          carry(view, lv);
          if (might) {
            gap = true;
            break;
          }
        }
        lift = r;
      }
      if (gap) {
        chain = none();
        counted = standing(applied, recs, chain, voidIds);
        view.cut.add(nodeId);
      } else if (restricted) {
        before = liftedState(lift);
        const under = standing({ ...applied, restricted: true }, recs, chain, voidIds);
        counted = asLifted(v, under, before, then);
      }
    }
  }
  return {
    state: effective({ ...withLifted(applied, before), parentId, restricted }, counted),
    counted,
    chain,
    applied,
    voided: voidIds,
  };
}

/** A user's authority on a settled node from the node itself: its anchor, and their counted entries (§4.1). */
export function ownAuthorityIn(s: Settled, userId: string): Role | null {
  if (anchorUser(s.applied) === userId) return "owner";
  return hereRole(s.chain, s.applied, s.counted, userId);
}

/** A user's authority on a settled node: anchor, their counted entries, and the chain while unrestricted (§4.1). */
export function authorityIn(s: Settled, userId: string): Role | null {
  const own = ownAuthorityIn(s, userId);
  return s.state.restricted || own === "owner" ? own : higher(own, chainRole(s.chain, userId));
}

/**
 * Whether `userId` still has `need` on a settled node (§3.3, a key maker): their authority as it is
 * now (`authorityIn`), so one that came only from above a restriction counts as lapsed. Vouchers
 * themselves (`holds`) read the chain regardless: the authority they had when vouching.
 */
export const stillHolds = (s: Settled, userId: string, need: Role): boolean => atLeast(authorityIn(s, userId), need);

/** The applied state with only what counts, at the role it counts at. */
export function effective(applied: State, counted: Map<string, Role>): State {
  const list = <T extends { role: Role }>(xs: T[], key: (x: T) => string): T[] =>
    xs.flatMap((x) => {
      const r = counted.get(key(x));
      return r === undefined ? [] : r === x.role ? [x] : [{ ...x, role: r }];
    });
  return {
    ...applied,
    shares: list(applied.shares, (x) => `u:${x.userId}`),
    groupShares: list(applied.groupShares, (x) => `g:${x.groupId}`),
    links: list(applied.links, (x) => `l:${x.linkId}`),
  };
}

const plus = (vs: Voucher[], v: Voucher) => (vs.some((x) => sameVoucher(x, v)) ? vs : [...vs, v]);

/** A value after a snapshot: the same value gains its author as a voucher; a new one starts afresh, the old as fallback. */
function heldNext<T>(h: Held<T> | null, value: T, v: Voucher, fresh: Voucher): Held<T> {
  if (h === null) return { value, vouchers: [v], fallback: null };
  if (h.value === value) return { ...h, vouchers: plus(h.vouchers, v) };
  return { value, vouchers: [fresh], fallback: h };
}

/**
 * The vouchers after applying a snapshot by `author` (empty: the origin's own say). Every entry it
 * contains gains them as a voucher; one it adds or loosens starts afresh (a looser role keeps the one
 * before as its fallback); a tighter role keeps every voucher the entry had. Its place likewise: the
 * parent needs editor, the restriction owner (the origin's, editor: creating a child needs only that).
 * At a root's genesis the entries its anchor implies (`anchored`: a team root's Everyone and Admins, a personal
 * root's owner) are vouched by ORIGIN, since they are the anchor's, not the creator's (§4.2); every other genesis
 * entry keeps the author, and lapses with them (§3.3). A snapshot that makes the node restricted (a restricted creation, or a restrict) vouches for the
 * owner shares and owner groups in it by that restriction instead of by its author (§3.3). One that
 * lifts a restriction remembers the state it lifted, and what later ones remove or demote (`removals`:
 * the judged removals, not what was left out as lapsed) is kept against it, for when the lift lapses.
 */
export function vouch(
  prev: Vouched,
  next: State,
  author: string,
  removals: Diff[] = [],
  /** Entry keys (`u:`, `g:`) the node's anchor itself implies at its genesis: vouched by ORIGIN, not the author (§4.2). */
  anchored?: ReadonlySet<string>,
): Vouched {
  const by = (need: Role): Voucher => (author === "" ? ORIGIN : { author, need });
  // A lift remembers the state it lifted: the lifter's owner authority is read there (`lifted`).
  const lift: Voucher = author === "" ? ORIGIN : { author, need: "owner", before: prev };
  const place: Place = prev.place
    ? {
        parent: heldNext(prev.place.parent, next.parentId, by("editor"), by("editor")),
        restricted: heldNext(prev.place.restricted, next.restricted, by("owner"), next.restricted ? by("owner") : lift),
      }
    : {
        parent: heldNext(null, next.parentId, by("editor"), by("editor")),
        restricted: heldNext(null, next.restricted, by("editor"), by("editor")),
      };
  const restricts = author !== "" && next.restricted && !(prev.place && prev.applied.restricted);
  const anchor: Voucher | null = restricts ? { author: "", need: "owner", restriction: true } : null;
  const before = new Map(entriesOf(prev.applied).map((x) => [x.key, x.role]));
  const recs: Recs = new Map();
  for (const { key, role } of entriesOf(next)) {
    const was = before.get(key);
    const old = prev.recs.get(key) ?? null;
    const owner = role === "owner";
    const v =
      anchor && owner && !key.startsWith("l:") ? anchor : anchored?.has(key) ? ORIGIN : by(owner ? "owner" : "editor");
    let rec: Held<Role>;
    if (was === undefined || old === null) rec = { value: role, vouchers: [v], fallback: null };
    else if (was === role) rec = { ...old, vouchers: plus(old.vouchers, v) };
    else if (ROLE_RANK[role] > ROLE_RANK[was])
      rec = { value: role, vouchers: [owner ? v : by("owner")], fallback: old };
    else {
      let all: Voucher[] = [v];
      for (let r: Held<Role> | null = old; r; r = r.fallback) for (const x of r.vouchers) all = plus(all, x);
      rec = { value: role, vouchers: all, fallback: null };
    }
    recs.set(key, rec);
  }
  const lifts = !next.restricted && prev.place !== null && prev.applied.restricted;
  const removed = next.restricted
    ? new Map<string, Role | null>()
    : removedSince(lifts ? new Map() : prev.removed, removals);
  return { applied: next, recs, place, deps: prev.deps, removed };
}

/** The removals so far plus `drops`: a removed entry is null, a demoted one the lowest role it was brought to. */
export function removedSince(so: ReadonlyMap<string, Role | null>, drops: Diff[]): ReadonlyMap<string, Role | null> {
  if (drops.length === 0) return so;
  const out = new Map(so);
  const demote = (key: string, from: Role, to: Role) => {
    if (ROLE_RANK[to] >= ROLE_RANK[from]) return;
    const had = out.get(key);
    if (had !== null) out.set(key, had === undefined ? to : lower(had, to));
  };
  for (const d of drops) {
    if (d.kind === "remove-share") out.set(`u:${d.userId}`, null);
    else if (d.kind === "remove-group") out.set(`g:${d.groupId}`, null);
    else if (d.kind === "remove-link") out.set(`l:${d.linkId}`, null);
    else if (d.kind === "role") demote(`u:${d.userId}`, d.from, d.to);
    else if (d.kind === "group-role") demote(`g:${d.groupId}`, d.from, d.to);
    else if (d.kind === "link-role") demote(`l:${d.linkId}`, d.from, d.to);
  }
  return out;
}
