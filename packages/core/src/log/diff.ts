import type { Role } from "../wire.ts";
import type { Anchor, State } from "./types.ts";

/** One part of the difference between two states; each is judged on its own (§3.2). */
export type Diff =
  | { kind: "add-share"; userId: string; role: Role }
  | { kind: "remove-share"; userId: string }
  | { kind: "role"; userId: string; from: Role; to: Role }
  | { kind: "add-group"; groupId: string; role: Role }
  | { kind: "remove-group"; groupId: string }
  | { kind: "group-role"; groupId: string; from: Role; to: Role }
  | { kind: "add-link"; linkId: string; role: Role }
  | { kind: "remove-link"; linkId: string }
  | { kind: "link-role"; linkId: string; from: Role; to: Role }
  | { kind: "move"; from: string | null; to: string | null }
  | { kind: "restrict" }
  | { kind: "unrestrict" }
  | { kind: "rekey" }
  | { kind: "illegal"; what: string };

const sameAnchor = (a: Anchor | null, b: Anchor | null): boolean => {
  if (a === null || b === null) return a === b;
  if ("team" in a) return "team" in b && a.team === b.team;
  return "user" in b && a.user === b.user && a.signPub === b.signPub;
};

/** Additions, removals and role changes between two lists keyed by id. A share's `signPub` is only a hint, so it isn't one. */
function listDiff<T extends { role: Role }>(
  prev: T[],
  next: T[],
  id: (x: T) => string,
  make: {
    add: (id: string, role: Role) => Diff;
    remove: (id: string) => Diff;
    change: (id: string, from: Role, to: Role) => Diff;
  },
): Diff[] {
  const before = new Map(prev.map((x) => [id(x), x.role]));
  const after = new Map(next.map((x) => [id(x), x.role]));
  const out: Diff[] = [];
  for (const [k, role] of after) {
    const was = before.get(k);
    if (was === undefined) out.push(make.add(k, role));
    else if (was !== role) out.push(make.change(k, was, role));
  }
  for (const k of before.keys()) if (!after.has(k)) out.push(make.remove(k));
  return out;
}

/** Whether the state names an owner of its own: a person, or a group, at owner (a root's anchor isn't asked). */
export const hasOwner = (s: State): boolean =>
  s.shares.some((x) => x.role === "owner") || s.groupShares.some((x) => x.role === "owner");

/** What `next` changes about `prev`. Things no snapshot may change come back as "illegal". */
export function diffStates(prev: State, next: State): Diff[] {
  const out: Diff[] = [];
  if (prev.kind !== next.kind) out.push({ kind: "illegal", what: "kind" });
  if (!sameAnchor(prev.anchor, next.anchor)) out.push({ kind: "illegal", what: "anchor" });
  if (prev.parentId !== next.parentId) out.push({ kind: "move", from: prev.parentId, to: next.parentId });
  if (!prev.restricted && next.restricted) out.push({ kind: "restrict" });
  if (prev.restricted && !next.restricted) out.push({ kind: "unrestrict" });
  // A restricted node has nothing above it to fall back on, so no snapshot takes its last owner away (a
  // restrict keeps one too). One that already has none (legacy data) is judged normally, so its members
  // can still leave, re-key, or be given an owner by someone with authority.
  if (next.restricted && next.parentId !== null && !hasOwner(next) && (hasOwner(prev) || !prev.restricted))
    out.push({ kind: "illegal", what: "owner" });

  if (next.version === prev.version + 1) {
    const fresh = next.keyCommit !== null && next.keyCommit !== prev.keyCommit;
    out.push(fresh ? { kind: "rekey" } : { kind: "illegal", what: "commit" });
  } else if (next.version !== prev.version) out.push({ kind: "illegal", what: "version" });
  else if (next.keyCommit !== prev.keyCommit) out.push({ kind: "illegal", what: "commit" });

  out.push(
    ...listDiff(prev.shares, next.shares, (x) => x.userId, {
      add: (userId, role) => ({ kind: "add-share", userId, role }),
      remove: (userId) => ({ kind: "remove-share", userId }),
      change: (userId, from, to) => ({ kind: "role", userId, from, to }),
    }),
    ...listDiff(prev.groupShares, next.groupShares, (x) => x.groupId, {
      add: (groupId, role) => ({ kind: "add-group", groupId, role }),
      remove: (groupId) => ({ kind: "remove-group", groupId }),
      change: (groupId, from, to) => ({ kind: "group-role", groupId, from, to }),
    }),
    ...listDiff(prev.links, next.links, (x) => x.linkId, {
      add: (linkId, role) => ({ kind: "add-link", linkId, role }),
      remove: (linkId) => ({ kind: "remove-link", linkId }),
      change: (linkId, from, to) => ({ kind: "link-role", linkId, from, to }),
    }),
  );
  return out;
}

/** Removals take someone's access away, so they go with a re-key (§3.2). */
export const isRemoval = (d: Diff): boolean =>
  d.kind === "remove-share" || d.kind === "remove-group" || d.kind === "remove-link" || d.kind === "restrict";

/** The role a difference needs on the node itself (a move or an unrestrict also needs a parent, fold.ts). Null: never allowed. */
export function needs(d: Diff): Role | null {
  switch (d.kind) {
    case "add-share":
    case "add-group":
    case "add-link":
      return d.role === "owner" ? "owner" : "editor";
    case "role":
    case "group-role":
    case "link-role":
    case "remove-share":
    case "remove-group":
    case "remove-link":
    case "restrict":
    case "unrestrict":
      return "owner";
    case "move":
    case "rekey":
      return "editor";
    case "illegal":
      return null;
  }
}
