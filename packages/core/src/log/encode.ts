import { type Bytes, fromBase64Url, hashWith, sign, toBase64Url, verify } from "@jelly/crypto";
import type { UnlockedAccount } from "../account.ts";
import { lengthPrefixed } from "../grants.ts";
import { SIG } from "../tags.ts";
import type { B64 } from "../wire.ts";
import type { Change, Snapshot, State } from "./types.ts";

const HASH_CONTEXT = "jelly-node-log@1";
const str = (n: number): string => String(n);
const byId = <T>(list: T[], id: (x: T) => string): T[] =>
  [...list].sort((a, b) => (id(a) < id(b) ? -1 : id(a) > id(b) ? 1 : 0));

/** The state as length-prefixable fields in a fixed order; lists are sorted by id and led by their entry count. */
export function stateFields(state: State): string[] {
  const a = state.anchor;
  const shares = byId(state.shares, (x) => x.userId);
  const groups = byId(state.groupShares, (x) => x.groupId);
  const links = byId(state.links, (x) => x.linkId);
  return [
    state.kind,
    state.parentId ?? "",
    ...(a === null ? [""] : "user" in a ? ["u", a.user, a.signPub] : ["t", a.team]),
    state.restricted ? "1" : "0",
    str(state.version),
    state.keyCommit ?? "",
    str(shares.length),
    ...shares.flatMap((x) => [x.userId, x.role, x.signPub]),
    str(groups.length),
    ...groups.flatMap((x) => [x.groupId, x.role]),
    str(links.length),
    ...links.flatMap((x) => [x.linkId, x.role]),
  ];
}

/** What the author signs: every field but the signature, length-prefixed in a fixed order. */
export function snapshotBytes(s: Omit<Snapshot, "sig">): Bytes {
  const skipped = [...s.skipped].sort();
  const deps = byId(s.deps, (d) => d.log);
  return lengthPrefixed([
    s.nodeId,
    str(s.seq),
    s.prev ?? "",
    ...stateFields(s.state),
    s.change,
    s.supersedes ?? "",
    str(skipped.length),
    ...skipped,
    s.nonce ?? "",
    s.authorId,
    s.authorSignPub,
    str(deps.length),
    ...deps.flatMap((d) => [d.log, str(d.seq), d.head]),
    s.at,
  ]);
}

/** Signs a snapshot as the account, filling in who the author is. */
export function createSnapshot(
  account: UnlockedAccount,
  s: Omit<Snapshot, "sig" | "authorId" | "authorSignPub">,
): Snapshot {
  const unsigned = { ...s, authorId: account.userId, authorSignPub: toBase64Url(account.signing.publicKey) };
  return { ...unsigned, sig: toBase64Url(sign(account.signing.privateKey, SIG.nodeLog, snapshotBytes(unsigned))) };
}

/** The snapshot's identity: the next one's `prev`. Covers the signature, so a re-signed copy is a different snapshot. */
export const snapshotHash = (s: Snapshot): B64 =>
  toBase64Url(hashWith(HASH_CONTEXT, snapshotBytes(s), fromBase64Url(s.sig)));

export function verifySnapshotSig(s: Snapshot): boolean {
  try {
    return verify(fromBase64Url(s.authorSignPub), SIG.nodeLog, snapshotBytes(s), fromBase64Url(s.sig));
  } catch {
    return false;
  }
}

/** Lowercase only: one id, one spelling, so no two encodings name the same node or person. */
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const B64URL = /^[A-Za-z0-9_-]+$/;
/** `at`: strict ISO-8601 UTC with up to millisecond precision, the one form `toISOString` writes. */
export const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;
const CHANGES: readonly Change[] = ["create", "change", "leave", "checkpoint"];

/** How long a snapshot's lists may be (M-f); the server checks the same limits before it appends. */
export const LIMITS = { shares: 1000, groupShares: 1000, links: 1000, skipped: 1000, deps: 256 } as const;

const isObj = (x: unknown): x is Record<string, unknown> => typeof x === "object" && x !== null && !Array.isArray(x);
/** An object with exactly these keys: what the canonical encoding covers, and nothing a signature doesn't. */
const exact = (x: unknown, keys: readonly string[]): x is Record<string, unknown> => {
  if (!isObj(x)) return false;
  const own = Object.keys(x);
  return own.length === keys.length && keys.every((k) => Object.hasOwn(x, k));
};
const isUuid = (x: unknown): x is string => typeof x === "string" && UUID.test(x);
const isB64 = (x: unknown): x is string => typeof x === "string" && B64URL.test(x);
const isCount = (x: unknown): x is number => typeof x === "number" && Number.isSafeInteger(x) && x >= 0;
const isRole = (x: unknown): boolean => x === "viewer" || x === "editor" || x === "owner";
const distinct = (ids: string[]): boolean => new Set(ids).size === ids.length;
const isList = (
  x: unknown,
  max: number,
  keys: readonly string[],
  ok: (e: Record<string, unknown>) => boolean,
  id: string,
): boolean =>
  Array.isArray(x) &&
  x.length <= max &&
  x.every((e) => exact(e, keys) && ok(e)) &&
  distinct(x.map((e) => String((e as Record<string, unknown>)[id])));

const STATE_KEYS = [
  "kind",
  "parentId",
  "anchor",
  "restricted",
  "version",
  "keyCommit",
  "shares",
  "groupShares",
  "links",
];
const SNAPSHOT_KEYS = [
  "nodeId",
  "seq",
  "prev",
  "state",
  "change",
  "supersedes",
  "skipped",
  "nonce",
  "authorId",
  "authorSignPub",
  "deps",
  "at",
  "sig",
];

/** An anchor is exactly `{ team }` or exactly `{ user, signPub }` (§4.2). */
const wellFormedAnchor = (a: unknown): boolean =>
  (exact(a, ["team"]) && isUuid(a.team)) || (exact(a, ["user", "signPub"]) && isUuid(a.user) && isB64(a.signPub));

/** Whether `x` has the shape of a state, with exactly its fields, never throwing. */
export function wellFormedState(x: unknown): x is State {
  if (!exact(x, STATE_KEYS)) return false;
  return (
    typeof x.kind === "string" &&
    x.kind !== "" &&
    (x.parentId === null || isUuid(x.parentId)) &&
    (x.anchor === null || wellFormedAnchor(x.anchor)) &&
    typeof x.restricted === "boolean" &&
    isCount(x.version) &&
    (x.keyCommit === null || isB64(x.keyCommit)) &&
    isList(
      x.shares,
      LIMITS.shares,
      ["userId", "role", "signPub"],
      (e) => isUuid(e.userId) && isRole(e.role) && isB64(e.signPub),
      "userId",
    ) &&
    isList(
      x.groupShares,
      LIMITS.groupShares,
      ["groupId", "role"],
      (e) => isUuid(e.groupId) && isRole(e.role),
      "groupId",
    ) &&
    isList(x.links, LIMITS.links, ["linkId", "role"], (e) => isUuid(e.linkId) && isRole(e.role), "linkId")
  );
}

/** Whether `x` has the shape of a snapshot (exactly its fields; ids, base64url, counts, roles, no repeated ids), never throwing. */
export function wellFormedSnapshot(x: unknown): x is Snapshot {
  if (!exact(x, SNAPSHOT_KEYS)) return false;
  try {
    return (
      isUuid(x.nodeId) &&
      isCount(x.seq) &&
      (x.prev === null || isB64(x.prev)) &&
      wellFormedState(x.state) &&
      CHANGES.includes(x.change as Change) &&
      (x.supersedes === null || (x.change === "checkpoint" && isB64(x.supersedes))) &&
      Array.isArray(x.skipped) &&
      x.skipped.length <= LIMITS.skipped &&
      x.skipped.every(isUuid) &&
      distinct(x.skipped) &&
      (x.nonce === null || (x.seq === 0 && isB64(x.nonce))) &&
      isUuid(x.authorId) &&
      isB64(x.authorSignPub) &&
      isList(
        x.deps,
        LIMITS.deps,
        ["log", "seq", "head"],
        (d) =>
          typeof d.log === "string" &&
          isUuid(d.log.startsWith("group:") ? d.log.slice(6) : d.log) &&
          isCount(d.seq) &&
          isB64(d.head),
        "log",
      ) &&
      typeof x.at === "string" &&
      ISO_UTC.test(x.at) &&
      isB64(x.sig) &&
      fromBase64Url(x.sig).length === 64
    );
  } catch {
    return false;
  }
}
