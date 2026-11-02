import { toBase64Url } from "@jelly/crypto";
import { describe, expect, it } from "vitest";
import {
  createAccount,
  createSnapshot,
  LIMITS,
  type Snapshot,
  type State,
  snapshotBytes,
  snapshotHash,
  unlockAccount,
  verifySnapshotSig,
  wellFormedSnapshot,
  wellFormedState,
} from "../../src/index.ts";

function user() {
  const id = crypto.randomUUID();
  const acct = createAccount();
  return {
    id,
    account: unlockAccount({ userId: id, handle: "u", ak: acct.ak, bundle: acct.bundle }),
    signPub: acct.bundle.signPub,
  };
}

const alice = user();
const bob = user();
const id = () => crypto.randomUUID();
const id1 = id();
const id2 = id();
const key = (n: number) => toBase64Url(new Uint8Array(32).fill(n));

const state = (over: Partial<State> = {}): State => ({
  kind: "page",
  parentId: id(),
  anchor: { user: alice.id, signPub: alice.signPub },
  restricted: false,
  version: 1,
  keyCommit: key(1),
  shares: [
    { userId: alice.id, role: "owner", signPub: alice.signPub },
    { userId: bob.id, role: "editor", signPub: bob.signPub },
  ],
  groupShares: [
    { groupId: id(), role: "viewer" },
    { groupId: id(), role: "editor" },
  ],
  links: [
    { linkId: id(), role: "viewer" },
    { linkId: id(), role: "viewer" },
  ],
  ...over,
});

const make = (over: Partial<Parameters<typeof createSnapshot>[1]> = {}): Snapshot =>
  createSnapshot(alice.account, {
    nodeId: id(),
    seq: 3,
    prev: key(2),
    state: state(),
    change: "change",
    supersedes: null,
    skipped: [id(), id()],
    nonce: null,
    deps: [
      { log: id(), seq: 4, head: key(3) },
      { log: `group:${id()}`, seq: 0, head: key(4) },
    ],
    at: "2026-10-30T10:00:00.000Z",
    ...over,
  });

describe("node log snapshots", () => {
  it("signs and verifies", () => {
    const s = make();
    expect(s.authorId).toBe(alice.id);
    expect(verifySnapshotSig(s)).toBe(true);
    const flips: Array<(s: Snapshot) => Snapshot> = [
      (s) => ({ ...s, nodeId: id() }),
      (s) => ({ ...s, seq: s.seq + 1 }),
      (s) => ({ ...s, prev: key(9) }),
      (s) => ({ ...s, prev: null }),
      (s) => ({ ...s, change: "checkpoint" }),
      (s) => ({ ...s, supersedes: key(9) }),
      (s) => ({ ...s, skipped: [...s.skipped, id()] }),
      (s) => ({ ...s, nonce: key(9) }),
      (s) => ({ ...s, authorId: bob.id }),
      (s) => ({ ...s, authorSignPub: bob.signPub }),
      (s) => ({ ...s, at: "2026-10-30T10:00:01.000Z" }),
      (s) => ({ ...s, deps: s.deps.slice(1) }),
      (s) => ({ ...s, deps: s.deps.map((d, i) => (i === 1 ? { ...d, head: key(9) } : d)) }),
      (s) => ({ ...s, deps: s.deps.map((d, i) => (i === 1 ? { ...d, seq: d.seq + 1 } : d)) }),
      (s) => ({ ...s, state: { ...s.state, kind: "drive" } }),
      (s) => ({ ...s, state: { ...s.state, parentId: null } }),
      (s) => ({ ...s, state: { ...s.state, anchor: null } }),
      (s) => ({ ...s, state: { ...s.state, anchor: { team: id() } } }),
      (s) => ({ ...s, state: { ...s.state, restricted: true } }),
      (s) => ({ ...s, state: { ...s.state, version: 2 } }),
      (s) => ({ ...s, state: { ...s.state, keyCommit: null } }),
      (s) => ({
        ...s,
        state: { ...s.state, shares: s.state.shares.map((x, i) => (i === 1 ? { ...x, role: "owner" as const } : x)) },
      }),
      (s) => ({ ...s, state: { ...s.state, shares: s.state.shares.slice(1) } }),
      (s) => ({
        ...s,
        state: { ...s.state, shares: s.state.shares.map((x, i) => (i === 1 ? { ...x, signPub: alice.signPub } : x)) },
      }),
      (s) => ({
        ...s,
        state: {
          ...s.state,
          groupShares: s.state.groupShares.map((x, i) => (i === 0 ? { ...x, role: "owner" as const } : x)),
        },
      }),
      (s) => ({ ...s, state: { ...s.state, links: s.state.links.slice(1) } }),
      (s) => ({
        ...s,
        state: { ...s.state, links: s.state.links.map((x, i) => (i === 0 ? { ...x, role: "editor" as const } : x)) },
      }),
    ];
    for (const flip of flips) expect(verifySnapshotSig(flip(s))).toBe(false);
  });

  it("does not verify with a garbage signature or throw", () => {
    const s = make();
    expect(verifySnapshotSig({ ...s, sig: "!!" })).toBe(false);
    expect(verifySnapshotSig({ ...s, sig: toBase64Url(new Uint8Array(10)) })).toBe(false);
  });

  it("list order doesn't change the bytes, contents do", () => {
    const s = make();
    const reversed: Snapshot = {
      ...s,
      skipped: [...s.skipped].reverse(),
      deps: [...s.deps].reverse(),
      state: {
        ...s.state,
        shares: [...s.state.shares].reverse(),
        groupShares: [...s.state.groupShares].reverse(),
        links: [...s.state.links].reverse(),
      },
    };
    expect(snapshotBytes(reversed)).toEqual(snapshotBytes(s));
    expect(verifySnapshotSig(reversed)).toBe(true);
    expect(snapshotBytes({ ...s, skipped: s.skipped.slice(1) })).not.toEqual(snapshotBytes(s));
  });

  it("the encoding is unambiguous", () => {
    // One fixed base: a case differs from its twin only in the field under test, never in random ids.
    const base = make();
    const bytes = (over: Partial<Snapshot>, st: Partial<State> = {}) =>
      snapshotBytes({ ...base, ...over, state: { ...base.state, ...st } });
    expect(bytes({})).toEqual(bytes({}));
    // A value moved across adjacent fields.
    expect(bytes({}, { kind: "a|", parentId: id1 })).not.toEqual(bytes({}, { kind: "a", parentId: `|${id1}` }));
    expect(bytes({}, { kind: "ab", keyCommit: "c" })).not.toEqual(bytes({}, { kind: "a", keyCommit: "bc" }));
    // A list split differently (same count, same joined text).
    expect(bytes({ skipped: [id1, id2] })).not.toEqual(bytes({ skipped: [`${id1}${id2}`, ""] }));
    expect(bytes({ skipped: ["a|b", "c"] })).not.toEqual(bytes({ skipped: ["a", "b|c"] }));
    // The same id as a skipped member or as a dep log.
    expect(bytes({ skipped: [id1], deps: [] })).not.toEqual(
      bytes({ skipped: [], deps: [{ log: id1, seq: 0, head: key(1) }] }),
    );
    // An entry in one list or another.
    const e = { groupId: id1, role: "viewer" as const };
    const l = { linkId: id1, role: "viewer" as const };
    expect(bytes({}, { groupShares: [e], links: [] })).not.toEqual(bytes({}, { groupShares: [], links: [l] }));
    // Null versus a value.
    expect(bytes({ prev: null })).not.toEqual(bytes({ prev: key(1) }));
    expect(bytes({}, { anchor: null })).not.toEqual(bytes({}, { anchor: { team: id1 } }));
  });

  it("hash covers the signature", () => {
    const s = make();
    expect(snapshotHash(s)).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(snapshotHash(s)).toBe(snapshotHash({ ...s }));
    const other = { ...s, sig: toBase64Url(new Uint8Array(64).fill(7)) };
    expect(snapshotHash(other)).not.toBe(snapshotHash(s));
    expect(snapshotHash({ ...s, at: "x" })).not.toBe(snapshotHash(s));
  });

  it("accepts what createSnapshot makes", () => {
    expect(wellFormedSnapshot(make())).toBe(true);
    expect(
      wellFormedSnapshot(make({ seq: 0, prev: null, change: "create", nonce: key(5), skipped: [], deps: [] })),
    ).toBe(true);
    expect(wellFormedSnapshot(make({ change: "checkpoint", supersedes: key(6) }))).toBe(true);
    expect(
      wellFormedSnapshot(make({ state: state({ parentId: null, anchor: { team: id() }, keyCommit: null }) })),
    ).toBe(true);
  });

  it("rejects garbage without throwing", () => {
    const s = make();
    const bad: unknown[] = [
      null,
      undefined,
      {},
      "snapshot",
      42,
      [],
      { ...s, sig: toBase64Url(new Uint8Array(63)) },
      { ...s, sig: `${s.sig}=` },
      { ...s, change: "rewrite" },
      { ...s, seq: -1 },
      { ...s, seq: 1.5 },
      { ...s, nodeId: "not-a-uuid" },
      { ...s, prev: "abc=" },
      { ...s, nonce: key(1) }, // seq 3
      { ...s, supersedes: key(1) }, // not a checkpoint
      { ...s, skipped: [bob.id, bob.id] },
      { ...s, deps: [s.deps[0], s.deps[0]] },
      { ...s, deps: [{ log: "group:nope", seq: 0, head: key(1) }] },
      { ...s, at: 5 },
      { ...s, state: null },
      { ...s, state: { ...s.state, version: -1 } },
      { ...s, state: { ...s.state, restricted: "no" } },
      { ...s, state: { ...s.state, anchor: { user: alice.id } } },
      { ...s, state: { ...s.state, shares: [s.state.shares[0], s.state.shares[0]] } },
      { ...s, state: { ...s.state, shares: [{ userId: bob.id, role: "admin", signPub: bob.signPub }] } },
      { ...s, state: { ...s.state, groupShares: [s.state.groupShares[0], s.state.groupShares[0]] } },
      { ...s, state: { ...s.state, links: [s.state.links[0], s.state.links[0]] } },
      { ...s, state: { ...s.state, links: "x" } },
    ];
    for (const x of bad) expect(wellFormedSnapshot(x)).toBe(false);
  });

  it("ids are lowercase UUIDs only, so one id has one spelling", () => {
    const s = make();
    expect(wellFormedSnapshot(s)).toBe(true);
    const up = s.nodeId.toUpperCase();
    const bad: unknown[] = [
      { ...s, nodeId: up },
      { ...s, authorId: s.authorId.toUpperCase() },
      { ...s, skipped: [up] },
      { ...s, deps: [{ log: up, seq: 0, head: key(1) }] },
      { ...s, deps: [{ log: `group:${up}`, seq: 0, head: key(1) }] },
      { ...s, state: { ...s.state, parentId: up } },
      { ...s, state: { ...s.state, anchor: { user: alice.id.toUpperCase(), signPub: alice.signPub } } },
      { ...s, state: { ...s.state, anchor: { team: up } } },
      { ...s, state: { ...s.state, shares: [{ userId: bob.id.toUpperCase(), role: "editor", signPub: bob.signPub }] } },
      { ...s, state: { ...s.state, groupShares: [{ groupId: up, role: "viewer" }] } },
      { ...s, state: { ...s.state, links: [{ linkId: up, role: "viewer" }] } },
    ];
    for (const x of bad) expect(wellFormedSnapshot(x), JSON.stringify(x).slice(0, 80)).toBe(false);
  });

  it("`at` is strict ISO-8601 UTC, not whatever Date.parse takes", () => {
    const ok = [
      "2026-10-30T10:00:00Z",
      "2026-10-30T10:00:00.000Z",
      "2026-10-30T10:00:00.5Z",
      "2026-10-30T10:00:00.12Z",
    ];
    for (const at of ok) expect(wellFormedSnapshot(make({ at })), at).toBe(true);
    const bad = [
      "",
      "2026-10-30",
      "2026-10-30T10:00Z",
      "2026-10-30T10:00:00",
      "2026-10-30T10:00:00+02:00",
      "2026-10-30T10:00:00.0000Z",
      "2026-10-30t10:00:00z",
      " 2026-10-30T10:00:00Z",
      "2026-10-30T10:00:00Z ",
      "Thu, 30 Oct 2026 10:00:00 GMT",
      "1761818400000",
    ];
    for (const at of bad) expect(wellFormedSnapshot(make({ at })), at).toBe(false);
  });

  it("lists are capped: 1000 shares, group shares, links and skipped, 256 deps", () => {
    expect(LIMITS).toEqual({ shares: 1000, groupShares: 1000, links: 1000, skipped: 1000, deps: 256 });
    const many = <T>(n: number, f: (i: number) => T) => Array.from({ length: n }, (_, i) => f(i));
    const uid = () => crypto.randomUUID();
    const shares = (n: number) => many(n, () => ({ userId: uid(), role: "viewer" as const, signPub: bob.signPub }));
    const groups = (n: number) => many(n, () => ({ groupId: uid(), role: "viewer" as const }));
    const links = (n: number) => many(n, () => ({ linkId: uid(), role: "viewer" as const }));
    const deps = (n: number) => many(n, () => ({ log: uid(), seq: 0, head: key(1) }));
    const skipped = (n: number) => many(n, () => uid());
    expect(wellFormedSnapshot(make({ state: state({ shares: shares(1000) }) }))).toBe(true);
    expect(wellFormedSnapshot(make({ state: state({ shares: shares(1001) }) }))).toBe(false);
    expect(wellFormedSnapshot(make({ state: state({ groupShares: groups(1000) }) }))).toBe(true);
    expect(wellFormedSnapshot(make({ state: state({ groupShares: groups(1001) }) }))).toBe(false);
    expect(wellFormedSnapshot(make({ state: state({ links: links(1000) }) }))).toBe(true);
    expect(wellFormedSnapshot(make({ state: state({ links: links(1001) }) }))).toBe(false);
    expect(wellFormedSnapshot(make({ deps: deps(256) }))).toBe(true);
    expect(wellFormedSnapshot(make({ deps: deps(257) }))).toBe(false);
    expect(wellFormedSnapshot(make({ skipped: skipped(1000) }))).toBe(true);
    expect(wellFormedSnapshot(make({ skipped: skipped(1001) }))).toBe(false);
    expect(wellFormedState(state({ shares: shares(1001) }))).toBe(false);
  });

  it("an anchor is exactly a team or exactly a user with their key", () => {
    const user = { user: alice.id, signPub: alice.signPub };
    const team = { team: id() };
    expect(wellFormedState(state({ anchor: user }))).toBe(true);
    expect(wellFormedState(state({ anchor: team }))).toBe(true);
    expect(wellFormedState(state({ anchor: null }))).toBe(true);
    const bad: unknown[] = [
      { ...team, ...user },
      { ...user, team: id() },
      { ...team, user: alice.id },
      { ...team, extra: 1 },
      { ...user, extra: 1 },
      { user: alice.id },
      { signPub: alice.signPub },
      {},
      [],
      "team",
    ];
    for (const anchor of bad)
      expect(wellFormedState(state({ anchor: anchor as never })), JSON.stringify(anchor)).toBe(false);
  });

  it("rejects unknown keys on a snapshot, its state, and every entry in them", () => {
    const s = make();
    expect(wellFormedSnapshot(s)).toBe(true);
    const share = s.state.shares[0] as State["shares"][number];
    const group = s.state.groupShares[0] as State["groupShares"][number];
    const link = s.state.links[0] as State["links"][number];
    const dep = s.deps[0] as Snapshot["deps"][number];
    const bad: unknown[] = [
      { ...s, extra: true },
      { ...s, legacyProof: [] },
      { ...s, state: { ...s.state, extra: true } },
      { ...s, state: { ...s.state, shares: [{ ...share, extra: 1 }] } },
      { ...s, state: { ...s.state, groupShares: [{ ...group, extra: 1 }] } },
      { ...s, state: { ...s.state, links: [{ ...link, extra: 1 }] } },
      { ...s, deps: [{ ...dep, extra: 1 }] },
    ];
    for (const x of bad) expect(wellFormedSnapshot(x)).toBe(false);
    // and a missing one
    for (const k of Object.keys(s)) {
      const { [k]: _gone, ...rest } = s as unknown as Record<string, unknown>;
      expect(wellFormedSnapshot(rest), k).toBe(false);
    }
    for (const k of Object.keys(s.state)) {
      const { [k]: _gone, ...rest } = s.state as unknown as Record<string, unknown>;
      expect(wellFormedState(rest), k).toBe(false);
    }
  });
});
