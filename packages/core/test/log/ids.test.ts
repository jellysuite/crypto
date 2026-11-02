import { toBase64Url } from "@jelly/crypto";
import { describe, expect, it } from "vitest";
import {
  createAccount,
  createFirstSnapshot,
  firstIdMatches,
  isLegacyId,
  keyCommit,
  nodeIdFromFirst,
  type State,
  unlockAccount,
  verifySnapshotSig,
  wellFormedSnapshot,
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
const key = (n: number) => new Uint8Array(32).fill(n);
const state = (over: Partial<State> = {}): State => ({
  kind: "page",
  parentId: crypto.randomUUID(),
  anchor: { user: alice.id, signPub: alice.signPub },
  restricted: false,
  version: 1,
  keyCommit: toBase64Url(key(1)),
  shares: [{ userId: alice.id, role: "owner", signPub: alice.signPub }],
  groupShares: [],
  links: [],
  ...over,
});
const at = "2026-10-30T10:00:00.000Z";

describe("self-certifying ids", () => {
  it("an id is v8 and derived from the first snapshot", () => {
    const st = state();
    const s = createFirstSnapshot(alice.account, { state: st, deps: [], at });
    expect(s.nodeId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(s.seq).toBe(0);
    expect(s.prev).toBeNull();
    expect(s.change).toBe("create");
    expect(wellFormedSnapshot(s)).toBe(true);
    expect(verifySnapshotSig(s)).toBe(true);
    expect(firstIdMatches(s)).toBe(true);
    const { sig: _sig, nodeId: _id, ...rest } = s;
    expect(nodeIdFromFirst(rest)).toBe(s.nodeId);

    const variants: Array<[string, (s: typeof rest) => typeof rest]> = [
      ["parentId", (r) => ({ ...r, state: { ...r.state, parentId: crypto.randomUUID() } })],
      ["kind", (r) => ({ ...r, state: { ...r.state, kind: "file" } })],
      ["nonce", (r) => ({ ...r, nonce: toBase64Url(key(9)) })],
      ["author", (r) => ({ ...r, authorId: bob.id, authorSignPub: bob.signPub })],
      [
        "share",
        (r) => ({
          ...r,
          state: { ...r.state, shares: [...r.state.shares, { userId: bob.id, role: "viewer", signPub: bob.signPub }] },
        }),
      ],
    ];
    for (const [name, change] of variants) {
      const changed = change(rest);
      expect(nodeIdFromFirst(changed), name).not.toBe(s.nodeId);
      expect(firstIdMatches({ ...changed, nodeId: s.nodeId, sig: s.sig }), name).toBe(false);
    }
  });

  it("two first snapshots of the same fields get different ids", () => {
    const st = state();
    const a = createFirstSnapshot(alice.account, { state: st, deps: [], at });
    const b = createFirstSnapshot(alice.account, { state: st, deps: [], at });
    expect(a.nodeId).not.toBe(b.nodeId);
  });

  it("legacy ids are lowercase v4 only", () => {
    const v4 = crypto.randomUUID();
    expect(isLegacyId(v4)).toBe(true);
    expect(isLegacyId(v4.toUpperCase())).toBe(false);
  });

  it("legacy ids are v4 only", () => {
    expect(isLegacyId(crypto.randomUUID())).toBe(true);
    const v8 = createFirstSnapshot(alice.account, { state: state(), deps: [], at }).nodeId;
    expect(isLegacyId(v8)).toBe(false);
    expect(isLegacyId("not-a-uuid")).toBe(false);
    expect(isLegacyId("")).toBe(false);
  });

  it("firstIdMatches is false past seq 0", () => {
    const s = createFirstSnapshot(alice.account, { state: state(), deps: [], at });
    expect(firstIdMatches({ ...s, seq: 1 })).toBe(false);
  });

  it("key commitments bind node, version and key", () => {
    const n = crypto.randomUUID();
    const c = keyCommit(n, 1, key(1));
    expect(c).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(keyCommit(n, 1, key(1))).toBe(c);
    expect(keyCommit(crypto.randomUUID(), 1, key(1))).not.toBe(c);
    expect(keyCommit(n, 2, key(1))).not.toBe(c);
    expect(keyCommit(n, 1, key(2))).not.toBe(c);
  });
});
