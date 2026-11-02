import { toBase64Url } from "@jelly/crypto";
import { describe, expect, it } from "vitest";
import {
  isLegacyId,
  type LegacyLeaf,
  type LogEntry,
  leafHash,
  legacySnapshot,
  merkleProof,
  merkleRoot,
  type State,
  verifyLegacy,
  wellFormedSnapshot,
} from "../../src/index.ts";

const uuid = () => crypto.randomUUID();
const b64 = (n: number) => toBase64Url(new Uint8Array(32).fill(n));
const leaf = (i = 0): LegacyLeaf => {
  const owner = uuid();
  const state: State = {
    kind: "page",
    parentId: i % 2 ? uuid() : null,
    anchor: null,
    restricted: false,
    version: 1,
    keyCommit: i % 3 ? b64(i % 250) : null,
    shares: [
      { userId: owner, role: "owner", signPub: b64(1) },
      { userId: uuid(), role: "editor", signPub: b64(2) },
    ],
    groupShares: [],
    links: [],
  };
  return { nodeId: uuid(), state };
};
const at = <T>(xs: T[], i: number): T => xs[i] as T;
const leaves = (n: number) => Array.from({ length: n }, (_, i) => leaf(i));

describe("legacy leaves", () => {
  it.each([1, 2, 3, 7, 1000])("proves every leaf of %i", (n) => {
    const ls = leaves(n);
    const root = merkleRoot(ls);
    const step = n > 50 ? 37 : 1;
    for (let i = 0; i < n; i += step) {
      const proof = merkleProof(ls, at(ls, i).nodeId);
      expect(proof).not.toBeNull();
      expect(verifyLegacy(at(ls, i), proof as string[], root)).toBe(true);
    }
    const last = merkleProof(ls, at(ls, n - 1).nodeId) as string[];
    expect(verifyLegacy(at(ls, n - 1), last, root)).toBe(true);
  });

  it("has no proof for an unknown node", () => {
    expect(merkleProof(leaves(3), uuid())).toBeNull();
  });

  it("refuses a changed leaf", () => {
    const ls = leaves(5);
    const root = merkleRoot(ls);
    const l = at(ls, 2);
    const proof = merkleProof(ls, l.nodeId) as string[];
    const s = l.state;
    const changes: State[] = [
      { ...s, kind: "file" },
      { ...s, parentId: uuid() },
      { ...s, restricted: true },
      { ...s, version: 2 },
      { ...s, keyCommit: b64(77) },
      { ...s, shares: [{ ...at(s.shares, 0), signPub: b64(99) }, at(s.shares, 1)] },
      { ...s, shares: [{ ...at(s.shares, 0), role: "viewer" }, at(s.shares, 1)] },
      { ...s, shares: [at(s.shares, 0)] },
      { ...s, links: [{ linkId: uuid(), role: "viewer" }] },
      { ...s, groupShares: [{ groupId: uuid(), role: "viewer" }] },
    ];
    for (const state of changes) expect(verifyLegacy({ ...l, state }, proof, root)).toBe(false);
    expect(verifyLegacy({ ...l, nodeId: uuid() }, proof, root)).toBe(false);
  });

  it("refuses another root, a bad proof and a malformed proof", () => {
    const ls = leaves(4);
    const l = at(ls, 1);
    const proof = merkleProof(ls, l.nodeId) as string[];
    expect(verifyLegacy(l, proof, merkleRoot(leaves(4)))).toBe(false);
    expect(verifyLegacy(l, proof.slice(1), merkleRoot(ls))).toBe(false);
    expect(verifyLegacy(l, [`X${b64(1)}`], merkleRoot(ls))).toBe(false);
    expect(verifyLegacy(l, [""], merkleRoot(ls))).toBe(false);
  });

  it("refuses a proof with a side flipped, another leaf's proof, and an appended step", () => {
    const ls = leaves(6);
    const root = merkleRoot(ls);
    const l = at(ls, 2);
    const proof = merkleProof(ls, l.nodeId) as string[];
    expect(verifyLegacy(l, proof, root)).toBe(true);
    for (const i of proof.keys()) {
      const flipped = proof.map((p, j) => (j === i ? (p.startsWith("L") ? "R" : "L") + p.slice(1) : p));
      expect(verifyLegacy(l, flipped, root), `step ${i} flipped`).toBe(false);
    }
    for (const other of ls) {
      if (other.nodeId === l.nodeId) continue;
      expect(verifyLegacy(l, merkleProof(ls, other.nodeId) as string[], root), "another leaf's proof").toBe(false);
    }
    expect(verifyLegacy(l, [...proof, `L${b64(3)}`], root)).toBe(false);
    expect(verifyLegacy(l, [...proof, `R${b64(3)}`], root)).toBe(false);
    expect(verifyLegacy(l, [`L${b64(3)}`, ...proof], root)).toBe(false);
    expect(verifyLegacy(l, [], root)).toBe(false);
  });

  it("share order doesn't change the hash", () => {
    const l = leaf();
    const rev = { ...l, state: { ...l.state, shares: [...l.state.shares].reverse() } };
    expect(leafHash(rev)).toEqual(leafHash(l));
  });

  it("the root doesn't depend on leaf order", () => {
    const ls = leaves(6);
    expect(merkleRoot([...ls].reverse())).toBe(merkleRoot(ls));
  });

  it("a v8 nodeId is refused", () => {
    const l = leaf();
    const v8 = "00000000-0000-8000-8000-000000000000";
    const bad = { ...l, nodeId: v8 };
    const root = merkleRoot([bad]);
    expect(isLegacyId(v8)).toBe(false);
    expect(verifyLegacy(bad, merkleProof([bad], v8) as string[], root)).toBe(false);
  });

  it("builds a seq 0 entry for the fold", () => {
    const ls = leaves(3);
    const proof = merkleProof(ls, at(ls, 0).nodeId) as string[];
    const e: LogEntry = legacySnapshot(at(ls, 0), proof);
    expect(e.nodeId).toBe(at(ls, 0).nodeId);
    expect(e.seq).toBe(0);
    expect(e.prev).toBeNull();
    expect(e.change).toBe("create");
    expect(e.authorId).toBe("");
    expect(e.sig).toBe("");
    expect(e.state).toEqual(at(ls, 0).state);
    expect(e.legacyProof).toEqual(proof);
    expect(wellFormedSnapshot(e)).toBe(false);
  });
});
