import { type Bytes, constantTimeEqual, fromBase64Url, hashWith, toBase64Url } from "@jelly/crypto";
import { lengthPrefixed } from "../grants.ts";
import type { B64 } from "../wire.ts";
import { stateFields } from "./encode.ts";
import { isLegacyId } from "./ids.ts";
import type { LogEntry, State } from "./types.ts";

const LEAF_CONTEXT = "jelly-legacy-leaf@1";
const NODE_CONTEXT = "jelly-legacy-node@1";

/** A node that predates signed logs, as the migration root commits to it. */
export type LegacyLeaf = { nodeId: string; state: State };

export const leafHash = (l: LegacyLeaf): Bytes =>
  hashWith(LEAF_CONTEXT, lengthPrefixed([l.nodeId, ...stateFields(l.state)]));

const parent = (left: Bytes, right: Bytes): Bytes => hashWith(NODE_CONTEXT, left, right);

/** Hashes of each level, leaves first. An odd node at the end of a level is carried up unchanged. */
function levels(leaves: LegacyLeaf[]): { sorted: LegacyLeaf[]; levels: Bytes[][] } {
  const sorted = [...leaves].sort((a, b) => (a.nodeId < b.nodeId ? -1 : a.nodeId > b.nodeId ? 1 : 0));
  let level = sorted.map(leafHash);
  const all = [level];
  while (level.length > 1) {
    const next: Bytes[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i] as Bytes;
      const right = level[i + 1];
      next.push(right ? parent(left, right) : left);
    }
    all.push(next);
    level = next;
  }
  return { sorted, levels: all };
}

export function merkleRoot(leaves: LegacyLeaf[]): B64 {
  if (leaves.length === 0) return toBase64Url(hashWith(NODE_CONTEXT));
  const { levels: ls } = levels(leaves);
  return toBase64Url(ls[ls.length - 1]?.[0] as Bytes);
}

/** Sibling hashes from the leaf up, each `"L"` or `"R"` (the side the sibling is on) plus base64url; null if the node isn't a leaf. */
export function merkleProof(leaves: LegacyLeaf[], nodeId: string): string[] | null {
  const { sorted, levels: ls } = levels(leaves);
  let at = sorted.findIndex((l) => l.nodeId === nodeId);
  if (at < 0) return null;
  const proof: string[] = [];
  for (const level of ls.slice(0, -1)) {
    const sibling = at % 2 ? at - 1 : at + 1;
    const hash = level[sibling];
    if (hash) proof.push((at % 2 ? "L" : "R") + toBase64Url(hash));
    at = Math.floor(at / 2);
  }
  return proof;
}

export function verifyLegacy(leaf: LegacyLeaf, proof: string[], root: B64): boolean {
  if (!isLegacyId(leaf.nodeId)) return false;
  try {
    let h = leafHash(leaf);
    for (const step of proof) {
      const side = step[0];
      if (side !== "L" && side !== "R") return false;
      const sibling = fromBase64Url(step.slice(1));
      if (sibling.length !== h.length) return false;
      h = side === "L" ? parent(sibling, h) : parent(h, sibling);
    }
    return constantTimeEqual(h, fromBase64Url(root));
  } catch {
    return false;
  }
}

/** The seq 0 log entry for a legacy node: unsigned, every field but the state fixed, vouched for by its proof. */
export function legacySnapshot(leaf: LegacyLeaf, proof: string[]): LogEntry {
  return {
    nodeId: leaf.nodeId,
    seq: 0,
    prev: null,
    state: leaf.state,
    change: "create",
    supersedes: null,
    skipped: [],
    nonce: null,
    authorId: "",
    authorSignPub: "",
    deps: [],
    at: "",
    sig: "",
    legacyProof: proof,
  };
}
