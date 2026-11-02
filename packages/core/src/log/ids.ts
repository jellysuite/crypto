import { type Bytes, hashWith, randomBytes, toBase64Url } from "@jelly/crypto";
import type { UnlockedAccount } from "../account.ts";
import { lengthPrefixed } from "../grants.ts";
import type { B64 } from "../wire.ts";
import { createSnapshot, snapshotBytes } from "./encode.ts";
import type { Dep, Snapshot, State } from "./types.ts";

const ID_CONTEXT = "jelly-node-id@1";
const COMMIT_CONTEXT = "jelly-key-commit@1";
/** Lowercase only, as `wellFormedState` asks of every id (encode.ts). */
const V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const hex = (b: Bytes): string => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

/** A node id that commits to the node's first snapshot: 16 bytes of its hash as a UUID (version 8, variant 10). */
export function nodeIdFromFirst(s: Omit<Snapshot, "sig" | "nodeId">): string {
  const h = hashWith(ID_CONTEXT, snapshotBytes({ ...s, nodeId: "" })).slice(0, 16);
  const x = hex(h);
  const version = `8${x.slice(13, 16)}`;
  const variant = `${"89ab".charAt(Number.parseInt(x.charAt(16), 16) & 3)}${x.slice(17, 20)}`;
  return `${x.slice(0, 8)}-${x.slice(8, 12)}-${version}-${variant}-${x.slice(20)}`;
}

/** The first snapshot of a new node: seq 0, a fresh nonce, an id derived from its own content, signed. */
export function createFirstSnapshot(
  account: UnlockedAccount,
  fields: { state: State; deps: Dep[]; at: string },
): Snapshot {
  const nonce = toBase64Url(randomBytes(16));
  const unsigned = {
    seq: 0,
    prev: null,
    state: fields.state,
    change: "create" as const,
    supersedes: null,
    skipped: [],
    nonce,
    deps: fields.deps,
    at: fields.at,
  };
  const authorSignPub = toBase64Url(account.signing.publicKey);
  const nodeId = nodeIdFromFirst({ ...unsigned, authorId: account.userId, authorSignPub });
  return createSnapshot(account, { ...unsigned, nodeId });
}

/** Ids minted before self-certifying ids are random (v4) UUIDs. */
export const isLegacyId = (id: string): boolean => V4.test(id);

/** Whether a first snapshot's id is the one its own content derives. */
export function firstIdMatches(s: Snapshot): boolean {
  if (s.seq !== 0) return false;
  const { sig: _sig, nodeId, ...rest } = s;
  return nodeIdFromFirst(rest) === nodeId;
}

/** Commits to a node's key at a version without revealing it, bound to the node and version. */
export const keyCommit = (nodeId: string, version: number, key: Bytes): B64 =>
  toBase64Url(hashWith(COMMIT_CONTEXT, lengthPrefixed([nodeId, String(version)]), key));
