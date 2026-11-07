import type { B64, Role } from "../wire.ts";

/** What a node's authority roots in: a person (with the key they signed with) or a team. */
export type Anchor = { user: string; signPub: B64 } | { team: string };

/** A log another log's snapshot leaned on, pinned at a sequence number and head hash. `log` is a node id or `group:<groupId>`. */
export type Dep = { log: string; seq: number; head: B64 };

export type ShareEntry = { userId: string; role: Role; signPub: B64 };

/** Everything about a node that decides who may do what, in full. */
export type State = {
  kind: string;
  parentId: string | null;
  anchor: Anchor | null;
  restricted: boolean;
  version: number;
  keyCommit: B64 | null;
  shares: ShareEntry[];
  groupShares: { groupId: string; role: Role }[];
  links: { linkId: string; role: Role }[];
};

export type Change = "create" | "change" | "leave" | "checkpoint";

/** One signed full-state entry in a node's hash-chained log. `at` is an informational ISO-8601 time. */
export type Snapshot = {
  nodeId: string;
  seq: number;
  prev: B64 | null;
  state: State;
  change: Change;
  supersedes: B64 | null;
  skipped: string[];
  nonce: B64 | null;
  authorId: string;
  authorSignPub: B64;
  deps: Dep[];
  at: string;
  sig: B64;
};

/** An entry as the fold sees it. A legacy seq 0 entry is unsigned (`authorId` and `sig` empty) and carries its Merkle proof. */
export type LogEntry = Snapshot & { legacyProof?: string[] };

/** How far a node's log could be checked. `atSeq` is the first snapshot that couldn't be; `log` the log shown older than seen. */
export type Status =
  | { kind: "verified" }
  | { kind: "unverified"; atSeq: number; reason: string }
  | { kind: "rolled-back"; log: string };

/** A node's log folded (§3.5): its effective state, where the chain ends, and how far it could be checked. */
export type NodeState = {
  nodeId: string;
  state: State;
  /** A removal happened without a re-key, so the next write rotates first (§5.2). */
  stale: boolean;
  /** Hash and seq of the last snapshot that chains on; "" and -1 when none does. */
  head: B64;
  seq: number;
  status: Status;
  /** The highest dep per log named by an applied snapshot (§4.4). */
  deps: Map<string, { seq: number; head: B64 }>;
  /**
   * The removals counted while unverified, which a checkpoint must respect (§8.1): those by an owner
   * of the last verified prefix, and leaves. `demoted` holds the role an entry (`u:`, `g:` or `l:` +
   * id) was brought down to; `restricted`, whether such an owner restricted the node. Empty while verified.
   */
  stretchRemovals: StretchRemovals;
  /**
   * The highest version any chained, signed snapshot has carried since the node went unverified (the
   * state's own while verified). A checkpoint's version must be above it, by at most its seq (§8.1);
   * writers use the floor plus one (`checkpointPrefill`).
   */
  stretchVersion: number;
};

export type StretchRemovals = {
  userIds: Set<string>;
  groupIds: Set<string>;
  linkIds: Set<string>;
  demoted: Map<string, Role>;
  restricted: boolean;
};

/**
 * The client's verified view of team groups, from the team's signed group versions. Every answer,
 * `removedAt` and `removedSince` included, must come from the same verified versions as `latest` and
 * `member`. Neither removal answer may hide behind history the client wasn't shown (the server picks what
 * it serves): unknown history counts as a possible removal, so a removal `latest` shows always makes the
 * node stale, and a share is never void without `removedSince` being true from the key's version.
 */
export type GroupView = {
  latest(groupId: string): { version: number; head: B64 } | null;
  member(groupId: string, version: number, userId: string): boolean;
  /**
   * The first signed group version greater than `after` at which the user is no longer a member (they
   * were one at the version before it), or null if there is none at or below `latest`. People who were
   * never members are never "no longer" members, so this is null for them. Someone gone at `latest` whose
   * removal a gap hides counts from the earliest version above `after` it could be: after the last version
   * shown with them in it, or right after `after` when that version isn't shown at all (§4.2).
   */
  removedAt(groupId: string, userId: string, after: number): number | null;
  /**
   * Whether anyone who was a member at signed group version `version` may no longer be one at `latest`
   * (§5.2: a node sharing with the group, or below an ancestor that does, is stale). A group moves to its
   * next version only after a removal, so this is true for every version below `latest`, whatever history
   * was shown; false at or above `latest` and for a group the client has no verified view of.
   */
  removedSince(groupId: string, version: number): boolean;
  teamGroups(teamId: string): { everyone: string; admins: string } | null;
  /**
   * The team's workspace root as a verified team key named it (the client's pin, Task 6b), or null when the view
   * can't name it: then any root anchored to the team is judged on its anchor alone. With it, a root anchored to
   * the team that isn't this one is refused at its genesis.
   */
  teamRoot?(teamId: string): string | null;
};
