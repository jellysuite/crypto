import { toBase64Url } from "@jelly/crypto";
import { describe, expect, it } from "vitest";
import {
  type Change,
  createAccount,
  createFirstSnapshot,
  createSnapshot,
  type GroupView,
  keyHints,
  type LogEntry,
  LogWorld,
  legacySnapshot,
  merkleRoot,
  type NodeState,
  type Role,
  type Snapshot,
  type State,
  snapshotHash,
  unlockAccount,
  type WorldInput,
} from "../../src/index.ts";

function user(handle: string, id: string = crypto.randomUUID()) {
  const acct = createAccount();
  const account = unlockAccount({ userId: id, handle, ak: acct.ak, bundle: acct.bundle });
  return { id, account, signPub: acct.bundle.signPub };
}
type U = ReturnType<typeof user>;

const alice = user("alice");
const bob = user("bob");
const carol = user("carol");
const dan = user("dan");
const eve = user("eve");
const everyone = [alice, bob, carol, dan, eve];

const at = "2026-10-30T10:00:00.000Z";
const commit = (n: number) => toBase64Url(new Uint8Array(32).fill(n));
const share = (u: U, role: Role, signPub: string = u.signPub) => ({ userId: u.id, role, signPub });

const rootState = (over: Partial<State> = {}): State => ({
  kind: "folder",
  parentId: null,
  anchor: { user: alice.id, signPub: alice.signPub },
  restricted: false,
  version: 1,
  keyCommit: commit(1),
  shares: [share(alice, "owner")],
  groupShares: [],
  links: [],
  ...over,
});

const noGroups: GroupView = {
  latest: () => null,
  member: () => false,
  removedAt: () => null,
  removedSince: () => false,
  teamGroups: () => null,
};

type Resolve = WorldInput["identity"];
const known: Resolve = (userId, signPub) => {
  const u = everyone.find((x) => x.id === userId);
  return !u ? "unknown" : u.signPub === signPub ? "ok" : "mismatch";
};

function fold(nodeId: string, entries: unknown[], over: Partial<WorldInput> = {}): NodeState {
  const world = new LogWorld({
    logs: new Map([[nodeId, entries as LogEntry[]]]),
    legacyRoot: null,
    identity: known,
    groups: noGroups,
    ...over,
  });
  const ns = world.state(nodeId);
  if (!ns) throw new Error("no state");
  return ns;
}

/** Signs as `as` (its user id and key), so a test can sign with one key while claiming someone else. */
type Signer = { account: U["account"] };

class Log {
  entries: unknown[] = [];
  readonly nodeId: string;
  constructor(nodeId: string) {
    this.nodeId = nodeId;
  }
  static root(state: State = rootState(), by: Signer = alice): Log {
    const first = createFirstSnapshot(by.account, { state, deps: [], at });
    const log = new Log(first.nodeId);
    log.entries.push(first);
    return log;
  }
  last(): Snapshot {
    return this.entries[this.entries.length - 1] as Snapshot;
  }
  add(by: Signer, state: State, change: Change = "change"): this {
    const prev = this.last();
    this.entries.push(
      createSnapshot(by.account, {
        nodeId: this.nodeId,
        seq: prev.seq + 1,
        prev: snapshotHash(prev),
        state,
        change,
        supersedes: null,
        skipped: [],
        nonce: null,
        deps: [],
        at,
      }),
    );
    return this;
  }
  fold(over: Partial<WorldInput> = {}): NodeState {
    return fold(this.nodeId, this.entries, over);
  }
}

const roleOf = (ns: NodeState, u: U) => ns.state.shares.find((s) => s.userId === u.id)?.role ?? null;
const verified = { kind: "verified" };
const unverifiedAt = (atSeq: number, reason = "identity") => ({ kind: "unverified", atSeq, reason });

describe("identities (§6)", () => {
  it("an unresolvable author makes the node unverified there", () => {
    const base = [share(alice, "owner"), share(bob, "editor")];
    const log = Log.root(rootState({ shares: base }));
    log.add(bob, rootState({ shares: [...base, share(carol, "viewer")] }));
    for (const answer of ["unknown", "mismatch"] as const) {
      const bobDoesnt: Resolve = (id, pub) => (id === bob.id ? answer : known(id, pub));
      const ns = log.fold({ identity: bobDoesnt });
      expect(ns.status).toMatchObject(unverifiedAt(1));
      expect(roleOf(ns, carol)).toBeNull();
    }
    expect(roleOf(log.fold(), carol)).toBe("viewer");

    // what nobody could have been allowed to do is skipped whoever signed it, resolvable or not
    const stranger = user("stranger");
    const skipOnly = Log.root(rootState({ shares: base }));
    skipOnly.add(stranger, rootState({ shares: [...base, share(stranger, "owner")] }));
    skipOnly.add(bob, rootState({ shares: [...base, share(dan, "owner")] }));
    const ns = skipOnly.fold({ identity: (id, pub) => (id === bob.id ? "mismatch" : known(id, pub)) });
    expect(ns.status).toEqual(verified);
    expect(ns.state.shares).toEqual(base);
  });

  it("a share's key hint can't make anyone act as that person", () => {
    const base = [share(alice, "owner"), share(bob, "editor"), share(carol, "editor")];
    const hinted = [share(alice, "owner"), share(bob, "editor", carol.signPub), share(carol, "editor")];
    const log = Log.root(rootState({ shares: base }));
    // carol, an editor, writes her own key into bob's entry: allowed, and nothing freezes
    log.add(carol, rootState({ shares: hinted }));
    let ns = log.fold();
    expect(ns.status).toEqual(verified);
    expect(keyHints(ns, known)).toEqual([{ userId: bob.id, hint: carol.signPub }]);
    // bob, under the key this account resolves for him, still acts as bob
    log.add(bob, rootState({ shares: [...hinted, share(eve, "viewer")] }));
    ns = log.fold();
    expect(ns.status).toEqual(verified);
    expect(roleOf(ns, eve)).toBe("viewer");

    const asBob: Signer = { account: { ...carol.account, userId: bob.id } };
    // signed with the hinted key as "bob": an impossible one is skipped as ever...
    log.add(asBob, rootState({ shares: [...hinted, share(eve, "viewer"), share(dan, "owner")] }));
    expect(log.fold().status).toEqual(verified);
    // ...and one bob could have made doesn't resolve, so it isn't checkable
    log.add(asBob, rootState({ shares: [...hinted, share(eve, "viewer"), share(dan, "viewer")] }));
    ns = log.fold();
    expect(ns.status).toMatchObject(unverifiedAt(4));
    expect(roleOf(ns, dan)).toBeNull();
    expect(ns.state.shares).toEqual([...hinted, share(eve, "viewer")]);
  });

  it("keyHints lists only entries whose hint this account resolves differently", () => {
    const stranger = user("stranger");
    const shares = [
      share(alice, "owner"),
      share(bob, "editor", eve.signPub),
      share(carol, "viewer"),
      share(stranger, "viewer"),
    ];
    const ns = Log.root(rootState({ shares })).fold();
    expect(ns.status).toEqual(verified);
    // a person this account can't resolve at all isn't a disagreement
    expect(keyHints(ns, known)).toEqual([{ userId: bob.id, hint: eve.signPub }]);
    const throws: Resolve = () => {
      throw new Error("boom");
    };
    expect(keyHints(ns, throws)).toEqual([]);
    // a log that can't be checked from its start has no shares to hint at
    expect(keyHints(Log.root(rootState({ shares }), bob).fold(), known)).toEqual([]);
  });

  it("snapshots under an earlier key stay valid after a key change", () => {
    const bob2 = user("bob", bob.id);
    const base = [share(alice, "owner"), share(bob, "editor")];
    const log = Log.root(rootState({ shares: base }));
    log.add(bob, rootState({ shares: [...base, share(carol, "viewer")] }));
    // under his new key, bob adds dan and brings his own entry's hint up to date
    const renewed = [share(alice, "owner"), share(bob, "editor", bob2.signPub), share(carol, "viewer")];
    log.add(bob2, rootState({ shares: [...renewed, share(dan, "viewer")] }));

    const bothKeys: Resolve = (id, pub) => (id === bob.id && pub === bob2.signPub ? "ok" : known(id, pub));
    const ns = log.fold({ identity: bothKeys });
    expect(ns.status).toEqual(verified);
    expect(roleOf(ns, carol)).toBe("viewer");
    expect(roleOf(ns, dan)).toBe("viewer");
    expect(keyHints(ns, bothKeys)).toEqual([]);

    // before this account accepts the new key, only the old snapshot is checkable
    const before = log.fold();
    expect(before.status).toMatchObject(unverifiedAt(2));
    expect(roleOf(before, carol)).toBe("viewer");
  });

  it("a root whose anchor key doesn't resolve is not checkable", () => {
    const aliceOff: Resolve = (id, pub) => (id === alice.id ? "mismatch" : known(id, pub));
    expect(Log.root().fold({ identity: aliceOff }).status).toMatchObject(unverifiedAt(0));
    expect(Log.root().fold().status).toEqual(verified);

    // a legacy root's anchor too: the proof vouches for the server's state, not for the key
    const legacy = (anchorKey: string) => {
      const nodeId = crypto.randomUUID();
      const state = rootState({ anchor: { user: alice.id, signPub: anchorKey }, keyCommit: null });
      return fold(nodeId, [legacySnapshot({ nodeId, state }, [])], { legacyRoot: merkleRoot([{ nodeId, state }]) });
    };
    expect(legacy(alice.signPub).status).toEqual(verified);
    const wrong = legacy(carol.signPub);
    expect(wrong.status).toMatchObject(unverifiedAt(0));
    expect(wrong.state.shares).toEqual([]);
  });
});
