import { toBase64Url } from "@jelly/crypto";
import { describe, expect, it } from "vitest";
import {
  authorityDeps,
  type Change,
  createAccount,
  createFirstSnapshot,
  createSnapshot,
  type Dep,
  type GroupView,
  type LogEntry,
  LogWorld,
  type NodeState,
  type Role,
  type Snapshot,
  type State,
  snapshotHash,
  unlockAccount,
  type WorldInput,
} from "../../src/index.ts";

function user(handle: string) {
  const id = crypto.randomUUID();
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
const gina = user("gina");
const people = [alice, bob, carol, dan, eve, gina];

const at = "2026-10-31T10:00:00.000Z";
const commit = (n: number) => toBase64Url(new Uint8Array(32).fill(n));
const share = (u: U, role: Role) => ({ userId: u.id, role, signPub: u.signPub });
const known = (userId: string, signPub: string): "ok" | "unknown" | "mismatch" => {
  const u = people.find((x) => x.id === userId);
  return !u ? "unknown" : u.signPub === signPub ? "ok" : "mismatch";
};

/** A group's signed versions as the client verified them: the members at each version, from 0. */
type Group = { id: string; versions: U[][] };
const group = (...versions: U[][]): Group => ({ id: crypto.randomUUID(), versions });
const groupHead = (g: Group, v: number) => toBase64Url(new TextEncoder().encode(`${g.id}:${v}`));
const gdep = (g: Group, v = g.versions.length - 1, head = groupHead(g, v)): Dep => ({
  log: `group:${g.id}`,
  seq: v,
  head,
});

/** A GroupView over the given groups and teams; `over` replaces any of its answers. */
function view(
  gs: Group[],
  teams: Record<string, { everyone: Group; admins: Group }> = {},
  over: Partial<GroupView> = {},
) {
  const find = (id: string) => gs.find((g) => g.id === id);
  const base: GroupView = {
    latest: (id) => {
      const g = find(id);
      return g ? { version: g.versions.length - 1, head: groupHead(g, g.versions.length - 1) } : null;
    },
    member: (id, v, userId) => find(id)?.versions[v]?.some((u) => u.id === userId) ?? false,
    // the first version after `after` at which they're no longer a member, having been one just before
    removedAt: (id, userId, after) => {
      const g = find(id);
      if (!g) return null;
      const has = (v: number) => g.versions[v]?.some((u) => u.id === userId) ?? false;
      for (let v = Math.max(after + 1, 1); v < g.versions.length; v++) if (has(v - 1) && !has(v)) return v;
      return null;
    },
    // whether anyone who was a member at `version` isn't one at the newest version
    removedSince: (id, version) => {
      const g = find(id);
      if (!g) return false;
      const latest = g.versions[g.versions.length - 1] ?? [];
      return (g.versions[version] ?? []).some((u) => !latest.some((x) => x.id === u.id));
    },
    teamGroups: (teamId) => {
      const t = teams[teamId];
      return t ? { everyone: t.everyone.id, admins: t.admins.id } : null;
    },
  };
  return { ...base, ...over };
}

const teamRoot = (team: string, over: Partial<State> = {}): State => ({
  kind: "folder",
  parentId: null,
  anchor: { team },
  restricted: false,
  version: 1,
  keyCommit: commit(1),
  shares: [],
  groupShares: [],
  links: [],
  ...over,
});

const folderState = (over: Partial<State> = {}): State => ({
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

const childState = (parentId: string, over: Partial<State> = {}): State => ({
  kind: "page",
  parentId,
  anchor: null,
  restricted: false,
  version: 1,
  keyCommit: commit(1),
  shares: [],
  groupShares: [],
  links: [],
  ...over,
});

class Log {
  entries: LogEntry[] = [];
  readonly nodeId: string;
  constructor(nodeId: string) {
    this.nodeId = nodeId;
  }
  static create(by: U, state: State, deps: Dep[] = []): Log {
    const first = createFirstSnapshot(by.account, { state, deps, at });
    const log = new Log(first.nodeId);
    log.entries.push(first);
    return log;
  }
  last(): Snapshot {
    return this.entries[this.entries.length - 1] as Snapshot;
  }
  dep(seq = this.last().seq): Dep {
    return { log: this.nodeId, seq, head: snapshotHash(this.entries[seq] as Snapshot) };
  }
  add(by: U, state: State, deps: Dep[] = [], change: Change = "change"): this {
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
        deps,
        at,
      }),
    );
    return this;
  }
}

function world(logs: Log[], groups: GroupView, over: Partial<WorldInput> = {}): LogWorld {
  return new LogWorld({
    logs: new Map(logs.map((l) => [l.nodeId, l.entries])),
    legacyRoot: null,
    identity: known,
    groups,
    ...over,
  });
}

const st = (w: LogWorld, id: string): NodeState => {
  const ns = w.state(id);
  if (!ns) throw new Error("no state");
  return ns;
};
const verified = { kind: "verified" };
const shareIds = (ns: NodeState) => ns.state.shares.map((s) => s.userId).sort();
const ids = (...us: U[]) => us.map((u) => u.id).sort();

/** A team: alice is its only Admin; Everyone is alice, bob, carol and dan. */
function team(everyone: U[][] = [[alice, bob, carol, dan]]) {
  const id = crypto.randomUUID();
  const admins = group([alice]);
  const all = group(...everyone);
  const gv = view([admins, all], { [id]: { everyone: all, admins } });
  return { id, admins, all, gv };
}

describe("groups and teams", () => {
  it("admins own a team root, everyone edits it", () => {
    const t = team();
    const root = Log.create(alice, teamRoot(t.id), [gdep(t.admins), gdep(t.all)]);
    let w = world([root], t.gv);
    expect(st(w, root.nodeId).status).toEqual(verified);
    expect(w.role(alice.id, root.nodeId)).toBe("owner");
    expect(w.role(bob.id, root.nodeId)).toBe("editor");
    expect(w.role(eve.id, root.nodeId)).toBeNull();

    // bob, in Everyone, may re-key and add a viewer, naming Everyone
    root.add(bob, teamRoot(t.id, { version: 2, keyCommit: commit(2) }), [gdep(t.all)]);
    root.add(bob, teamRoot(t.id, { version: 2, keyCommit: commit(2), shares: [share(gina, "viewer")] }), [gdep(t.all)]);
    w = world([root], t.gv);
    expect(st(w, root.nodeId).state.version).toBe(2);
    expect(shareIds(st(w, root.nodeId))).toEqual(ids(gina));
    // without naming the group his role isn't there
    root.add(bob, teamRoot(t.id, { version: 3, keyCommit: commit(3), shares: [share(gina, "viewer")] }));
    w = world([root], t.gv);
    expect(st(w, root.nodeId).state.version).toBe(2);
    expect(st(w, root.nodeId).status).toEqual(verified);
    // alice, an Admin, may remove gina
    root.add(alice, teamRoot(t.id, { version: 3, keyCommit: commit(3) }), [gdep(t.admins)]);
    w = world([root], t.gv);
    expect(st(w, root.nodeId).state.version).toBe(3);
    expect(st(w, root.nodeId).state.shares).toEqual([]);

    // a page bob makes in the team root is the team's
    const page = Log.create(bob, childState(root.nodeId), [root.dep(), gdep(t.all)]);
    w = world([root, page], t.gv);
    expect(st(w, page.nodeId).status).toEqual(verified);
    expect(w.role(alice.id, page.nodeId)).toBe("owner");
    expect(w.role(bob.id, page.nodeId)).toBe("editor");

    // only a member may start a team root, and an owner share in it needs an Admin
    const byEve = Log.create(eve, teamRoot(t.id), [gdep(t.all)]);
    expect(st(world([byEve], t.gv), byEve.nodeId).status).toMatchObject({ kind: "unverified", atSeq: 0 });
    const bobOwner = Log.create(bob, teamRoot(t.id, { shares: [share(bob, "owner")] }), [gdep(t.all)]);
    expect(st(world([bobOwner], t.gv), bobOwner.nodeId).status).toMatchObject({ kind: "unverified", atSeq: 0 });
    // a team the client can't see isn't checkable
    // a group version newer than the client has is a stale dependency, at a team root too
    const newer = Log.create(alice, teamRoot(t.id), [
      gdep(t.admins, 1, groupHead(t.admins, 1)),
      gdep(t.all, 1, groupHead(t.all, 1)),
    ]);
    expect(st(world([newer], t.gv), newer.nodeId).status).toEqual({
      kind: "unverified",
      atSeq: 0,
      reason: "stale-dependency",
    });
    const unseen = Log.create(alice, teamRoot(crypto.randomUUID()), [gdep(t.admins)]);
    expect(st(world([unseen], t.gv), unseen.nodeId).status).toMatchObject({
      kind: "unverified",
      atSeq: 0,
      reason: "needs-team",
    });
  });

  it("a teammate outside Admins is no owner", () => {
    const t = team();
    const root = Log.create(alice, teamRoot(t.id, { shares: [share(gina, "viewer")] }), [gdep(t.admins), gdep(t.all)]);
    // dan is a teammate the server names, but only in Everyone: no removal, no owner share, no restrict
    root.add(dan, teamRoot(t.id, { version: 2, keyCommit: commit(2) }), [gdep(t.admins), gdep(t.all)]);
    root.add(dan, teamRoot(t.id, { shares: [share(gina, "viewer"), share(dan, "owner")] }), [
      gdep(t.admins),
      gdep(t.all),
    ]);
    root.add(dan, teamRoot(t.id, { shares: [share(gina, "owner")] }), [gdep(t.admins), gdep(t.all)]);
    const w = world([root], t.gv);
    const ns = st(w, root.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.version).toBe(1);
    expect(ns.state.shares).toEqual([share(gina, "viewer")]);
    expect(w.role(dan.id, root.nodeId)).toBe("editor");
  });

  it("a group share counts for its members at the version named, and only when named", () => {
    const g = group([bob], [bob, carol]);
    const gv = view([g]);
    const p = Log.create(alice, folderState({ groupShares: [{ groupId: g.id, role: "editor" }] }));
    // carol joined at v1: naming v0 she's no member
    p.add(carol, folderState({ groupShares: [{ groupId: g.id, role: "editor" }], version: 2, keyCommit: commit(2) }), [
      gdep(g, 0),
    ]);
    // bob without naming the group gets nothing
    p.add(bob, folderState({ groupShares: [{ groupId: g.id, role: "editor" }], version: 2, keyCommit: commit(2) }));
    let w = world([p], gv);
    expect(st(w, p.nodeId).state.version).toBe(1);
    expect(st(w, p.nodeId).status).toEqual(verified);
    p.add(carol, folderState({ groupShares: [{ groupId: g.id, role: "editor" }], version: 2, keyCommit: commit(2) }), [
      gdep(g, 1),
    ]);
    w = world([p], gv);
    expect(st(w, p.nodeId).state.version).toBe(2);
    expect(w.role(carol.id, p.nodeId)).toBe("editor");
    expect(w.role(dan.id, p.nodeId)).toBeNull();
    // and a child names the group its creator's role comes from
    const c = Log.create(bob, childState(p.nodeId), [p.dep(), gdep(g)]);
    w = world([p, c], gv);
    expect(st(w, c.nodeId).status).toEqual(verified);
    expect(w.role(bob.id, c.nodeId)).toBe("editor");
    expect(authorityDeps(w, c.nodeId)).toEqual([p.dep(), gdep(g)]);
  });

  it("a teammate who left loses their share, a guest doesn't", () => {
    // carol leaves the team at Everyone v1
    const t = team([
      [alice, bob, carol],
      [alice, bob],
    ]);
    const root = Log.create(alice, teamRoot(t.id), [gdep(t.admins), gdep(t.all, 0)]);
    const page = Log.create(
      alice,
      childState(root.nodeId, { shares: [share(carol, "editor"), share(gina, "viewer")] }),
      [root.dep(), gdep(t.admins), gdep(t.all, 0)],
    );
    let w = world([root, page], t.gv);
    let ns = st(w, page.nodeId);
    expect(ns.status).toEqual(verified);
    expect(shareIds(ns)).toEqual(ids(gina));
    expect(ns.stale).toBe(true);
    expect(w.role(carol.id, page.nodeId)).toBeNull();
    expect(w.role(gina.id, page.nodeId)).toBe("viewer");

    // alice drops carol without a re-key, naming the newer Everyone: not a removal, but still stale
    const drop = new Log(page.nodeId);
    drop.entries = [...page.entries];
    drop.add(alice, childState(root.nodeId, { shares: [share(gina, "viewer")] }), authorityDeps(w, page.nodeId));
    ns = st(world([root, drop], t.gv), page.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.seq).toBe(1);
    expect(ns.deps.get(`group:${t.all.id}`)?.seq).toBe(1);
    expect(ns.stale).toBe(true);

    // her backdated re-key, naming Everyone from before she left, applies but doesn't make it fresh
    const back = new Log(page.nodeId);
    back.entries = [...page.entries];
    back.add(
      carol,
      childState(root.nodeId, {
        shares: [share(carol, "editor"), share(gina, "viewer")],
        version: 2,
        keyCommit: commit(2),
      }),
      [root.dep(), gdep(t.all, 0)],
    );
    ns = st(world([root, back], t.gv), page.nodeId);
    expect(ns.state.version).toBe(2);
    expect(ns.stale).toBe(true);
    // naming the Everyone that shows her gone, her share gives her nothing
    const named = new Log(page.nodeId);
    named.entries = [...page.entries];
    named.add(
      carol,
      childState(root.nodeId, {
        shares: [share(carol, "editor"), share(gina, "viewer")],
        version: 2,
        keyCommit: commit(2),
      }),
      [root.dep(), gdep(t.all, 1)],
    );
    ns = st(world([root, named], t.gv), page.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.version).toBe(1);

    // alice's re-key leaves her out and the page is fresh
    page.add(
      alice,
      childState(root.nodeId, { shares: [share(gina, "viewer")], version: 2, keyCommit: commit(2) }),
      authorityDeps(w, page.nodeId),
    );
    w = world([root, page], t.gv);
    ns = st(w, page.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.version).toBe(2);
    expect(shareIds(ns)).toEqual(ids(gina));
    expect(ns.stale).toBe(false);
  });

  it("a withheld membership proof voids nothing", () => {
    const t = team([
      [alice, bob, carol],
      [alice, bob],
    ]);
    const build = () => {
      const root = Log.create(alice, teamRoot(t.id), [gdep(t.admins), gdep(t.all, 0)]);
      const page = Log.create(alice, childState(root.nodeId, { shares: [share(carol, "editor")] }), [
        root.dep(),
        gdep(t.admins),
        gdep(t.all, 0),
      ]);
      return [root, page] as const;
    };
    for (const removedAt of [() => null, () => 2]) {
      const [root, page] = build();
      // a client without the proof doesn't see the removal at all
      const w = world([root, page], { ...t.gv, removedAt, removedSince: () => false });
      const ns = st(w, page.nodeId);
      expect(ns.status).toEqual(verified);
      expect(shareIds(ns)).toEqual(ids(carol));
      expect(ns.stale).toBe(false);
    }
  });

  it("a guest share to someone who already left, named with the version that shows it, stands", () => {
    const t = team([
      [alice, bob, carol],
      [alice, bob],
    ]);
    const root = Log.create(alice, teamRoot(t.id), [gdep(t.admins), gdep(t.all)]);
    const page = Log.create(alice, childState(root.nodeId, { shares: [share(carol, "viewer")] }), [
      root.dep(),
      gdep(t.admins),
      gdep(t.all, 1),
    ]);
    const ns = st(world([root, page], t.gv), page.nodeId);
    expect(ns.status).toEqual(verified);
    expect(shareIds(ns)).toEqual(ids(carol));
    expect(ns.stale).toBe(false);
  });

  it("a teammate who left, came back and left again loses their share again", () => {
    const t = team([
      [alice, bob, carol],
      [alice, bob],
      [alice, bob, carol],
      [alice, bob],
    ]);
    const root = Log.create(alice, teamRoot(t.id), [gdep(t.admins), gdep(t.all, 2)]);
    const page = Log.create(alice, childState(root.nodeId, { shares: [share(carol, "editor")] }), [
      root.dep(),
      gdep(t.admins),
      gdep(t.all, 2),
    ]);
    const w = world([root, page], t.gv);
    const ns = st(w, page.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.shares).toEqual([]);
    expect(ns.stale).toBe(true);
    expect(w.role(carol.id, page.nodeId)).toBeNull();
  });

  it("a teammate who left can't act on their share by leaving Everyone out of the deps", () => {
    const t = team([
      [alice, bob, carol],
      [alice, bob],
    ]);
    const root = Log.create(alice, teamRoot(t.id), [gdep(t.admins), gdep(t.all, 0)]);
    const page = Log.create(
      alice,
      childState(root.nodeId, { shares: [share(carol, "editor"), share(gina, "viewer")] }),
      [root.dep(), gdep(t.admins), gdep(t.all, 0)],
    );
    page.add(
      carol,
      childState(root.nodeId, {
        shares: [share(carol, "editor"), share(gina, "viewer")],
        version: 2,
        keyCommit: commit(2),
      }),
      [root.dep(), gdep(t.admins)],
    );
    const ns = st(world([root, page], t.gv), page.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.version).toBe(1);
    expect(shareIds(ns)).toEqual(ids(gina));
  });

  it("a stale group version is refused", () => {
    // bob leaves the group at v1
    const g = group([bob], []);
    const gv = view([g]);
    const gs = [{ groupId: g.id, role: "editor" as Role }];
    const p = Log.create(alice, folderState({ groupShares: gs }));
    p.add(alice, folderState({ groupShares: gs, shares: [share(alice, "owner"), share(dan, "viewer")] }), [gdep(g, 1)]);
    // naming the group from before he left, after a snapshot named the newer one: skipped
    p.add(
      bob,
      folderState({
        groupShares: gs,
        shares: [share(alice, "owner"), share(dan, "viewer")],
        version: 2,
        keyCommit: commit(2),
      }),
      [gdep(g, 0)],
    );
    let ns = st(world([p], gv), p.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.version).toBe(1);

    const base = folderState({ groupShares: gs, shares: [share(alice, "owner"), share(dan, "viewer")] });
    const next = { ...base, version: 2, keyCommit: commit(2) };
    // a version newer than the client has, or a forked head, isn't checkable
    const newer = Log.create(alice, base);
    newer.add(alice, next, [gdep(g, 2, groupHead(g, 2))]);
    ns = st(world([newer], gv), newer.nodeId);
    expect(ns.status).toEqual({ kind: "unverified", atSeq: 1, reason: "stale-dependency" });
    const forked = Log.create(alice, base);
    forked.add(alice, next, [gdep(g, 1, commit(9))]);
    expect(st(world([forked], gv), forked.nodeId).status).toEqual({
      kind: "unverified",
      atSeq: 1,
      reason: "stale-dependency",
    });
    // and a group the client has no view of
    const unseen = Log.create(alice, base);
    unseen.add(alice, next, [gdep(group([bob]))]);
    expect(st(world([unseen], gv), unseen.nodeId).status).toEqual({
      kind: "unverified",
      atSeq: 1,
      reason: "needs-group",
    });
  });

  it("a leave of a share that lapsed is skipped, with or without a group share above", () => {
    const results: unknown[] = [];
    // "unchecked": the leave names a group the client has no view of. As a viewer group it can't
    // make bob's voucher hold, so the leave is skipped either way; as an editor group it might.
    for (const kind of ["none", "unnamed", "named", "unchecked", "unchecked-editor"] as const) {
      const g = group(kind === "unchecked-editor" ? [bob] : [dan]);
      const role: Role = kind === "unchecked-editor" ? "editor" : "viewer";
      const gs = kind === "none" ? [] : [{ groupId: g.id, role }];
      const gv = view(kind === "named" ? [g] : []);
      const top = Log.create(
        alice,
        folderState({ shares: [share(alice, "owner"), share(bob, "editor")], groupShares: gs }),
      );
      const p1 = Log.create(alice, childState(top.nodeId, { kind: "folder" }), [top.dep()]);
      const before = top.dep();
      const c = Log.create(alice, childState(p1.nodeId), [p1.dep(), top.dep()]);
      top.add(
        alice,
        folderState({ shares: [share(alice, "owner")], groupShares: gs, version: 2, keyCommit: commit(2) }),
      );
      c.add(bob, childState(p1.nodeId, { shares: [share(carol, "editor")] }), [p1.dep(), before]);
      let w = world([top, p1, c], gv);
      let deps = authorityDeps(w, c.nodeId);
      if (kind === "named") expect(deps).toContainEqual(gdep(g));
      if (kind.startsWith("unchecked")) deps = [...deps, gdep(g)];
      c.add(carol, childState(p1.nodeId), deps, "leave");
      w = world([top, p1, c], gv);
      const ns = st(w, c.nodeId);
      results.push({ status: ns.status, topDep: ns.deps.get(top.nodeId)?.seq });
    }
    expect(results).toEqual([
      { status: verified, topDep: 0 },
      { status: verified, topDep: 0 },
      { status: verified, topDep: 0 },
      { status: verified, topDep: 0 },
      { status: { kind: "unverified", atSeq: 2, reason: "needs-group" }, topDep: 0 },
    ]);
  });
});
