/**
 * The final phase 1 review's findings, each as the probe that found it (spec §3.3 "A restriction anchors its owners",
 * "The creator of a restricted child may be its owner", §8.1 the checkpoint version window) and the mutations its
 * harness found uncaught.
 */
import { describe, expect, it } from "vitest";
import {
  acceptGrant,
  acceptGroupGrant,
  authorityDeps,
  canCheckpoint,
  checkpointPrefill,
  type GroupGrant,
  type GroupView,
  nextSnapshot,
  reissueSet,
  type State,
  type WorldInput,
  wellFormedState,
  writable,
} from "../../src/index.ts";
import {
  alice,
  at,
  bob,
  carol,
  childState,
  create,
  dan,
  firstCommit,
  gdep,
  grant,
  group,
  hidden,
  key,
  known,
  Log,
  refused,
  rekeyTo,
  rootState,
  share,
  st,
  unverified,
  user,
  verified,
  view,
  world,
  write,
  eve as zed,
} from "./helpers.ts";

const roles = (w: ReturnType<typeof world>, nodeId: string) =>
  [alice, bob, zed].map((u) => w.role(u.id, nodeId)).join(",");

describe("a restriction anchors its owners (§3.3, C1)", () => {
  /** zed's root > F (alice owner); alice makes restricted X with alice and bob as owners; bob writes to X. */
  function setup() {
    const R = Log.create(zed, rootState(zed, 1));
    const logs = [R];
    const w = (over: Partial<WorldInput> = {}) => world(logs, over);
    const F = create(zed, w(), R, childState("", 2, { kind: "folder" }));
    logs.push(F);
    write(zed, w(), F, { add: share(alice, "owner") });
    const X = create(
      alice,
      w(),
      F,
      childState("", 3, { restricted: true, shares: [share(alice, "owner"), share(bob, "owner")] }),
    );
    logs.push(X);
    write(bob, w(), X, { add: share(carol, "viewer") });
    return { R, F, X, logs, w };
  }

  it("P11: the owners of a restricted creation stay owners after its creator loses the folder above", () => {
    const { F, X, w } = setup();
    expect(roles(w(), X.nodeId)).toBe("owner,owner,");
    write(zed, w(), F, { remove: alice.id, rekey: rekeyTo(F.nodeId, 2, 20) });
    const ns = st(w(), X.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.restricted).toBe(true);
    expect(ns.state.shares.map((s) => [s.userId, s.role])).toEqual([
      [alice.id, "owner"],
      [bob.id, "owner"],
      [carol.id, "viewer"],
    ]);
    // its key was made by alice on authority from F, which lapsed: re-keyed at the next write (§3.3)
    expect(ns.stale).toBe(true);
    expect(writable(ns)).toBe("stale");
    expect(roles(w(), X.nodeId)).toBe("owner,owner,");
    // both owners can re-key it; the folder's owner has no say in a restricted node
    for (const u of [alice, bob]) {
      const r = nextSnapshot(u.account, w(), ns, { rekey: rekeyTo(X.nodeId, 2, 30) }, at);
      expect("error" in r, u === alice ? "alice" : "bob").toBe(false);
    }
    expect(refused(zed, w(), X, { rekey: rekeyTo(X.nodeId, 2, 31) })).toMatch(/skip/);
    expect(canCheckpoint(w(), ns, alice.id)).toBe(false); // verified: nothing to repair
    write(bob, w(), X, { rekey: rekeyTo(X.nodeId, 2, 30) });
    expect(st(w(), X.nodeId).stale).toBe(false);
    expect(roles(w(), X.nodeId)).toBe("owner,owner,");
  });

  it("later owners are vouched by owners that count, not by the restriction", () => {
    const { F, X, w } = setup();
    // alice adds dan as owner: dan is vouched by alice, who counts through the anchored creation
    write(alice, w(), X, { add: share(dan, "owner") });
    write(zed, w(), F, { remove: alice.id, rekey: rekeyTo(F.nodeId, 2, 20) });
    const ns = st(w(), X.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.shares.map((s) => s.userId)).toEqual([alice.id, bob.id, carol.id, dan.id]);
    expect(w().role(dan.id, X.nodeId)).toBe("owner");
  });

  it("a restrict by an owner from above is not undone when that owner lapses: it stays, stale, re-keyable by her", () => {
    // the variant: alice (owner through F) restricts an existing node keeping bob; zed then removes alice from F.
    // Letting the restriction fall back would open private content to F's members (§3.3): it stands, alice keeps
    // owner through the share the restriction anchors, and the key she made on F's authority is stale.
    const R = Log.create(zed, rootState(zed, 1));
    const logs = [R];
    const w = () => world(logs);
    const F = create(zed, w(), R, childState("", 2, { kind: "folder" }));
    logs.push(F);
    write(zed, w(), F, { add: share(alice, "owner") });
    const X = create(zed, w(), F, childState("", 3));
    logs.push(X);
    write(zed, w(), X, { add: share(bob, "owner") });
    write(alice, w(), X, {
      restrict: { shares: [share(bob, "owner")], groups: [], links: [], rekey: rekeyTo(X.nodeId, 2, 21) },
    });
    expect(st(w(), X.nodeId).state.restricted).toBe(true);
    expect(roles(w(), X.nodeId)).toBe("owner,owner,");
    write(zed, w(), F, { remove: alice.id, rekey: rekeyTo(F.nodeId, 2, 20) });
    let ns = st(w(), X.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.restricted).toBe(true);
    expect(ns.state.shares.map((s) => [s.userId, s.role])).toEqual([
      [bob.id, "owner"],
      [alice.id, "owner"],
    ]);
    expect(roles(w(), X.nodeId)).toBe("owner,owner,");
    expect(ns.stale).toBe(true);
    expect(refused(zed, w(), X, { rekey: rekeyTo(X.nodeId, 3, 31) })).toMatch(/skip/);
    write(alice, w(), X, { rekey: rekeyTo(X.nodeId, 3, 30) });
    ns = st(w(), X.nodeId);
    expect(ns.stale).toBe(false);
    expect(ns.state.restricted).toBe(true);
    expect(roles(w(), X.nodeId)).toBe("owner,owner,");
  });

  it("a removed owner's backdated unrestrict reads as restricted: the folder's members get no role", () => {
    const R = Log.create(zed, rootState(zed, 1));
    const logs = [R];
    const w = () => world(logs);
    const F = create(zed, w(), R, childState("", 2, { kind: "folder", shares: [share(dan, "editor")] }));
    logs.push(F);
    write(zed, w(), F, { add: share(bob, "owner") });
    const X = create(
      bob,
      w(),
      F,
      childState("", 3, { restricted: true, shares: [share(bob, "owner"), share(carol, "editor")] }),
    );
    logs.push(X);
    const oldDeps = [F.dep(), ...authorityDeps(w(), F.nodeId)];
    write(zed, w(), F, { remove: bob.id, rekey: rekeyTo(F.nodeId, 2, 20) });
    // nothing on X named F after bob's removal, so his unrestrict naming the old F applies; but the lift counts only
    // while he has editor on F, which he hasn't: X reads as restricted to its own owners
    X.add(bob, { ...X.state(), restricted: false }, oldDeps);
    const ns = st(w(), X.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.restricted).toBe(true);
    expect(ns.state.shares.map((s) => [s.userId, s.role])).toEqual([
      [bob.id, "owner"],
      [carol.id, "editor"],
    ]);
    expect(roles(w(), X.nodeId)).toBe(",owner,");
    expect(w().role(dan.id, X.nodeId)).toBeNull();
    expect(w().role(carol.id, X.nodeId)).toBe("editor");
    expect(refused(zed, w(), X, { rekey: rekeyTo(X.nodeId, 2, 31) })).toMatch(/skip/);
    expect(refused(dan, w(), X, { rekey: rekeyTo(X.nodeId, 2, 32) })).toMatch(/skip/);
    // the same lift by an owner who still edits the folder holds, and opens X to it
    const honest = X.upTo(1);
    const logs2 = [R, F.upTo(2), honest];
    honest.push(write(bob, world(logs2), honest, { unrestrict: F.nodeId }));
    expect(st(world(logs2), X.nodeId).state.restricted).toBe(false);
    expect(world(logs2).role(zed.id, X.nodeId)).toBe("owner");
    expect(world(logs2).role(dan.id, X.nodeId)).toBe("editor");
  });

  it("the creator of a private channel publishes it; their owner share goes with the restriction, the team's role stays", () => {
    const id = crypto.randomUUID();
    const admins = group([alice]);
    const all = group([alice, bob, carol]);
    const gv = view([admins, all], { [id]: { everyone: all, admins } });
    const T = Log.create(alice, { ...rootState(alice, 1), anchor: { team: id }, shares: [] }, [
      gdep(admins),
      gdep(all),
    ]);
    const logs = [T];
    const w = () => world(logs, { groups: gv });
    const ch = create(
      bob,
      w(),
      T,
      childState("", 2, { kind: "channel", restricted: true, shares: [share(bob, "owner")] }),
    );
    logs.push(ch);
    write(bob, w(), ch, { add: share(dan, "viewer") });
    // the lift holds: bob was its owner under the restriction and edits the team root. His owner share, which only
    // the restriction vouched for, goes with it (the writer drops it, the fold reads it as lapsed, not removed); dan's
    // viewer share, vouched by bob as an editor, stays. He is then an editor like any teammate. If the lift lapses
    // later, the channel reads as the state he lifted, with him as owner (lift-lapse.test.ts).
    const lift = write(bob, w(), ch, { unrestrict: T.nodeId });
    expect(lift.state.shares).toEqual([share(dan, "viewer")]);
    const ns = st(w(), ch.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.restricted).toBe(false);
    expect(ns.state.shares).toEqual([share(dan, "viewer")]);
    expect(w().role(bob.id, ch.nodeId)).toBe("editor");
    expect(w().role(alice.id, ch.nodeId)).toBe("owner");
    expect(w().role(carol.id, ch.nodeId)).toBe("editor");
    expect(w().role(dan.id, ch.nodeId)).toBe("viewer");
    // whoever lapsed may still hold the key: the next write re-keys (§5.2)
    expect(ns.stale).toBe(true);
    write(carol, w(), ch, { rekey: rekeyTo(ch.nodeId, 2, 30) });
    expect(st(w(), ch.nodeId).stale).toBe(false);
  });

  it("residual: a former folder owner's backdated restricted creation is their own node, shown inside the folder", () => {
    const R = Log.create(zed, rootState(zed, 1));
    const logs = [R];
    const w = () => world(logs);
    const F = create(zed, w(), R, childState("", 2, { kind: "folder" }));
    logs.push(F);
    write(zed, w(), F, { add: share(bob, "owner") });
    // what a creation under F named while bob still owned it
    const oldDeps = [F.dep(), ...authorityDeps(w(), F.nodeId)];
    write(zed, w(), F, { remove: bob.id, rekey: rekeyTo(F.nodeId, 2, 20) });
    // bob names F's state from before his removal; at seq 0 there is nothing monotonic deps can hold it to
    const Y = Log.create(bob, childState(F.nodeId, 3, { restricted: true, shares: [share(bob, "owner")] }), oldDeps);
    logs.push(Y);
    const ns = st(w(), Y.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.restricted).toBe(true);
    expect(ns.state.parentId).toBe(F.nodeId);
    expect(roles(w(), Y.nodeId)).toBe(",owner,");
    // its key rests on bob's lapsed authority from F: stale until he re-keys as its owner
    expect(ns.stale).toBe(true);
    // the folder's owner can't open it: no role, nothing to re-key with
    expect(refused(zed, w(), Y, { rekey: rekeyTo(Y.nodeId, 2, 31) })).toMatch(/skip/);
    expect(checkpointPrefill(ns).shares.map((s) => s.userId)).toEqual([bob.id]);
    write(bob, w(), Y, { rekey: rekeyTo(Y.nodeId, 2, 30) });
    expect(st(w(), Y.nodeId).stale).toBe(false);
    expect(roles(w(), Y.nodeId)).toBe(",owner,");
  });
});

describe("the creator of a restricted child may be its owner (§3.3, I4)", () => {
  /** A team: alice is its only Admin; Everyone is alice, bob and carol. */
  function team() {
    const id = crypto.randomUUID();
    const admins = group([alice]);
    const all = group([alice, bob, carol]);
    const gv = view([admins, all], { [id]: { everyone: all, admins } });
    const T = Log.create(alice, { ...rootState(alice, 1), anchor: { team: id }, shares: [] }, [
      gdep(admins),
      gdep(all),
    ]);
    const logs = [T];
    const w = (over: Partial<WorldInput> = {}) => world(logs, { groups: gv, ...over });
    return { id, admins, all, T, logs, w };
  }

  it("a teammate makes a private channel they own, with editor on the team root", () => {
    const { T, logs, w } = team();
    const ch = create(
      bob,
      w(),
      T,
      childState("", 2, { kind: "channel", restricted: true, shares: [share(bob, "owner"), share(carol, "editor")] }),
    );
    logs.push(ch);
    const ns = st(w(), ch.nodeId);
    expect(ns.status).toEqual(verified);
    expect(w().role(bob.id, ch.nodeId)).toBe("owner");
    expect(w().role(carol.id, ch.nodeId)).toBe("editor");
    expect(w().role(alice.id, ch.nodeId)).toBeNull();
    // as its owner he may then make carol an owner too
    write(bob, w(), ch, { role: { userId: carol.id, role: "owner" } });
    expect(w().role(carol.id, ch.nodeId)).toBe("owner");
  });

  it("any other owner in a creation needs owner on the parent: another person, a group, a link", () => {
    const { T, admins, logs, w } = team();
    const attempts: [string, Partial<State>][] = [
      ["another owner share", { restricted: true, shares: [share(bob, "owner"), share(carol, "owner")] }],
      [
        "a group at owner",
        { restricted: true, shares: [share(bob, "owner")], groupShares: [{ groupId: admins.id, role: "owner" }] },
      ],
      [
        "a link at owner",
        { restricted: true, shares: [share(bob, "owner")], links: [{ linkId: crypto.randomUUID(), role: "owner" }] },
      ],
      ["the creator as owner of an unrestricted child", { shares: [share(bob, "owner")] }],
      ["an unrestricted group at owner", { groupShares: [{ groupId: admins.id, role: "owner" }] }],
    ];
    for (const [what, over] of attempts) {
      const byBob = create(bob, w(), T, childState("", 2, { kind: "channel", ...over }));
      expect(st(world([...logs, byBob], { groups: w().input.groups }), byBob.nodeId).status, `bob: ${what}`).toEqual(
        unverified(0, "origin"),
      );
      const byAlice = create(alice, w(), T, childState("", 2, { kind: "channel", ...over }));
      expect(
        st(world([...logs, byAlice], { groups: w().input.groups }), byAlice.nodeId).status,
        `alice: ${what}`,
      ).toEqual(verified);
    }
  });

  it("M-a: an editor's restricted creation whose only owner is a group is refused, not left ownerless", () => {
    const { T, admins, logs, w } = team();
    const ch = create(
      bob,
      w(),
      T,
      childState("", 2, { kind: "channel", restricted: true, groupShares: [{ groupId: admins.id, role: "owner" }] }),
    );
    expect(st(world([...logs, ch], { groups: w().input.groups }), ch.nodeId).status).toEqual(unverified(0, "origin"));
  });

  it("a team root with any owner entry needs an Admin", () => {
    const { id, admins, all, w } = team();
    for (const over of [
      { shares: [share(bob, "owner")] },
      { groupShares: [{ groupId: all.id, role: "owner" as const }] },
      { links: [{ linkId: crypto.randomUUID(), role: "owner" as const }] },
    ]) {
      const root = Log.create(bob, { ...rootState(bob, 1), anchor: { team: id }, shares: [], ...over }, [
        gdep(admins),
        gdep(all),
      ]);
      expect(st(world([root], { groups: w().input.groups }), root.nodeId).status).toEqual(unverified(0, "origin"));
    }
  });
});

describe("exact shapes on the wire (I1)", () => {
  it("P2: a team root whose anchor also names a user is refused, so Everyone can't make themselves owner", () => {
    const id = crypto.randomUUID();
    const admins = group([alice]);
    const all = group([alice, bob]);
    const gv = view([admins, all], { [id]: { everyone: all, admins } });
    const both: State = {
      ...rootState(bob, 1, { shares: [] }),
      anchor: { team: id, user: bob.id, signPub: bob.signPub } as never,
    };
    expect(wellFormedState(both)).toBe(false);
    const T = Log.create(bob, both, [gdep(all), gdep(admins)]);
    const w = world([T], { groups: gv });
    expect(st(w, T.nodeId).status).toEqual(unverified(0, "origin"));
    expect(w.role(bob.id, T.nodeId)).toBeNull();
  });
});

describe("the checkpoint version window (§8.1, I2)", () => {
  it("P3: two devices whose floors differ by whom they resolve both accept the owner's checkpoint", () => {
    const R = Log.create(alice, rootState(alice, 1));
    const logs = [R];
    const w = (over: Partial<WorldInput> = {}) => world(logs, over);
    const N = create(alice, w(), R, childState("", 2));
    logs.push(N);
    write(alice, w(), N, { add: share(dan, "editor") });
    write(dan, w(), N, { add: share(carol, "viewer") }); // seq 2, by dan
    // the server appends junk: signature-valid, author unknown to everyone, one version up with a fresh commit
    const stranger = user("stranger");
    N.add(stranger, { ...N.state(), version: 2, keyCommit: firstCommit(77) });
    const noDan: WorldInput["identity"] = (id, pk) => (id === dan.id ? "unknown" : known(id, pk));
    // device A doesn't resolve dan: unverified from seq 2, floor 2 (the junk's version is one honest re-keys could reach)
    const A = w({ identity: noDan });
    const nsA = st(A, N.nodeId);
    expect(nsA.status).toEqual(unverified(2, "identity"));
    expect(nsA.stretchVersion).toBe(2);
    // device B resolves dan: the junk is skipped (nobody could have been allowed to make it), B stays verified at v1
    expect(st(w(), N.nodeId).status).toEqual(verified);
    expect(st(w(), N.nodeId).state.version).toBe(1);
    // alice checkpoints on A at floor + 1 = 3; B sees a checkpoint at seq 4 on a verified node at v1: 1 < 3 <= 1 + 4
    expect(canCheckpoint(A, nsA, alice.id)).toBe(true);
    const pre = checkpointPrefill(nsA, { userId: alice.id, signPub: alice.signPub });
    const cp = nextSnapshot(alice.account, A, nsA, { checkpoint: { state: pre, rekey: rekeyTo(N.nodeId, 3, 30) } }, at);
    if ("error" in cp) throw new Error(cp.error);
    N.push(cp);
    for (const [name, dev] of [
      ["A", w({ identity: noDan })],
      ["B", w()],
    ] as const) {
      const ns = st(dev, N.nodeId);
      expect(ns.status, name).toEqual(verified);
      expect(ns.state.version, name).toBe(3);
      expect(ns.seq, name).toBe(4);
      // the checkpoint's state is what A pre-filled: carol, added by dan whom A doesn't resolve, isn't in it
      expect(
        ns.state.shares.map((s) => s.userId),
        name,
      ).toEqual([dan.id]);
    }
    // and both devices go on from the same head: alice adds bob on B, A sees it
    write(alice, w(), N, { add: share(bob, "viewer") });
    expect(st(w({ identity: noDan }), N.nodeId).state.shares.map((s) => s.userId)).toEqual([dan.id, bob.id]);
  });

  it("the window never lets a verified node be bricked, and writers still use floor + 1", () => {
    const R = Log.create(alice, rootState(alice, 1));
    const bricked = R.clone().add(
      alice,
      { ...R.state(), version: Number.MAX_SAFE_INTEGER, keyCommit: firstCommit(5) },
      [],
      "checkpoint",
      R.head(),
    );
    expect(st(world([bricked]), R.nodeId).status).toEqual(verified);
    expect(st(world([bricked]), R.nodeId).state.version).toBe(1);
    // a checkpoint on an unverified node written by the library is at floor + 1
    const N = create(alice, world([R]), R, childState("", 2));
    N.add(alice, { ...N.state(), version: 2, keyCommit: firstCommit(20) }, [R.dep(), hidden()]);
    const ns = st(world([R, N]), N.nodeId);
    expect(ns.status).toEqual(unverified(1, "stale-dependency"));
    const pre = checkpointPrefill(ns, { userId: alice.id, signPub: alice.signPub });
    expect(pre.version).toBe(2);
    expect(
      nextSnapshot(
        alice.account,
        world([R, N]),
        ns,
        { checkpoint: { state: pre, rekey: rekeyTo(N.nodeId, 4, 30) } },
        at,
      ),
    ).toMatchObject({ error: expect.stringContaining("must be 3") });
    const cp = nextSnapshot(
      alice.account,
      world([R, N]),
      ns,
      { checkpoint: { state: pre, rekey: rekeyTo(N.nodeId, 3, 30) } },
      at,
    );
    expect("error" in cp).toBe(false);
  });
});

describe("guards the mutation harness found untested (I3)", () => {
  it("M5: a counted-removed owner's checkpoint that omits themselves is skipped", () => {
    const R = Log.create(alice, rootState(alice, 1));
    const N = create(
      alice,
      world([R]),
      R,
      childState("", 2, {
        restricted: true,
        shares: [share(alice, "owner"), share(bob, "owner"), share(carol, "editor")],
      }),
    );
    // alice removes bob with a re-key, naming a log the server hides: unverified for everyone, the removal counted
    N.add(
      alice,
      { ...N.state(), ...rekeyTo(N.nodeId, 2, 20), shares: N.state().shares.filter((s) => s.userId !== bob.id) },
      [R.dep(), hidden()],
    );
    const w = () => world([R, N]);
    let ns = st(w(), N.nodeId);
    expect(ns.status).toEqual(unverified(1, "stale-dependency"));
    expect([...ns.stretchRemovals.userIds]).toEqual([bob.id]);
    expect(canCheckpoint(w(), ns, bob.id)).toBe(false);
    expect(canCheckpoint(w(), ns, alice.id)).toBe(true);
    // bob signs a checkpoint without himself (so it fits the counted removals) that makes dan an owner; he was owner on
    // the last verified prefix, so only the guard (the prefix minus the counted removals) stops it
    const pre = checkpointPrefill(ns);
    const without = pre.shares.filter((s) => s.userId !== bob.id);
    const state: State = {
      ...pre,
      ...rekeyTo(N.nodeId, pre.version + 1, 30),
      shares: [...without, share(dan, "owner")],
    };
    const asked = { ...pre, shares: [...without, share(dan, "owner")] };
    expect(
      nextSnapshot(bob.account, w(), ns, { checkpoint: { state: asked, rekey: rekeyTo(N.nodeId, 3, 30) } }, at),
    ).toMatchObject({ error: expect.stringContaining("refused") });
    N.add(bob, state, [R.dep()], "checkpoint", N.head());
    ns = st(w(), N.nodeId);
    expect(ns.status).toEqual(unverified(1, "stale-dependency"));
    expect(ns.state.version).toBe(1);
    expect(ns.state.shares.map((s) => s.userId)).toEqual([alice.id, carol.id]);
    expect(w().role(dan.id, N.nodeId)).toBeNull();
  });

  it("M20: a roleless author's dep in the stretch raises no floor; an editor's does", () => {
    const R = Log.create(alice, rootState(alice, 1));
    const logs = [R];
    const w = () => world(logs);
    const F = create(alice, w(), R, childState("", 2, { kind: "folder" }));
    logs.push(F);
    const N = create(alice, w(), F, childState("", 3));
    logs.push(N);
    write(alice, w(), N, { add: share(bob, "editor") });
    // N goes unverified: alice re-keys naming a log the server hides, with F at seq 0
    N.add(alice, { ...N.state(), ...rekeyTo(N.nodeId, 2, 20) }, [F.dep(), R.dep(), hidden()]);
    write(alice, w(), F, { add: share(carol, "viewer") }); // F moves to seq 1, which this client has
    const ns = st(w(), N.nodeId);
    expect(ns.status).toEqual(unverified(2, "stale-dependency"));
    const pre = checkpointPrefill(ns, { userId: alice.id, signPub: alice.signPub });
    const cp = { ...pre, ...rekeyTo(N.nodeId, pre.version + 1, 30) };
    // dan resolves but has no role on N or above it; his no-op names F at seq 1
    const byDan = N.clone().add(dan, { ...N.state() }, [F.dep(1), R.dep()]);
    // alice's checkpoint names F as her device last saw it, at seq 0: dan raised no floor, so it counts
    const afterDan = byDan.clone().add(alice, cp, [F.dep(0), R.dep()], "checkpoint", byDan.head());
    expect(st(world([R, F, afterDan]), N.nodeId).status).toEqual(verified);
    expect(st(world([R, F, afterDan]), N.nodeId).state.version).toBe(3);
    // had bob, an editor on N, named F at seq 1, her checkpoint at seq 0 would be skipped: she refreshes F first
    const byBob = N.clone().add(bob, { ...N.state() }, [F.dep(1), R.dep()]);
    const afterBob = byBob.clone().add(alice, cp, [F.dep(0), R.dep()], "checkpoint", byBob.head());
    expect(st(world([R, F, afterBob]), N.nodeId).status).toEqual(unverified(2, "stale-dependency"));
    const fresh = nextSnapshot(
      alice.account,
      world([R, F, byBob]),
      st(world([R, F, byBob]), N.nodeId),
      { checkpoint: { state: pre, rekey: rekeyTo(N.nodeId, pre.version + 1, 30) } },
      at,
    );
    expect("error" in fresh).toBe(false);
    expect((fresh as { deps: { log: string; seq: number }[] }).deps.find((d) => d.log === F.nodeId)?.seq).toBe(1);
  });
});

describe("a group view that throws (M-h)", () => {
  /** A view that answers until `arm()`, then throws from every call: the fold is done, the key helpers aren't. */
  function fragile(inner: GroupView) {
    let armed = false;
    const guard =
      <A extends unknown[], R>(f: (...a: A) => R) =>
      (...a: A): R => {
        if (armed) throw new Error("boom");
        return f(...a);
      };
    const gv: GroupView = {
      latest: guard(inner.latest),
      member: guard(inner.member),
      removedAt: guard(inner.removedAt),
      removedSince: guard(inner.removedSince),
      teamGroups: guard(inner.teamGroups),
    };
    return { gv, arm: () => void (armed = true) };
  }

  it("acceptGrant answers false when the grantee's role would come from a group the view can't read", () => {
    const G = group([bob]);
    const { gv, arm } = fragile(view([G]));
    const R = Log.create(alice, rootState(alice, 1));
    const N = create(
      alice,
      world([R], { groups: gv }),
      R,
      childState("", 2, { groupShares: [{ groupId: G.id, role: "viewer" }] }),
    );
    const w = world([R, N], { groups: gv });
    const ns = st(w, N.nodeId);
    expect(ns.status).toEqual(verified);
    const g = grant(alice, bob, N.nodeId, 1, key(2));
    expect(acceptGrant(w, ns, g, key(2))).toBe(true);
    arm();
    expect(() => acceptGrant(w, ns, g, key(2))).not.toThrow();
    expect(acceptGrant(w, ns, g, key(2))).toBe(false);
  });

  it("acceptGroupGrant answers false and reissueSet leaves the team groups out when the view can't name them", () => {
    const id = crypto.randomUUID();
    const admins = group([alice]);
    const all = group([alice, bob]);
    const G = group([carol]);
    const { gv, arm } = fragile(view([admins, all, G], { [id]: { everyone: all, admins } }));
    const T = Log.create(
      alice,
      { ...rootState(alice, 1), anchor: { team: id }, shares: [], groupShares: [{ groupId: G.id, role: "viewer" }] },
      [gdep(admins), gdep(all), gdep(G)],
    );
    const w = world([T], { groups: gv });
    const ns = st(w, T.nodeId);
    expect(ns.status).toEqual(verified);
    const gg: GroupGrant = {
      nodeId: T.nodeId,
      groupId: all.id,
      keyVersion: 1,
      grantorId: alice.id,
      role: "editor",
      wrapped: "x",
    } as never;
    expect(acceptGroupGrant(w, ns, gg, key(1))).toBe(true);
    expect(reissueSet(w, ns).groups.map((g) => g.groupId)).toEqual([G.id, all.id, admins.id]);
    arm();
    expect(() => acceptGroupGrant(w, ns, gg, key(1))).not.toThrow();
    expect(acceptGroupGrant(w, ns, gg, key(1))).toBe(false);
    expect(() => reissueSet(w, ns)).not.toThrow();
    expect(reissueSet(w, ns)).toEqual({ people: [], groups: [{ groupId: G.id, role: "viewer" }], links: [] });
  });
});
