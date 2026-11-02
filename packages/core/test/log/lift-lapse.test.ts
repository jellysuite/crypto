/**
 * A lapsed lift reads as the state it lifted (spec §3.3, user call 2026-10-31): the restricted state just before the
 * lift with its anchored owners counting again, minus removals made since (removals never lapse), plus additions made
 * since judged as usual. So the writer may drop a lifter's restriction-only owner share when publishing (the 8b
 * behaviour, 5f7d4ff3) without the lift's later lapse leaving the node ownerless (the 8a×8b orphan, 1141b1c2).
 */
import { describe, expect, it } from "vitest";
import { canCheckpoint, checkpointPrefill, writable } from "../../src/index.ts";
import {
  alice,
  bob,
  carol,
  childState,
  create,
  dan,
  eve,
  gdep,
  group,
  hidden,
  Log,
  refused,
  rekeyTo,
  rootState,
  share,
  st,
  verified,
  view,
  world,
  write,
} from "./helpers.ts";

const roles = (w: ReturnType<typeof world>, nodeId: string) =>
  [alice, bob, carol, dan, eve].map((u) => w.role(u.id, nodeId) ?? "-").join(",");

/**
 * alice's root R > folder F (bob editor, carol editor unless given another role); bob makes a private channel X under
 * F (his owner share anchored by the restriction), adds dan as a viewer and publishes it through the library. The
 * published node is stale (his share went as lapsed, §5.2), so anything but a re-key waits for one.
 */
function published(carolOnF: "editor" | "owner" = "editor") {
  const R = Log.create(alice, rootState(alice, 1));
  const logs = [R];
  const w = () => world(logs);
  const F = create(
    alice,
    w(),
    R,
    childState("", 2, { kind: "folder", shares: [share(bob, "editor"), share(carol, carolOnF)] }),
  );
  logs.push(F);
  const X = create(
    bob,
    w(),
    F,
    childState("", 3, { kind: "channel", restricted: true, shares: [share(bob, "owner")] }),
  );
  logs.push(X);
  write(bob, w(), X, { add: share(dan, "viewer") });
  const lift = write(bob, w(), X, { unrestrict: F.nodeId });
  return { R, F, X, logs, w, lift };
}

/** bob (and whoever else is named) loses their role above: alice removes them from F, re-keying each time. */
const removeBob = (w: () => ReturnType<typeof world>, F: Log, ...others: (typeof bob)[]) => {
  for (const [i, u] of [bob, ...others].entries())
    write(alice, w(), F, { remove: u.id, rekey: rekeyTo(F.nodeId, 2 + i, 20 + i) });
};

describe("a lapsed lift reads as the state it lifted (§3.3)", () => {
  it("L1: the creator publishes, then loses editor above: the channel is private again with him as owner", () => {
    const { F, X, w, lift } = published();
    // the writer drops his restriction-only owner share with the lift (8b); dan's viewer share stays
    expect(lift.state.shares).toEqual([share(dan, "viewer")]);
    let ns = st(w(), X.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.restricted).toBe(false);
    expect(roles(w(), X.nodeId)).toBe("owner,editor,editor,viewer,-");
    removeBob(w, F);
    ns = st(w(), X.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.restricted).toBe(true);
    // the state he lifted: his anchored owner share counts again, dan keeps the role he had under the restriction
    expect(ns.state.shares).toEqual([share(dan, "viewer"), share(bob, "owner")]);
    expect(roles(w(), X.nodeId)).toBe("-,owner,-,viewer,-");
    // the key rests on his lapsed authority from F: stale, and only he can re-key it
    expect(ns.stale).toBe(true);
    expect(writable(ns)).toBe("stale");
    for (const u of [alice, carol, dan, eve])
      expect(refused(u, w(), X, { rekey: rekeyTo(X.nodeId, 2, 30) })).toMatch(/skip/);
    write(bob, w(), X, { rekey: rekeyTo(X.nodeId, 2, 30) });
    ns = st(w(), X.nodeId);
    expect(ns).toMatchObject({ status: verified, stale: false, state: { restricted: true, version: 2 } });
    expect(roles(w(), X.nodeId)).toBe("-,owner,-,viewer,-");
    // and he can run it as a private channel again
    write(bob, w(), X, { add: share(carol, "viewer") });
    expect(roles(w(), X.nodeId)).toBe("-,owner,viewer,viewer,-");
  });

  it("L2: an editor on a folder publishes a restricted node she made, then is removed from the folder", () => {
    const R = Log.create(eve, rootState(eve, 1));
    const logs = [R];
    const w = () => world(logs);
    const F = create(eve, w(), R, childState("", 2, { kind: "folder" }));
    logs.push(F);
    write(eve, w(), F, { add: share(alice, "editor") });
    write(eve, w(), F, { add: share(dan, "viewer") });
    const X = create(
      alice,
      w(),
      F,
      childState("", 3, { restricted: true, shares: [share(alice, "owner"), share(carol, "editor")] }),
    );
    logs.push(X);
    const lift = write(alice, w(), X, { unrestrict: F.nodeId });
    expect(lift.state.shares).toEqual([share(carol, "editor")]);
    expect(roles(w(), X.nodeId)).toBe("editor,-,editor,viewer,owner");
    write(eve, w(), F, { remove: alice.id, rekey: rekeyTo(F.nodeId, 2, 20) });
    const ns = st(w(), X.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.restricted).toBe(true);
    expect(ns.state.shares).toEqual([share(carol, "editor"), share(alice, "owner")]);
    expect(roles(w(), X.nodeId)).toBe("owner,-,editor,-,-");
    expect(ns.stale).toBe(true);
    for (const u of [bob, carol, dan, eve])
      expect(refused(u, w(), X, { rekey: rekeyTo(X.nodeId, 2, 30) })).toMatch(/skip/);
    // confidentiality over availability: the folder's owner has no role on it any more (he can trash it, not open it)
    expect(refused(eve, w(), X, { unrestrict: F.nodeId })).toMatch(/stale/);
    write(alice, w(), X, { rekey: rekeyTo(X.nodeId, 2, 30) });
    expect(st(w(), X.nodeId)).toMatchObject({ status: verified, stale: false, state: { restricted: true } });
    expect(roles(w(), X.nodeId)).toBe("owner,-,editor,-,-");
  });

  it("L1c: an editor re-keys and adds to the published channel before the creator lapses", () => {
    const { F, X, w } = published();
    write(carol, w(), X, { rekey: rekeyTo(X.nodeId, 2, 30) });
    write(carol, w(), X, { add: share(eve, "viewer") });
    removeBob(w, F);
    const ns = st(w(), X.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.restricted).toBe(true);
    // bob and dan from the state he lifted; eve's share, vouched by carol whose authority above still holds,
    // is judged as usual and stands
    expect(ns.state.shares).toEqual([share(dan, "viewer"), share(eve, "viewer"), share(bob, "owner")]);
    expect(roles(w(), X.nodeId)).toBe("-,owner,-,viewer,viewer");
    // carol made the key on the folder's authority, which a restricted node doesn't read: stale, bob re-keys
    expect(ns.stale).toBe(true);
    for (const u of [alice, carol, dan, eve])
      expect(refused(u, w(), X, { rekey: rekeyTo(X.nodeId, 3, 31) })).toMatch(/skip/);
    write(bob, w(), X, { rekey: rekeyTo(X.nodeId, 3, 31) });
    expect(st(w(), X.nodeId)).toMatchObject({ status: verified, stale: false, state: { restricted: true } });
    expect(roles(w(), X.nodeId)).toBe("-,owner,-,viewer,viewer");
  });

  it("L1d: the creator re-keys as an editor after publishing, then lapses: stale, and he re-keys as owner", () => {
    const { F, X, w } = published();
    write(bob, w(), X, { rekey: rekeyTo(X.nodeId, 2, 30) });
    expect(st(w(), X.nodeId).stale).toBe(false);
    removeBob(w, F);
    const ns = st(w(), X.nodeId);
    expect(ns).toMatchObject({ status: verified, stale: true, state: { restricted: true } });
    expect(ns.state.shares).toEqual([share(dan, "viewer"), share(bob, "owner")]);
    expect(refused(alice, w(), X, { rekey: rekeyTo(X.nodeId, 3, 31) })).toMatch(/skip/);
    write(bob, w(), X, { rekey: rekeyTo(X.nodeId, 3, 31) });
    expect(st(w(), X.nodeId)).toMatchObject({ status: verified, stale: false, state: { restricted: true } });
  });

  it("a removal made after the lift still applies once it lapses: removals never lapse", () => {
    // carol, owner through F, removes dan from the open channel with a re-key. Her write vouches for the open state
    // too (an owner's snapshot containing it), so the lift lapses only once she loses F as well
    const { F, X, w } = published("owner");
    write(carol, w(), X, { remove: dan.id, rekey: rekeyTo(X.nodeId, 2, 30) });
    expect(st(w(), X.nodeId).state.shares).toEqual([]);
    removeBob(w, F, carol);
    const ns = st(w(), X.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.restricted).toBe(true);
    expect(ns.state.shares).toEqual([share(bob, "owner")]);
    expect(roles(w(), X.nodeId)).toBe("-,owner,-,-,-");
    write(bob, w(), X, { rekey: rekeyTo(X.nodeId, 3, 31) });
    expect(roles(w(), X.nodeId)).toBe("-,owner,-,-,-");
  });

  it("a demotion made after the lift still applies once it lapses, like a removal", () => {
    const R = Log.create(alice, rootState(alice, 1));
    const logs = [R];
    const w = () => world(logs);
    const F = create(
      alice,
      w(),
      R,
      childState("", 2, { kind: "folder", shares: [share(bob, "editor"), share(carol, "owner")] }),
    );
    logs.push(F);
    const X = create(bob, w(), F, childState("", 3, { restricted: true, shares: [share(bob, "owner")] }));
    logs.push(X);
    // dan was an editor under the restriction; on the open channel carol (owner through F) brings him down to viewer
    write(bob, w(), X, { add: share(dan, "editor") });
    write(bob, w(), X, { unrestrict: F.nodeId });
    write(carol, w(), X, { rekey: rekeyTo(X.nodeId, 2, 30) });
    write(carol, w(), X, { role: { userId: dan.id, role: "viewer" } });
    expect(st(w(), X.nodeId).state.restricted).toBe(false);
    removeBob(w, F, carol);
    const ns = st(w(), X.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.restricted).toBe(true);
    expect(ns.state.shares).toEqual([share(dan, "viewer"), share(bob, "owner")]);
    expect(roles(w(), X.nodeId)).toBe("-,owner,-,viewer,-");
  });

  it("an addition made after the lift by someone whose authority came only through the open chain lapses with it", () => {
    const { F, X, w } = published("owner");
    // bob, now an editor like any folder member, re-keys and adds eve; carol, owner through F, makes dan an editor
    write(bob, w(), X, { rekey: rekeyTo(X.nodeId, 2, 30) });
    write(bob, w(), X, { add: share(eve, "viewer") });
    write(carol, w(), X, { role: { userId: dan.id, role: "editor" } });
    expect(roles(w(), X.nodeId)).toBe("owner,editor,owner,editor,viewer");
    removeBob(w, F, carol);
    const ns = st(w(), X.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.restricted).toBe(true);
    // eve, vouched by bob as an editor through F, lapses with him; dan's editor role, vouched by carol as an owner
    // through F, lapses with her: he is the viewer the lifted state made him
    expect(ns.state.shares).toEqual([share(dan, "viewer"), share(bob, "owner")]);
    expect(roles(w(), X.nodeId)).toBe("-,owner,-,viewer,-");
    expect(ns.stale).toBe(true);
    for (const u of [alice, carol, dan, eve])
      expect(refused(u, w(), X, { rekey: rekeyTo(X.nodeId, 3, 31) })).toMatch(/skip/);
    write(bob, w(), X, { rekey: rekeyTo(X.nodeId, 3, 31) });
    expect(st(w(), X.nodeId)).toMatchObject({ status: verified, stale: false, state: { restricted: true } });
    expect(roles(w(), X.nodeId)).toBe("-,owner,-,viewer,-");
  });

  it("a later owner's write to the open node vouches for the lift: it stands when the lifter alone lapses", () => {
    const { F, X, w } = published();
    write(alice, w(), X, { rekey: rekeyTo(X.nodeId, 2, 30) });
    removeBob(w, F);
    const ns = st(w(), X.nodeId);
    // open, on alice's say; stale as any node below a folder that removed someone since the key (§5.2)
    expect(ns).toMatchObject({ status: verified, stale: true, state: { restricted: false } });
    expect(roles(w(), X.nodeId)).toBe("owner,-,editor,viewer,-");
    write(carol, w(), X, { rekey: rekeyTo(X.nodeId, 3, 31) });
    expect(st(w(), X.nodeId)).toMatchObject({ stale: false, state: { restricted: false } });
  });

  it("lifting drops a co-owner the creator-owner added, without a re-key; a lapse brings her back", () => {
    const R = Log.create(eve, rootState(eve, 1));
    const logs = [R];
    const w = () => world(logs);
    const F = create(eve, w(), R, childState("", 2, { kind: "folder", shares: [share(alice, "editor")] }));
    logs.push(F);
    const X = create(alice, w(), F, childState("", 3, { restricted: true, shares: [share(alice, "owner")] }));
    logs.push(X);
    write(alice, w(), X, { add: share(carol, "owner") });
    write(alice, w(), X, { add: share(dan, "viewer") });
    const lift = write(alice, w(), X, { unrestrict: F.nodeId });
    // carol's owner share was vouched by alice as an owner, which she isn't on the open node: it goes with the lift
    expect(lift.state.shares).toEqual([share(dan, "viewer")]);
    expect(lift.state.version).toBe(1);
    expect(st(w(), X.nodeId)).toMatchObject({ status: verified, stale: true, state: { restricted: false } });
    expect(roles(w(), X.nodeId)).toBe("editor,-,-,viewer,owner");
    write(eve, w(), F, { remove: alice.id, rekey: rekeyTo(F.nodeId, 2, 20) });
    const ns = st(w(), X.nodeId);
    expect(ns.state.restricted).toBe(true);
    expect(ns.state.shares).toEqual([share(dan, "viewer"), share(alice, "owner"), share(carol, "owner")]);
    expect(roles(w(), X.nodeId)).toBe("owner,-,owner,viewer,-");
  });

  it("the anchored owner's re-key after a lapse restricts the applied state again, anchoring him anew", () => {
    const { F, X, w } = published();
    removeBob(w, F);
    const rekey = write(bob, w(), X, { rekey: rekeyTo(X.nodeId, 2, 30) });
    // the snapshot itself is restricted with his owner share: nothing reads the lapsed lift any more
    expect(rekey.state.restricted).toBe(true);
    expect(rekey.state.shares).toEqual([share(dan, "viewer"), share(bob, "owner")]);
    const ns = st(w(), X.nodeId);
    expect(ns).toMatchObject({ status: verified, stale: false, state: { restricted: true, version: 2 } });
    expect(canCheckpoint(w(), ns, bob.id)).toBe(false);
    // alice, owner of the folder, has no role on it; bob, no longer an editor of F, can't open it to F again
    expect(refused(alice, w(), X, { unrestrict: F.nodeId })).toMatch(/skip/);
    expect(refused(bob, w(), X, { unrestrict: F.nodeId })).toMatch(/skip/);
    expect(roles(w(), X.nodeId)).toBe("-,owner,-,viewer,-");
  });

  it("a removal made in a stretch and confirmed by a checkpoint counts against the lift once it lapses", () => {
    const { R, F, X, w } = published("owner");
    write(carol, w(), X, { rekey: rekeyTo(X.nodeId, 2, 30) });
    // a snapshot naming a log the client isn't shown makes X unverified; carol then removes dan in the stretch
    X.add(carol, { ...X.state(), shares: [...X.state().shares, share(eve, "viewer")] }, [hidden(), F.dep(), R.dep()]);
    X.add(
      carol,
      { ...X.state(), ...rekeyTo(X.nodeId, 3, 32), shares: X.state().shares.filter((x) => x.userId !== dan.id) },
      [F.dep(), R.dep()],
    );
    let ns = st(w(), X.nodeId);
    expect(ns.status).toMatchObject({ kind: "unverified", atSeq: 4 });
    expect(ns.stretchRemovals.userIds.has(dan.id)).toBe(true);
    // while unverified, the ceil carries the removal too: were the lift to lapse now, dan would stay out
    const F2 = F.clone();
    const w2 = () => world([R, F2, X]);
    write(alice, w2(), F2, { remove: bob.id, rekey: rekeyTo(F.nodeId, 2, 20) });
    write(alice, w2(), F2, { remove: carol.id, rekey: rekeyTo(F.nodeId, 3, 21) });
    expect(st(w2(), X.nodeId)).toMatchObject({ status: { kind: "unverified" }, state: { restricted: true } });
    expect(st(w2(), X.nodeId).state.shares).toEqual([share(bob, "owner")]);
    // carol, owner through F, checkpoints from the pre-fill: verified again, dan gone, eve never in
    expect(canCheckpoint(w(), ns, carol.id)).toBe(true);
    const pre = checkpointPrefill(ns);
    write(carol, w(), X, { checkpoint: { state: pre, rekey: rekeyTo(X.nodeId, pre.version + 1, 33) } });
    ns = st(w(), X.nodeId);
    expect(ns).toMatchObject({ status: verified, state: { restricted: false, version: 4 } });
    expect(ns.state.shares).toEqual([]);
    // then bob and carol lose F: the lift lapses, and the removal the checkpoint confirmed still applies
    removeBob(w, F, carol);
    ns = st(w(), X.nodeId);
    expect(ns).toMatchObject({ status: verified, state: { restricted: true } });
    expect(ns.state.shares).toEqual([share(bob, "owner")]);
    expect(roles(w(), X.nodeId)).toBe("-,owner,-,-,-");
  });

  it("residual (§4.2): on a team, a creator who leaves the team is void: no worse than never publishing", () => {
    const id = crypto.randomUUID();
    const admins = group([alice]);
    const all0 = { id: crypto.randomUUID(), versions: [[alice, bob, carol]] };
    const all1 = {
      id: all0.id,
      versions: [
        [alice, bob, carol],
        [alice, carol],
      ],
    };
    const gv0 = view([admins, all0], { [id]: { everyone: all0, admins } });
    const gv1 = view([admins, all1], { [id]: { everyone: all1, admins } });
    const T = Log.create(alice, { ...rootState(alice, 1), anchor: { team: id }, shares: [] }, [
      gdep(admins),
      gdep(all0),
    ]);
    const mk = () => {
      const logs = [T];
      const w0 = () => world(logs, { groups: gv0 });
      const ch = create(
        bob,
        w0(),
        T,
        childState("", 2, { kind: "channel", restricted: true, shares: [share(bob, "owner")] }),
      );
      logs.push(ch);
      write(bob, w0(), ch, { add: share(dan, "viewer") });
      return { logs, w0, ch };
    };
    const kept = mk();
    const lifted = mk();
    write(bob, lifted.w0(), lifted.ch, { unrestrict: T.nodeId });
    expect(st(lifted.w0(), lifted.ch.nodeId).state.restricted).toBe(false);
    // bob leaves the team: his share on a team item is void (§4.2), lift or no lift, and dan's rests on his
    const after = (x: typeof kept) => st(world(x.logs, { groups: gv1 }), x.ch.nodeId);
    expect(after(lifted).state.restricted).toBe(true);
    expect(after(lifted).state.shares).toEqual(after(kept).state.shares);
    expect(after(kept).state.shares).toEqual([]);
  });
});
