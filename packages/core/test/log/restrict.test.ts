/**
 * A restriction as one signed change (§3.3): the restricted state names exactly the people, groups and links it
 * keeps, adds and role changes included, so nobody new is ever on the open item first.
 */
import { describe, expect, it } from "vitest";
import { legacySnapshot, linkMakers } from "../../src/index.ts";
import {
  alice,
  bob,
  carol,
  childState,
  create,
  dan,
  gdep,
  group,
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

const alices = crypto.randomUUID();
const bobs = crypto.randomUUID();

function setup() {
  const G = group([carol]);
  const H = group([dan]);
  const groups = view([G, H]);
  const R = Log.create(alice, rootState(alice, 1));
  const logs = [R];
  const w = () => world(logs, { groups });
  const F = create(alice, w(), R, childState("", 2, { kind: "folder" }));
  logs.push(F);
  write(alice, w(), F, { add: share(bob, "editor") });
  const X = create(alice, w(), F, childState("", 3));
  logs.push(X);
  write(alice, w(), X, { add: share(carol, "viewer") });
  write(alice, w(), X, { addGroup: { groupId: G.id, role: "editor" } });
  write(alice, w(), X, { addLink: { linkId: alices, role: "viewer" } });
  write(bob, w(), X, { addLink: { linkId: bobs, role: "viewer" } });
  return { G, H, R, F, X, w };
}

describe("restrict: one snapshot sets who keeps it", () => {
  it("adds, changes roles, drops unnamed groups and links, and makes the author owner", () => {
    const { G, H, X, w } = setup();
    write(alice, w(), X, {
      restrict: {
        shares: [share(carol, "editor"), share(dan, "viewer")],
        groups: [{ groupId: H.id, role: "viewer" }],
        links: [alices, crypto.randomUUID()],
        rekey: rekeyTo(X.nodeId, 2, 30),
      },
    });
    const ns = st(w(), X.nodeId);
    expect(ns.status).toEqual(verified);
    expect(ns.state.restricted).toBe(true);
    expect(ns.state.shares.map((s) => [s.userId, s.role])).toEqual([
      [carol.id, "editor"],
      [dan.id, "viewer"],
      [alice.id, "owner"],
    ]);
    expect(ns.state.groupShares).toEqual([{ groupId: H.id, role: "viewer" }]);
    expect(ns.state.links).toEqual([{ linkId: alices, role: "viewer" }]);
    expect(w().role(dan.id, X.nodeId)).toBe("viewer");
    expect(w().role(bob.id, X.nodeId)).toBeNull();
    // A group it newly shares with is named in the deps (§5.2).
    expect(X.last().deps).toContainEqual(gdep(H));
    expect(G.id).not.toBe(H.id);
  });

  it("a person named twice is refused", () => {
    const { X, w } = setup();
    expect(
      refused(alice, w(), X, {
        restrict: {
          shares: [share(carol, "editor"), share(carol, "viewer")],
          groups: [],
          links: [],
          rekey: rekeyTo(X.nodeId, 2, 31),
        },
      }),
    ).toMatch(/once/);
  });

  it("an editor's restriction is something the fold would skip, so it isn't signed", () => {
    const { X, w } = setup();
    expect(
      refused(bob, w(), X, {
        restrict: { shares: [share(dan, "editor")], groups: [], links: [], rekey: rekeyTo(X.nodeId, 2, 32) },
      }),
    ).toMatch(/skip/);
  });

  it("linkMakers names who first carried each link in the log", () => {
    const { X } = setup();
    const makers = linkMakers(X.entries);
    expect(makers.get(alices)).toBe(alice.id);
    expect(makers.get(bobs)).toBe(bob.id);
    expect(makers.get("nothing")).toBeUndefined();
  });

  it("a link only a legacy seq 0 carries has no signed maker, so no owner who stays keeps it", () => {
    const legacy = legacySnapshot(
      {
        nodeId: crypto.randomUUID(),
        state: { ...childState(crypto.randomUUID(), 9), links: [{ linkId: alices, role: "viewer" }] },
      },
      [],
    );
    const makers = linkMakers([legacy]);
    expect(makers.get(alices)).toBe("");
    // What a restrictor keeps: links whose maker is an owner in the restricted state; "" never is one.
    const owners = new Set<string>([alice.id]);
    expect(legacy.state.links.filter((l) => owners.has(makers.get(l.linkId) ?? ""))).toEqual([]);
  });
});
