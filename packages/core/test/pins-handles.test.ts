import { describe, expect, it } from "vitest";
import {
  backfillHandle,
  checkIdentity,
  checkPin,
  normalizeHandle,
  pin,
  pinnedUserOfHandle,
  shownHandle,
  validateAddressHandle,
  validateHandle,
} from "../src/index.ts";

describe("pins bind the handle (one account per handle, one handle per account)", () => {
  const empty = { pinnedKeys: {}, settings: {} };
  const alice = { userId: "uA", handle: "alice", signPub: "kA" };

  it("records the handle when pinning and keeps it when the key moves", () => {
    const d = pin(empty, "uA", "kA", false, "alice");
    expect(d.pinnedKeys.uA).toEqual({ signPub: "kA", verified: false, handle: "alice" });
    expect(pin(d, "uA", "kA2", true).pinnedKeys.uA).toEqual({
      signPub: "kA2",
      verified: true,
      earlier: ["kA"],
      handle: "alice",
    });
    // A pin's handle never moves: a later, different one is ignored here (checkIdentity refuses it).
    expect(pin(d, "uA", "kA", false, "mallory").pinnedKeys.uA?.handle).toBe("alice");
  });

  it("checkIdentity: new, match, and mismatch on key, handle or a handle pinned to someone else", () => {
    expect(checkIdentity(empty, alice)).toBe("new");
    const d = pin(empty, "uA", "kA", false, "alice");
    expect(checkIdentity(d, alice)).toBe("match");
    expect(checkIdentity(d, { ...alice, handle: "ALICE" })).toBe("match");
    expect(checkIdentity(d, { ...alice, signPub: "kX" })).toBe("mismatch");
    // The pinned account under another handle.
    expect(checkIdentity(d, { ...alice, handle: "bob" })).toBe("mismatch");
    // Another account (even one never seen) under the pinned handle.
    expect(checkIdentity(d, { userId: "uX", handle: "alice", signPub: "kX" })).toBe("mismatch");
    expect(pinnedUserOfHandle(d, "Alice")).toBe("uA");
    expect(pinnedUserOfHandle(d, "bob")).toBeUndefined();
    // What is shown: the pinned handle; another account never under a pinned one.
    expect(shownHandle(d, "uA", "mallory")).toBe("alice");
    expect(shownHandle(d, "uX", "alice")).toBeUndefined();
    expect(shownHandle(d, "uX", "xavier")).toBe("xavier");
    expect(shownHandle(d, "uX", undefined)).toBeUndefined();
  });

  it("a pin without a handle (older data) matches on the key and takes the handle on first sight", () => {
    const old = pin(empty, "uA", "kA", true);
    expect(checkIdentity(old, alice)).toBe("match");
    const filled = backfillHandle(old, alice);
    expect(filled.pinnedKeys.uA).toEqual({ signPub: "kA", verified: true, handle: "alice" });
    // Nothing to fill: the same object back.
    expect(backfillHandle(filled, alice)).toBe(filled);
    expect(backfillHandle(old, { ...alice, signPub: "kX" })).toBe(old);
    // A handle another pin already carries is never filled in.
    const both = pin(old, "uB", "kB", false, "alice");
    expect(backfillHandle(both, alice)).toBe(both);
    expect(checkIdentity(both, alice)).toBe("mismatch");
  });
});

describe("pins", () => {
  const empty = { pinnedKeys: {}, settings: {} };

  it("reports new, match and mismatch", () => {
    expect(checkPin(empty, "u2", "k1")).toBe("new");
    const pinned = pin(empty, "u2", "k1");
    expect(checkPin(pinned, "u2", "k1")).toBe("match");
    expect(checkPin(pinned, "u2", "k2")).toBe("mismatch");
  });

  it("does not mutate the input and keeps verified status when re-pinning the same key", () => {
    const verified = pin(empty, "u2", "k1", true);
    expect(empty.pinnedKeys).toEqual({});
    expect(pin(verified, "u2", "k1").pinnedKeys.u2?.verified).toBe(true);
  });

  it("keeps every earlier key when the pin moves to a new one (spec §6.1)", () => {
    const k1 = pin(empty, "u2", "k1", true);
    expect(k1.pinnedKeys.u2).toEqual({ signPub: "k1", verified: true });
    const k2 = pin(k1, "u2", "k2", true);
    expect(k2.pinnedKeys.u2).toEqual({ signPub: "k2", verified: true, earlier: ["k1"] });
    const k3 = pin(k2, "u2", "k3");
    expect(k3.pinnedKeys.u2).toEqual({ signPub: "k3", verified: false, earlier: ["k1", "k2"] });
    // Re-pinning the current key adds nothing; moving back to an earlier key keeps the rest without repeating it.
    expect(pin(k3, "u2", "k3").pinnedKeys.u2?.earlier).toEqual(["k1", "k2"]);
    expect(pin(k3, "u2", "k1").pinnedKeys.u2).toEqual({ signPub: "k1", verified: false, earlier: ["k2", "k3"] });
    // Only the current key decides match or mismatch; the resolver reads the history (api-client).
    expect(checkPin(k3, "u2", "k1")).toBe("mismatch");
  });
});

describe("handles", () => {
  it("accepts valid handles", () => {
    for (const h of ["alice", "a.b-c_9", "bob123"]) expect(validateHandle(h)).toEqual({ ok: true });
  });

  it("rejects badly formatted handles", () => {
    for (const h of ["1abc", "ab", "Alice!", "a".repeat(31), "al ice"]) {
      expect(validateHandle(h)).toEqual({ ok: false, reason: "format" });
    }
  });

  it("rejects reserved handles", () => {
    expect(validateHandle("admin")).toEqual({ ok: false, reason: "reserved" });
    expect(validateHandle("postmaster")).toEqual({ ok: false, reason: "reserved" });
    // Company addresses and names that could pass for us in a phishing mail.
    for (const h of ["hello", "hey", "welcome", "news", "contact", "press", "careers", "verify", "official"]) {
      expect(validateHandle(h)).toEqual({ ok: false, reason: "reserved" });
    }
  });

  it("normalizes case and whitespace", () => {
    expect(normalizeHandle("  Alice ")).toBe("alice");
    expect(normalizeHandle(" Bob@Acme.Test ")).toBe("bob@acme.test");
  });

  it("refuses address handles in the plain form", () => {
    expect(validateHandle("bob@acme.test")).toEqual({ ok: false, reason: "format" });
  });

  it("validates address handles: local@hostname", () => {
    for (const h of ["bob@acme.test", "0x.y_z-1@mail.acme.co", `${"a".repeat(64)}@a.io`]) {
      expect(validateAddressHandle(h)).toBe(true);
    }
    for (const h of [
      "bob",
      "@acme.test",
      "bob@",
      "Bob@acme.test",
      ".bob@acme.test",
      `${"a".repeat(65)}@acme.test`,
      "bob@acme",
      "bob@-acme.test",
      "bob@acme..test",
      "bob@@acme.test",
      "b ob@acme.test",
      "bob@acme.test.",
    ]) {
      expect(validateAddressHandle(h)).toBe(false);
    }
  });
});
