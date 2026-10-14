import { describe, expect, it } from "vitest";
import { checkPin, normalizeHandle, pin, validateAddressHandle, validateHandle } from "../src/index.ts";

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
