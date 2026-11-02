import { hashWith, ready, toBase64Url } from "@jelly/crypto";
import { beforeAll, describe, expect, it } from "vitest";
import { lengthPrefixed } from "../../src/grants.ts";
import { groupHead } from "../../src/log/index.ts";

beforeAll(ready);

const v = { teamId: "t1", groupId: "g1", version: 3, encPub: "AAAA" };

describe("groupHead", () => {
  it("hashes the version's stable fields under jelly-group-head@2", () => {
    const expected = toBase64Url(hashWith("jelly-group-head@2", lengthPrefixed(["t1", "g1", "3", "AAAA"])));
    expect(groupHead(v)).toBe(expected);
    expect(groupHead(v)).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("is stable, differs per field, and ignores the team key's signature (it survives a re-sign)", () => {
    expect(groupHead({ ...v })).toBe(groupHead(v));
    for (const over of [{ teamId: "t2" }, { groupId: "g2" }, { version: 4 }, { encPub: "AAAB" }])
      expect(groupHead({ ...v, ...over })).not.toBe(groupHead(v));
    const signed = { ...v, teamKeyVersion: 1, signature: "x" };
    const resigned = { ...v, teamKeyVersion: 2, signature: "y" };
    expect(groupHead(signed)).toBe(groupHead(resigned));
  });
});
