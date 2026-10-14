import { describe, expect, it } from "vitest";
import {
  decodeLinkFragment,
  encodeLinkFragment,
  linkAuth,
  linkAuthHash,
  newLinkSecret,
  newNodeKey,
  unwrapLinkSecret,
  unwrapNodeKeyForLink,
  wrapLinkSecret,
  wrapNodeKeyForLink,
} from "../src/index.ts";

describe("link shares", () => {
  const secret = newLinkSecret();
  const nodeKey = newNodeKey();

  it("round-trips the fragment", () => {
    expect(decodeLinkFragment(encodeLinkFragment(secret))).toEqual(secret);
  });

  it("returns null for missing or corrupted fragments", () => {
    expect(decodeLinkFragment("")).toBeNull();
    expect(decodeLinkFragment("zz!")).toBeNull();
    expect(decodeLinkFragment(encodeLinkFragment(secret).slice(0, 20))).toBeNull();
  });

  it("wraps the node key for the link and binds it to link and node", () => {
    const wrapped = wrapNodeKeyForLink(secret, "l1", "n1", 1, nodeKey);
    expect(unwrapNodeKeyForLink(secret, "l1", "n1", 1, wrapped)).toEqual(nodeKey);
    expect(() => unwrapNodeKeyForLink(secret, "l2", "n1", 1, wrapped)).toThrow();
    expect(() => unwrapNodeKeyForLink(newLinkSecret(), "l1", "n1", 1, wrapped)).toThrow();
  });

  it("lets key holders re-display the link secret", () => {
    expect(unwrapLinkSecret(nodeKey, "l1", wrapLinkSecret(nodeKey, "l1", secret))).toEqual(secret);
  });

  it("derives a stable auth value distinct from the secret", () => {
    expect(linkAuth(secret)).toBe(linkAuth(secret));
    expect(linkAuthHash(linkAuth(secret))).not.toBe(linkAuth(secret));
  });
});
