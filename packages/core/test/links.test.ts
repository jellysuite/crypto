import { toBase64Url } from "@jelly/crypto";
import { describe, expect, it } from "vitest";
import {
  createAccount,
  decodeLinkFragment,
  encodeLinkFragment,
  linkAuth,
  linkAuthHash,
  newLinkSecret,
  newNodeKey,
  signLink,
  unlockAccount,
  unwrapLinkSecret,
  unwrapNodeKeyForLink,
  verifyLink,
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

describe("signed link rows", () => {
  const signer = () => {
    const a = createAccount();
    return unlockAccount({ userId: crypto.randomUUID(), handle: "alice", ak: a.ak, bundle: a.bundle });
  };
  const alice = signer();
  const alicePub = toBase64Url(alice.signing.publicKey);
  const row = {
    id: crypto.randomUUID(),
    nodeId: crypto.randomUUID(),
    role: "viewer" as const,
    authHash: linkAuthHash(linkAuth(newLinkSecret())),
  };
  const signed = { ...row, signature: signLink(alice, row) };

  it("verifies under its creator's key", () => {
    expect(verifyLink(signed, alicePub)).toBe(true);
  });

  it("fails for another role, node, link id or secret, or another signer", () => {
    expect(verifyLink({ ...signed, role: "editor" }, alicePub)).toBe(false);
    expect(verifyLink({ ...signed, nodeId: crypto.randomUUID() }, alicePub)).toBe(false);
    expect(verifyLink({ ...signed, id: crypto.randomUUID() }, alicePub)).toBe(false);
    expect(verifyLink({ ...signed, authHash: linkAuthHash(linkAuth(newLinkSecret())) }, alicePub)).toBe(false);
    expect(verifyLink(signed, toBase64Url(signer().signing.publicKey))).toBe(false);
    expect(verifyLink({ ...signed, signature: "not-a-signature" }, alicePub)).toBe(false);
  });
});
