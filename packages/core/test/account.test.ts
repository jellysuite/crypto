import { generateKey, randomBytes, toBase64Url } from "@jelly/crypto";
import { describe, expect, it } from "vitest";
import {
  createAccount,
  encryptPrivateData,
  openPgpKeys,
  passwordWrap,
  sealPgpKeys,
  unlockAccount,
  unwrapPasswordWrap,
  verifyIdentity,
} from "../src/index.ts";

// OPAQUE export keys are 64 bytes, base64url encoded (86 chars).
const exportKey = () => toBase64Url(randomBytes(64));

describe("accounts", () => {
  it("unlocks with the AK recovered from the password wrap", () => {
    const acct = createAccount();
    const ek = exportKey();
    const ak = unwrapPasswordWrap(passwordWrap(acct.ak, ek), ek);
    const unlocked = unlockAccount({ userId: "u1", handle: "alice", ak, bundle: acct.bundle });
    expect(toBase64Url(unlocked.signing.publicKey)).toBe(acct.bundle.signPub);
    expect(toBase64Url(unlocked.encryption.publicKey)).toBe(acct.bundle.encPub);
    expect(unlocked.privateData).toEqual({ pinnedKeys: {}, settings: {}, revision: 0 });
  });

  it("rejects the wrap under a different export key", () => {
    const acct = createAccount();
    expect(() => unwrapPasswordWrap(passwordWrap(acct.ak, exportKey()), exportKey())).toThrow();
  });

  it("refuses to unlock a bundle whose encryption key signature is forged", () => {
    const acct = createAccount();
    const other = createAccount();
    const bundle = { ...acct.bundle, encPubSig: other.bundle.encPubSig };
    expect(() => unlockAccount({ userId: "u1", handle: "alice", ak: acct.ak, bundle })).toThrow();
  });

  it("refuses to unlock with the wrong AK", () => {
    const acct = createAccount();
    expect(() => unlockAccount({ userId: "u1", handle: "alice", ak: generateKey(), bundle: acct.bundle })).toThrow();
  });

  it("still unlocks when private data was replaced with garbage, and flags it", () => {
    const acct = createAccount();
    const other = createAccount();
    const bundle = { ...acct.bundle, privateData: other.bundle.privateData };
    const unlocked = unlockAccount({ userId: "u1", handle: "alice", ak: acct.ak, bundle });
    expect(unlocked.privateData).toEqual({ pinnedKeys: {}, settings: {} });
    expect(unlocked.privateDataLost).toBe(true);
    expect(unlockAccount({ userId: "u1", handle: "alice", ak: acct.ak, bundle: acct.bundle }).privateDataLost).toBe(
      false,
    );
  });

  it("persists updated private data", () => {
    const acct = createAccount();
    const data = { pinnedKeys: { u2: { signPub: "abc", verified: true } }, settings: {} };
    const bundle = { ...acct.bundle, privateData: encryptPrivateData(acct.ak, acct.bundle.signPub, data) };
    expect(unlockAccount({ userId: "u1", handle: "alice", ak: acct.ak, bundle }).privateData).toEqual(data);
  });

  it("verifies public identities", () => {
    const acct = createAccount();
    const id = { userId: "u1", handle: "alice", ...acct.bundle };
    expect(verifyIdentity(id)).toBe(true);
    expect(verifyIdentity({ ...id, encPub: createAccount().bundle.encPub })).toBe(false);
  });
});

describe("PGP keys", () => {
  it("seals PGP keys to the account and refuses another account", () => {
    const a = createAccount();
    const b = createAccount();
    const sealed = sealPgpKeys(a.ak, a.bundle.signPub, ["-----BEGIN PGP PRIVATE KEY BLOCK-----x"]);
    expect(openPgpKeys(a.ak, a.bundle.signPub, sealed)).toEqual(["-----BEGIN PGP PRIVATE KEY BLOCK-----x"]);
    expect(() => openPgpKeys(a.ak, b.bundle.signPub, sealed)).toThrow();
    expect(() => openPgpKeys(b.ak, a.bundle.signPub, sealed)).toThrow();
  });
});
