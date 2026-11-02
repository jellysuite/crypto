import { generateSigningKeyPair, type KeyPair, ready, toBase64Url } from "@jelly/crypto";
import { beforeAll, describe, expect, it } from "vitest";
import { createAccount, keyChangeRequest, openPgpKeys, unlockAccount, verifyIdentity } from "../src/account.ts";
import { createKeyChange, type KeyChange, keyChain, verifyKeyChange } from "../src/identity-chain.ts";
import { ISO_UTC } from "../src/index.ts";

beforeAll(ready);

const pub = (k: KeyPair) => toBase64Url(k.publicKey);
function user() {
  const acct = createAccount();
  return unlockAccount({ userId: crypto.randomUUID(), handle: "ana", ak: acct.ak, bundle: acct.bundle });
}
const at = "2026-10-31T10:00:00.000Z";
/** A chain k0 -> k1 -> k2 for one user. */
function chain() {
  const a = user();
  const k1 = generateSigningKeyPair();
  const k2 = generateSigningKeyPair();
  const c1 = createKeyChange(a, k1, at);
  const c2 = createKeyChange({ ...a, signing: k1 }, k2, at);
  return { a, k1, k2, c1, c2, k0: pub(a.signing) };
}

describe("keyChain for a named user", () => {
  it("refuses a chain whose changes name another user", () => {
    const { a, c1, c2, k2 } = chain();
    expect(keyChain(pub(k2), [c1, c2], a.userId)).toHaveLength(3);
    expect(keyChain(pub(k2), [c1, c2], "someone-else")).toBeNull();
    expect(keyChain(pub(k2), [], "someone-else")).toEqual([pub(k2)]);
  });
});

describe("key changes", () => {
  it("verifies a change signed by both keys", () => {
    const { c1, a, k1 } = chain();
    expect(c1).toMatchObject({ userId: a.userId, oldSignPub: pub(a.signing), newSignPub: pub(k1), at });
    expect(verifyKeyChange(c1)).toBe(true);
  });

  it("refuses a change with one side missing or altered", () => {
    const { c1, c2 } = chain();
    expect(verifyKeyChange({ ...c1, oldSig: c2.oldSig })).toBe(false);
    expect(verifyKeyChange({ ...c1, newSig: c2.newSig })).toBe(false);
    expect(verifyKeyChange({ ...c1, at: "2026-11-01T00:00:00.000Z" })).toBe(false);
    expect(verifyKeyChange({ ...c1, userId: "someone-else" })).toBe(false);
    expect(verifyKeyChange({ ...c1, oldSig: "!!" })).toBe(false);
  });

  it("refuses a change whose signatures are swapped between the keys", () => {
    const { c1 } = chain();
    expect(verifyKeyChange({ ...c1, oldSig: c1.newSig, newSig: c1.oldSig })).toBe(false);
  });
});

describe("keyChain", () => {
  it("is just the current key without changes", () => {
    const { k2 } = chain();
    expect(keyChain(pub(k2), [])).toEqual([pub(k2)]);
  });

  it("resolves a two-change chain oldest to current, whatever the input order", () => {
    const { c1, c2, k0, k1, k2 } = chain();
    expect(keyChain(pub(k2), [c1, c2])).toEqual([k0, pub(k1), pub(k2)]);
    expect(keyChain(pub(k2), [c2, c1])).toEqual([k0, pub(k1), pub(k2)]);
  });

  it("is null when a change is signed by only one side", () => {
    const { c1, c2, k2 } = chain();
    expect(keyChain(pub(k2), [c1, { ...c2, newSig: c1.newSig }])).toBeNull();
    expect(keyChain(pub(k2), [{ ...c1, oldSig: c2.oldSig }, c2])).toBeNull();
  });

  it("is null on a gap, with changes left over that do not connect", () => {
    const { c1, c2, k2 } = chain();
    expect(keyChain(pub(k2), [c1])).toBeNull();
    const other = chain();
    expect(keyChain(pub(k2), [c1, c2, other.c1])).toBeNull();
  });

  it("is null on a fork (two changes away from one key)", () => {
    const { a, k1, c1, c2, k2 } = chain();
    const kx = generateSigningKeyPair();
    const fork: KeyChange = createKeyChange(a, kx, at);
    expect(keyChain(pub(k2), [c1, c2, fork])).toBeNull();
    expect(keyChain(pub(k1), [c1, fork])).toBeNull();
  });

  it("is null when it does not end at the current key", () => {
    const { c1, c2, k1 } = chain();
    expect(keyChain(pub(k1), [c1, c2])).toBeNull();
    expect(keyChain(pub(generateSigningKeyPair()), [c1, c2])).toBeNull();
  });

  it("is null for changes of different users, and for a loop", () => {
    const { c1, k1 } = chain();
    const b = chain();
    expect(keyChain(pub(k1), [c1, { ...b.c1, newSignPub: pub(k1) }])).toBeNull();
    const a = user();
    const k1b = generateSigningKeyPair();
    const there = createKeyChange(a, k1b, at);
    const back = createKeyChange({ ...a, signing: k1b }, a.signing, at);
    expect(keyChain(pub(a.signing), [there, back])).toBeNull();
  });
});

describe("keyChangeRequest", () => {
  it("re-seals the account for the new key: it unlocks with the same account key, under the new signing key", () => {
    const a = user();
    a.privateData.pinnedKeys.bob = { signPub: "b0b", verified: true };
    const next = generateSigningKeyPair();
    const req = keyChangeRequest(a, next, { at, privateDataRevision: 4, pgpKeys: ["-----armored-----"] });
    expect(req.change).toMatchObject({ userId: a.userId, oldSignPub: pub(a.signing), newSignPub: pub(next), at });
    expect(verifyKeyChange(req.change)).toBe(true);
    expect(req.privateDataRevision).toBe(4);
    expect(req.bundle.signPub).toBe(pub(next));
    expect(req.bundle.encPub).toBe(toBase64Url(a.encryption.publicKey));
    expect(verifyIdentity(req.bundle)).toBe(true);
    const b = unlockAccount({ userId: a.userId, handle: a.handle, ak: a.ak, bundle: req.bundle });
    expect(b.privateDataLost).toBe(false);
    expect(toBase64Url(b.signing.privateKey)).toBe(toBase64Url(next.privateKey));
    expect(toBase64Url(b.encryption.privateKey)).toBe(toBase64Url(a.encryption.privateKey));
    expect(b.privateData.pinnedKeys).toEqual({ bob: { signPub: "b0b", verified: true } });
    expect(b.privateData.revision).toBe(4);
    expect(openPgpKeys(a.ak, pub(next), req.pgpSealedKeys!)).toEqual(["-----armored-----"]);
    expect(() => openPgpKeys(a.ak, pub(a.signing), req.pgpSealedKeys!)).toThrow();
  });

  it("leaves out the PGP keys when the account has none", () => {
    const a = user();
    expect(keyChangeRequest(a, generateSigningKeyPair(), { at, privateDataRevision: 1 })).not.toHaveProperty(
      "pgpSealedKeys",
    );
  });
});

describe("ISO_UTC", () => {
  it("is exported and takes only the toISOString form", () => {
    expect(ISO_UTC.test(new Date().toISOString())).toBe(true);
    expect(ISO_UTC.test("2026-10-31")).toBe(false);
    expect(ISO_UTC.test("2026-10-31T10:00:00+00:00")).toBe(false);
  });
});
