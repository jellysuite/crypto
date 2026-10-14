import { generateKey } from "@jelly/crypto";
import { describe, expect, it } from "vitest";
import {
  createAccount,
  formatRecoveryKey,
  newRecoveryMaterial,
  parseRecoveryKey,
  recoveryAuth,
  recoveryAuthHash,
  unwrapRecoveryWrap,
} from "../src/index.ts";

describe("recovery keys", () => {
  it("formats as JELLY- plus dash-separated groups and parses back", () => {
    const raw = generateKey();
    const s = formatRecoveryKey(raw);
    expect(s).toMatch(/^JELLY(-[A-Z2-7]{4})+(-[A-Z2-7]{1,4})?$/);
    expect(parseRecoveryKey(s)).toEqual(raw);
  });

  it("parses lowercase input with spaces and without prefix", () => {
    const raw = generateKey();
    const loose = formatRecoveryKey(raw).replace("JELLY-", "").toLowerCase().replaceAll("-", " ");
    expect(parseRecoveryKey(`  ${loose} `)).toEqual(raw);
  });

  it("rejects keys of the wrong length or alphabet", () => {
    expect(parseRecoveryKey("JELLY-ABCD")).toBeNull();
    expect(parseRecoveryKey(formatRecoveryKey(generateKey()).replace(/.$/, "1"))).toBeNull();
    expect(parseRecoveryKey("")).toBeNull();
  });

  it("unwraps the AK with the recovery key and matches the stored auth hash", () => {
    const acct = createAccount();
    expect(unwrapRecoveryWrap(acct.recoveryWrap, acct.recoveryKey)).toEqual(acct.ak);
    expect(recoveryAuthHash(recoveryAuth(acct.recoveryKey))).toBe(acct.recoveryAuthHash);
  });

  it("issues fresh material that can't open with the old key", () => {
    const acct = createAccount();
    const fresh = newRecoveryMaterial(acct.ak);
    expect(unwrapRecoveryWrap(fresh.recoveryWrap, fresh.recoveryKey)).toEqual(acct.ak);
    expect(() => unwrapRecoveryWrap(fresh.recoveryWrap, acct.recoveryKey)).toThrow();
  });

  it("throws on an unparseable recovery key", () => {
    expect(() => recoveryAuth("nope")).toThrow();
  });
});
