import { fromBase64Url, generateEncryptionKeyPair, openSealed, ready, sign, toBase64Url, utf8 } from "@jelly/crypto";
import { beforeAll, describe, expect, it } from "vitest";
import { createAccount, unlockAccount } from "../src/account.ts";
import { pushDevicePayload, sealPushNotice, signPushDevice, verifyPushDevice } from "../src/push-notice.ts";
import { SIG } from "../src/tags.ts";

beforeAll(ready);

/* What a phone's notification extension opens (apps/desktop/ios/notify/NotificationService.swift `Message`). */
describe("sealPushNotice", () => {
  it("seals {v:1, title, body, path} to the device's push key, base64url", () => {
    const pair = generateEncryptionKeyPair();
    const sealed = sealPushNotice(toBase64Url(pair.publicKey), { title: "Ana", body: "Lunch?", path: "/mail/?m=1" });
    expect(sealed).toMatch(/^[A-Za-z0-9_-]+$/);
    const plain = new TextDecoder().decode(openSealed(pair, fromBase64Url(sealed)));
    expect(JSON.parse(plain)).toEqual({ v: 1, title: "Ana", body: "Lunch?", path: "/mail/?m=1" });
  });
});

function user() {
  const userId = crypto.randomUUID();
  const acct = createAccount();
  return unlockAccount({ userId, handle: "ana", ak: acct.ak, bundle: acct.bundle });
}
const pushKey = () => toBase64Url(generateEncryptionKeyPair().publicKey);
const ownerOf = (a: ReturnType<typeof user>) => ({ userId: a.userId, signPub: a.signing.publicKey });

/* A push device counts only when the account's own identity key vouches for its key (security fix round 4, §1). */
describe("push device statements", () => {
  it("verifies a device the account signed", () => {
    const a = user();
    const publicKey = pushKey();
    const keySig = signPushDevice(a, publicKey);
    expect(keySig).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(verifyPushDevice(ownerOf(a), { publicKey, keySig })).toBe(true);
  });

  it("refuses an unsigned device, or garbage", () => {
    const a = user();
    expect(verifyPushDevice(ownerOf(a), { publicKey: pushKey() })).toBe(false);
    expect(verifyPushDevice(ownerOf(a), { publicKey: pushKey(), keySig: null })).toBe(false);
    expect(verifyPushDevice(ownerOf(a), { publicKey: pushKey(), keySig: "not*base64" })).toBe(false);
    expect(verifyPushDevice(ownerOf(a), { publicKey: pushKey(), keySig: "AAAA" })).toBe(false);
  });

  it("refuses a statement for another user", () => {
    const a = user();
    const publicKey = pushKey();
    const keySig = signPushDevice(a, publicKey);
    expect(verifyPushDevice({ ...ownerOf(a), userId: crypto.randomUUID() }, { publicKey, keySig })).toBe(false);
  });

  it("refuses a statement signed by another identity", () => {
    const a = user();
    const mallory = user();
    const publicKey = pushKey();
    // Made for a's user id, but signed with mallory's key.
    const keySig = signPushDevice({ userId: a.userId, signing: mallory.signing }, publicKey);
    expect(verifyPushDevice(ownerOf(a), { publicKey, keySig })).toBe(false);
  });

  it("refuses a signature moved to another push key", () => {
    const a = user();
    const keySig = signPushDevice(a, pushKey());
    expect(verifyPushDevice(ownerOf(a), { publicKey: pushKey(), keySig })).toBe(false);
  });

  it("is domain-separated: the same fields signed in another context or framing don't count", () => {
    const a = user();
    const publicKey = pushKey();
    const other = toBase64Url(sign(a.signing.privateKey, SIG.grantV2, pushDevicePayload(a.userId, publicKey)));
    expect(verifyPushDevice(ownerOf(a), { publicKey, keySig: other })).toBe(false);
    const bare = toBase64Url(sign(a.signing.privateKey, SIG.pushDevice, utf8(`${a.userId}|${publicKey}`)));
    expect(verifyPushDevice(ownerOf(a), { publicKey, keySig: bare })).toBe(false);
  });
});
