import { fromBase64Url, generateEncryptionKeyPair, openSealed, ready, sign, toBase64Url, utf8 } from "@jelly/crypto";
import { beforeAll, describe, expect, it } from "vitest";
import { createAccount, unlockAccount } from "../src/account.ts";
import {
  pushDevicePayload,
  sealNoticesFor,
  sealPushFrom,
  sealPushNotice,
  signPushDevice,
  verifyPushDevice,
} from "../src/push-notice.ts";
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

  it("carries a thread when given (the phone groups by it; Apple never sees it)", () => {
    const pair = generateEncryptionKeyPair();
    const n = { title: "@ana in #design", body: "hi", path: "/chat/?c=1", thread: "chat-1" };
    const sealed = sealPushNotice(toBase64Url(pair.publicKey), n);
    expect(JSON.parse(new TextDecoder().decode(openSealed(pair, fromBase64Url(sealed))))).toEqual({ v: 1, ...n });
  });
});

describe("sealPushFrom", () => {
  it("seals {v:1, from} (the author's handle, as the server knows it)", () => {
    const pair = generateEncryptionKeyPair();
    const sealed = sealPushFrom(toBase64Url(pair.publicKey), "@ana");
    expect(JSON.parse(new TextDecoder().decode(openSealed(pair, fromBase64Url(sealed))))).toEqual({
      v: 1,
      from: "@ana",
    });
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

/* A sender seals someone else's notice only to devices that person's own key vouched for (chat mention pushes §3). */
describe("sealNoticesFor", () => {
  const notice = { title: "@me in #design", body: "look", path: "/chat/?c=1&m=2", thread: "chat-1" };

  function phoneOf(a: ReturnType<typeof user>, signed = true) {
    const pair = generateEncryptionKeyPair();
    const publicKey = toBase64Url(pair.publicKey);
    return {
      pair,
      device: { id: crypto.randomUUID(), publicKey, keySig: signed ? signPushDevice(a, publicKey) : null },
    };
  }

  it("seals to each vouched device of each user, keyed by device id", () => {
    const bob = user();
    const carol = user();
    const b1 = phoneOf(bob);
    const b2 = phoneOf(bob);
    const c1 = phoneOf(carol);
    const keys = new Map([
      [bob.userId, bob.signing.publicKey],
      [carol.userId, carol.signing.publicKey],
    ]);
    const out = sealNoticesFor(
      [
        { userId: bob.userId, devices: [b1.device, b2.device] },
        { userId: carol.userId, devices: [c1.device] },
      ],
      (id) => keys.get(id),
      notice,
    );
    expect(out.skipped).toEqual([]);
    expect(out.pushes.map((p) => p.userId)).toEqual([bob.userId, carol.userId]);
    const bobs = out.pushes[0]!.sealed;
    expect(Object.keys(bobs).sort()).toEqual([b1.device.id, b2.device.id].sort());
    const opened = JSON.parse(new TextDecoder().decode(openSealed(b2.pair, fromBase64Url(bobs[b2.device.id]!))));
    expect(opened).toEqual({ v: 1, ...notice });
  });

  it("skips devices not signed by the user's trusted key, and users it can't vouch for", () => {
    const bob = user();
    const mallory = user();
    const good = phoneOf(bob);
    const unsigned = phoneOf(bob, false);
    // A key the server slipped in, signed by someone else's identity for bob's user id.
    const forged = phoneOf(bob);
    forged.device.keySig = signPushDevice({ userId: bob.userId, signing: mallory.signing }, forged.device.publicKey);
    const stranger = user();
    const out = sealNoticesFor(
      [
        { userId: bob.userId, devices: [good.device, unsigned.device, forged.device] },
        { userId: stranger.userId, devices: [phoneOf(stranger).device] },
      ],
      (id) => (id === bob.userId ? bob.signing.publicKey : undefined),
      notice,
    );
    expect(out.pushes).toHaveLength(1);
    expect(Object.keys(out.pushes[0]!.sealed)).toEqual([good.device.id]);
    expect(out.skipped.sort()).toEqual([unsigned.device.id, forged.device.id, `user:${stranger.userId}`].sort());
  });

  it("leaves out a user with no vouched device", () => {
    const bob = user();
    const out = sealNoticesFor(
      [{ userId: bob.userId, devices: [phoneOf(bob, false).device] }],
      () => bob.signing.publicKey,
      notice,
    );
    expect(out.pushes).toEqual([]);
  });
});
