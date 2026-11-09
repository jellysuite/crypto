import { type Bytes, fromBase64Url, sealTo, sign, toBase64Url, utf8, verify } from "@jelly/crypto";
import type { UnlockedAccount } from "./account.ts";
import { lengthPrefixed } from "./grants.ts";
import { SIG } from "./tags.ts";
import type { B64 } from "./wire.ts";

/**
 * The text of a pushed notification: what the device shows, and what a tap opens. `thread`: how the phone groups
 * it (a chat channel's pushes), set there from inside the box so Apple doesn't learn which pushes belong together.
 */
export type PushNoticeText = { title: string; body: string; path: string; thread?: string };

/**
 * The text a device's notification extension opens: `crypto_box_seal` of `{"v":1,title,body,path}` to its push key,
 * base64url. Apple and our database only ever hold this. Sealed in the apps for reminders, and by the server for
 * new mail, at the moment it holds the mail in the clear anyway (docs/superpowers/specs/2026-10-21-push-design.md §9).
 */
export function sealPushNotice(publicKey: string, n: PushNoticeText): string {
  const text = JSON.stringify({
    v: 1,
    title: n.title,
    body: n.body,
    path: n.path,
    ...(n.thread !== undefined ? { thread: n.thread } : {}),
  });
  return toBase64Url(sealTo(fromBase64Url(publicKey), utf8(text)));
}

/**
 * Who a notice someone else's app sealed is really from: `{"v":1,"from":"@handle"}` sealed by the server (which knows
 * the author) to the device, sent beside it as `f`. The extension keeps the sealed title only when it starts with
 * that handle, so one team member can't push as another (chat mention push design §3).
 */
export function sealPushFrom(publicKey: string, handle: string): string {
  return toBase64Url(sealTo(fromBase64Url(publicKey), utf8(JSON.stringify({ v: 1, from: handle }))));
}

/** What the statement vouches the key is for: opening this account's pushed notices, nothing else. */
export const PUSH_DEVICE_PURPOSE = "push-notices";

/**
 * push-device@1: the account says "this push key is one of my devices, for my notices". Length-prefixed purpose,
 * user id and the push key as registered (base64url), signed under the `push-device@1` context.
 */
export const pushDevicePayload = (userId: string, publicKey: B64): Bytes =>
  lengthPrefixed([PUSH_DEVICE_PURPOSE, userId, publicKey]);

/** The `keySig` a device registers with: the account's identity key vouching for the device's push key. */
export function signPushDevice(account: Pick<UnlockedAccount, "userId" | "signing">, publicKey: B64): B64 {
  return toBase64Url(sign(account.signing.privateKey, SIG.pushDevice, pushDevicePayload(account.userId, publicKey)));
}

/**
 * Whether a listed device is one the account itself vouched for. `owner.signPub` must be the account's own signing
 * key as this client holds it (from its unlocked keys), never one the server hands out with the device list.
 */
export function verifyPushDevice(
  owner: { userId: string; signPub: Bytes },
  device: { publicKey: string; keySig?: string | null },
): boolean {
  if (typeof device.keySig !== "string" || typeof device.publicKey !== "string") return false;
  try {
    return verify(
      owner.signPub,
      SIG.pushDevice,
      pushDevicePayload(owner.userId, device.publicKey),
      fromBase64Url(device.keySig),
    );
  } catch {
    return false;
  }
}

/** Someone's push devices as a server lists them for a sender, unverified. */
export type ListedPushDevices = {
  userId: string;
  devices: ReadonlyArray<{ id: string; publicKey: string; keySig?: string | null }>;
};

/**
 * Seals one notice for other people's devices: per user, to each device whose `keySig` verifies against that user's
 * signing key as this client trusts it (`trustedKey`: a pinned key, or one a team key vouches for; never one the
 * server sends with the list). A user without a trusted key, or without a vouched device, gets nothing. `skipped`
 * names the devices (and, as `user:<id>`, the users) left out, for a log line.
 */
export function sealNoticesFor(
  users: readonly ListedPushDevices[],
  trustedKey: (userId: string) => Bytes | undefined,
  notice: PushNoticeText,
): { pushes: Array<{ userId: string; sealed: Record<string, string> }>; skipped: string[] } {
  const pushes: Array<{ userId: string; sealed: Record<string, string> }> = [];
  const skipped: string[] = [];
  for (const u of users) {
    const signPub = trustedKey(u.userId);
    if (!signPub) {
      skipped.push(`user:${u.userId}`);
      continue;
    }
    const sealed: Record<string, string> = {};
    for (const d of u.devices) {
      if (!verifyPushDevice({ userId: u.userId, signPub }, d)) {
        skipped.push(d.id);
        continue;
      }
      try {
        sealed[d.id] = sealPushNotice(d.publicKey, notice);
      } catch {
        skipped.push(d.id);
      }
    }
    if (Object.keys(sealed).length > 0) pushes.push({ userId: u.userId, sealed });
  }
  return { pushes, skipped };
}
