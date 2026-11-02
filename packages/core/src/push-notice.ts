import { type Bytes, fromBase64Url, sealTo, sign, toBase64Url, utf8, verify } from "@jelly/crypto";
import type { UnlockedAccount } from "./account.ts";
import { lengthPrefixed } from "./grants.ts";
import { SIG } from "./tags.ts";
import type { B64 } from "./wire.ts";

/** The text of a pushed notification: what the device shows, and what a tap opens. */
export type PushNoticeText = { title: string; body: string; path: string };

/**
 * The text a device's notification extension opens: `crypto_box_seal` of `{"v":1,title,body,path}` to its push key,
 * base64url. Apple and our database only ever hold this. Sealed in the apps for reminders, and by the server for
 * new mail, at the moment it holds the mail in the clear anyway (docs/superpowers/specs/2026-10-21-push-design.md §9).
 */
export function sealPushNotice(publicKey: string, n: PushNoticeText): string {
  const text = JSON.stringify({ v: 1, title: n.title, body: n.body, path: n.path });
  return toBase64Url(sealTo(fromBase64Url(publicKey), utf8(text)));
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
