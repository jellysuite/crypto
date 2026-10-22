import { fromBase64Url, sealTo, toBase64Url, utf8 } from "@jelly/crypto";

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
