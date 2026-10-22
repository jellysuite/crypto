import { fromBase64Url, generateEncryptionKeyPair, openSealed, ready, toBase64Url } from "@jelly/crypto";
import { beforeAll, describe, expect, it } from "vitest";
import { sealPushNotice } from "../src/push-notice.ts";

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
