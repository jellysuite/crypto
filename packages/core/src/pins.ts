import type { PrivateData } from "./account.ts";
import type { B64 } from "./wire.ts";

export type PinStatus = "new" | "match" | "mismatch";

export function checkPin(data: PrivateData, userId: string, signPub: B64): PinStatus {
  const pinned = data.pinnedKeys[userId];
  if (!pinned) return "new";
  return pinned.signPub === signPub ? "match" : "mismatch";
}

export function pin(data: PrivateData, userId: string, signPub: B64, verified?: boolean): PrivateData {
  const existing = data.pinnedKeys[userId];
  const keepVerified = existing?.signPub === signPub && existing.verified;
  return {
    ...data,
    pinnedKeys: { ...data.pinnedKeys, [userId]: { signPub, verified: verified ?? keepVerified } },
  };
}
