import type { PinnedKey, PrivateData } from "./account.ts";
import type { B64 } from "./wire.ts";

export type PinStatus = "new" | "match" | "mismatch";

export function checkPin(data: PrivateData, userId: string, signPub: B64): PinStatus {
  const pinned = data.pinnedKeys[userId];
  if (!pinned) return "new";
  return pinned.signPub === signPub ? "match" : "mismatch";
}

/**
 * Pins `signPub` for the user. A key that replaces another keeps the old one in `earlier` (the pin's history), so
 * `pinnedKeysOf` still lists it; the current key alone decides `checkPin`.
 */
export function pin(data: PrivateData, userId: string, signPub: B64, verified?: boolean): PrivateData {
  const existing = data.pinnedKeys[userId];
  const keepVerified = existing?.signPub === signPub && existing.verified;
  const earlier = pinnedKeysOf(existing).filter((k) => k !== signPub);
  const next: PinnedKey = { signPub, verified: verified ?? keepVerified };
  if (earlier.length > 0) next.earlier = earlier;
  return { ...data, pinnedKeys: { ...data.pinnedKeys, [userId]: next } };
}

/** Every key the pin names, oldest first, the current one last; none for no pin. */
export function pinnedKeysOf(pinned: PinnedKey | undefined): B64[] {
  if (!pinned) return [];
  const out: B64[] = [];
  for (const k of [...(pinned.earlier ?? []), pinned.signPub]) if (!out.includes(k)) out.push(k);
  return out;
}
