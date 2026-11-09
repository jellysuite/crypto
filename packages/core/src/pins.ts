import type { PinnedKey, PrivateData } from "./account.ts";
import { normalizeHandle } from "./handles.ts";
import type { B64 } from "./wire.ts";

export type PinStatus = "new" | "match" | "mismatch";

export function checkPin(data: PrivateData, userId: string, signPub: B64): PinStatus {
  const pinned = data.pinnedKeys[userId];
  if (!pinned) return "new";
  return pinned.signPub === signPub ? "match" : "mismatch";
}

/** The account a pin names for `handle`, if any (handles are never reused, so at most one). */
export function pinnedUserOfHandle(data: PrivateData, handle: string): string | undefined {
  const h = normalizeHandle(handle);
  for (const [userId, p] of Object.entries(data.pinnedKeys))
    if (p.handle !== undefined && p.handle === h) return userId;
  return undefined;
}

/**
 * `checkPin` plus the handle, both of them the server's word: an identity is a mismatch when its key differs from
 * the pin, when the pinned account comes under another handle, or when a handle pinned to one account comes with
 * another (a handle never moves to another account and an account's handle never changes). A pin from before
 * handles were recorded checks the key alone until `backfillHandle` fills it in.
 */
export function checkIdentity(data: PrivateData, id: { userId: string; handle: string; signPub: B64 }): PinStatus {
  const handle = normalizeHandle(id.handle);
  const holder = pinnedUserOfHandle(data, handle);
  if (holder !== undefined && holder !== id.userId) return "mismatch";
  const pinned = data.pinnedKeys[id.userId];
  if (pinned?.handle !== undefined && pinned.handle !== handle) return "mismatch";
  return checkPin(data, id.userId, id.signPub);
}

/**
 * The handle to show for `userId`: the pinned one when there is a pin with a handle, else what the server names
 * (`served`) unless that handle is pinned to another account (then none: the server's word can't borrow a name).
 */
export function shownHandle(data: PrivateData, userId: string, served: string | undefined): string | undefined {
  const pinned = data.pinnedKeys[userId]?.handle;
  if (pinned !== undefined) return pinned;
  if (served === undefined) return undefined;
  const holder = pinnedUserOfHandle(data, served);
  return holder === undefined || holder === userId ? served : undefined;
}

/**
 * Records the handle of a pin that has none yet (pins from before handles were kept), on a sight that matches the
 * pin: first sight of the handle, as the key had. Returns `data` itself when there is nothing to fill.
 */
export function backfillHandle(data: PrivateData, id: { userId: string; handle: string; signPub: B64 }): PrivateData {
  const pinned = data.pinnedKeys[id.userId];
  if (!pinned || pinned.handle !== undefined || checkIdentity(data, id) !== "match") return data;
  return {
    ...data,
    pinnedKeys: { ...data.pinnedKeys, [id.userId]: { ...pinned, handle: normalizeHandle(id.handle) } },
  };
}

/**
 * Pins `signPub` for the user. A key that replaces another keeps the old one in `earlier` (the pin's history), so
 * `pinnedKeysOf` still lists it; the current key alone decides `checkPin`. `handle` is recorded when the pin has
 * none; a pin's handle never changes.
 */
export function pin(data: PrivateData, userId: string, signPub: B64, verified?: boolean, handle?: string): PrivateData {
  const existing = data.pinnedKeys[userId];
  const keepVerified = existing?.signPub === signPub && existing.verified;
  const earlier = pinnedKeysOf(existing).filter((k) => k !== signPub);
  const next: PinnedKey = { signPub, verified: verified ?? keepVerified };
  if (earlier.length > 0) next.earlier = earlier;
  const h = existing?.handle ?? (handle === undefined ? undefined : normalizeHandle(handle));
  if (h !== undefined) next.handle = h;
  return { ...data, pinnedKeys: { ...data.pinnedKeys, [userId]: next } };
}

/** Every key the pin names, oldest first, the current one last; none for no pin. */
export function pinnedKeysOf(pinned: PinnedKey | undefined): B64[] {
  if (!pinned) return [];
  const out: B64[] = [];
  for (const k of [...(pinned.earlier ?? []), pinned.signPub]) if (!out.includes(k)) out.push(k);
  return out;
}
