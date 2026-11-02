import { fromBase64Url, type KeyPair, sign, toBase64Url, verify } from "@jelly/crypto";
import type { UnlockedAccount } from "./account.ts";
import { lengthPrefixed } from "./grants.ts";
import { SIG } from "./tags.ts";
import type { B64 } from "./wire.ts";

/**
 * An account's signing key changing: the old key signs over to the new one and the new one signs back, both over
 * the same statement (`key-change@1`). A device that never knew the old key can then still resolve it from the
 * current key (spec §6.2).
 */
export type KeyChange = { userId: string; oldSignPub: B64; newSignPub: B64; at: string; oldSig: B64; newSig: B64 };

const changePayload = (c: Pick<KeyChange, "userId" | "oldSignPub" | "newSignPub" | "at">) =>
  lengthPrefixed([c.userId, c.oldSignPub, c.newSignPub, c.at]);

export function createKeyChange(
  oldAccount: Pick<UnlockedAccount, "userId" | "signing">,
  newSigning: KeyPair,
  at: string,
): KeyChange {
  const c = {
    userId: oldAccount.userId,
    oldSignPub: toBase64Url(oldAccount.signing.publicKey),
    newSignPub: toBase64Url(newSigning.publicKey),
    at,
  };
  const payload = changePayload(c);
  return {
    ...c,
    oldSig: toBase64Url(sign(oldAccount.signing.privateKey, SIG.keyChange, payload)),
    newSig: toBase64Url(sign(newSigning.privateKey, SIG.keyChange, payload)),
  };
}

/** Whether both the old and the new key signed this exact statement. */
export function verifyKeyChange(c: KeyChange): boolean {
  try {
    const payload = changePayload(c);
    return (
      verify(fromBase64Url(c.oldSignPub), SIG.keyChange, payload, fromBase64Url(c.oldSig)) &&
      verify(fromBase64Url(c.newSignPub), SIG.keyChange, payload, fromBase64Url(c.newSig))
    );
  } catch {
    return false;
  }
}

/**
 * Every key of the account from the oldest to `current`, walking back through the changes; null if any change is
 * unsigned by a side, the chain has a gap, a fork or a loop, mixes users, has changes left over, or doesn't end
 * at `current`. With `userId`, also null if the changes are another user's (a valid chain served under the wrong
 * name says nothing about that name).
 */
export function keyChain(current: B64, changes: KeyChange[], userId?: string): B64[] | null {
  if (!changes.every(verifyKeyChange)) return null;
  if (changes.some((c) => c.userId !== changes[0]?.userId)) return null;
  if (userId !== undefined && changes.some((c) => c.userId !== userId)) return null;
  const byNew = new Map<B64, KeyChange>();
  for (const c of changes) {
    if (byNew.has(c.newSignPub)) return null;
    byNew.set(c.newSignPub, c);
  }
  const keys = [current];
  const seen = new Set(keys);
  let used = 0;
  for (let c = byNew.get(current); c; c = byNew.get(c.oldSignPub)) {
    if (seen.has(c.oldSignPub)) return null;
    seen.add(c.oldSignPub);
    keys.push(c.oldSignPub);
    used++;
  }
  return used === changes.length ? keys.reverse() : null;
}
