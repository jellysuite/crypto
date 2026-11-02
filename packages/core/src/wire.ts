import type { KeyChange } from "./identity-chain.ts";

/** base64url without padding */
export type B64 = string;

export type Role = "viewer" | "editor" | "owner";

export const ROLE_RANK: Record<Role, number> = { viewer: 1, editor: 2, owner: 3 };

export const atLeast = (role: Role | null | undefined, min: Role): boolean =>
  role != null && ROLE_RANK[role] >= ROLE_RANK[min];

export type AccountBundle = { signPub: B64; encPub: B64; encPubSig: B64; privateKeys: B64; privateData: B64 };

export type PublicIdentity = {
  userId: string;
  handle: string;
  signPub: B64;
  encPub: B64;
  encPubSig: B64;
  /**
   * The account's signing-key changes, oldest first; absent when the key never changed. `keyChain(signPub,
   * keyChanges)` resolves the earlier keys (spec §6.2).
   */
  keyChanges?: KeyChange[];
  /**
   * The server reports the account deleted (a tombstone, §5.5): a re-key leaves it out of its seals and names it in
   * the snapshot's `skipped`. The server's word only, so it can only delay that person's next key, never remove them.
   */
  deleted?: true;
};
