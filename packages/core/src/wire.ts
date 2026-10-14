/** base64url without padding */
export type B64 = string;

export type Role = "viewer" | "editor" | "owner";

export const ROLE_RANK: Record<Role, number> = { viewer: 1, editor: 2, owner: 3 };

export const atLeast = (role: Role | null | undefined, min: Role): boolean =>
  role != null && ROLE_RANK[role] >= ROLE_RANK[min];

export type AccountBundle = { signPub: B64; encPub: B64; encPubSig: B64; privateKeys: B64; privateData: B64 };

export type PublicIdentity = { userId: string; handle: string; signPub: B64; encPub: B64; encPubSig: B64 };
