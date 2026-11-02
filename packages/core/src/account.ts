import {
  type Bytes,
  derive,
  fromBase64Url,
  generateEncryptionKeyPair,
  generateKey,
  generateSigningKeyPair,
  type KeyPair,
  open,
  openJson,
  seal,
  sealJson,
  sign,
  toBase64Url,
  utf8,
  verify,
} from "@jelly/crypto";
import type { KeyChangeReq } from "./api.ts";
import { createKeyChange } from "./identity-chain.ts";
import { newRecoveryMaterial } from "./recovery.ts";
import { KDF, SIG, TAG } from "./tags.ts";
import type { AccountBundle, B64, PublicIdentity } from "./wire.ts";

/**
 * A contact's pinned signing key. `earlier` holds every key this account pinned for them before, oldest first
 * (spec §6.1: pins keep their history), so what they signed under an older key still resolves to them.
 */
export type PinnedKey = { signPub: B64; verified: boolean; earlier?: B64[] };
/** A contact's pinned OpenPGP public key (armored) and where we first got it. */
export type PgpContact = {
  fingerprint: string;
  key: string;
  source: "manual" | "wkd" | "vks" | "autocrypt";
  firstSeen: string;
};
export type PrivateData = {
  pinnedKeys: Record<string, PinnedKey>;
  settings: Record<string, unknown>;
  /** Mirrors the server's `private_data_revision` for this blob; each save writes previous + 1. */
  revision?: number;
  pgpContacts?: Record<string, PgpContact>;
  /** Team signing keys pinned on join (after comparing safety words); later keys only through the signed chain. */
  teamPins?: Record<string, TeamPin>;
  /**
   * Ids of teams this account has pinned a key for. A team listed here with no pin is a lost pin, never a first
   * sight: the key chain is not re-anchored at whatever the server calls version 1. Also kept per device.
   */
  teamsSeen?: string[];
  /**
   * What this account took away, so a re-key never hands it back on the server's word: per node, the people
   * removed from it (user id to the grant signatures on the shares of theirs it saw then) and the share links
   * turned off.
   */
  revoked?: { people?: Record<string, Record<string, B64[]>>; links?: Record<string, string[]> };
};
export type TeamPin = {
  version: number;
  signPub: B64;
  /**
   * Older team keys this account verified on the way to the pin (each through the signed chain from an
   * earlier pin), so what they signed (a former member's proof, an old group key) can still be checked.
   */
  earlier?: Array<{ version: number; signPub: B64 }>;
  /**
   * Per group id, the newest group version this account verified (and its key): a floor the server can't roll
   * back, as an older version is never sealed or granted to again.
   */
  groups?: Record<string, { version: number; encPub: B64 }>;
  /**
   * The team's workspace root, as a statement signed by a verified team key named it: a root the server names
   * otherwise is refused, and the fold takes no other team-anchored root for this team's (Task 6b).
   */
  rootNodeId?: string;
  /**
   * Pinned on first sight by someone outside the team who holds a share on one of its items (§11): no membership,
   * no group keys, the team's history is only checked. Cleared when this account joins the team.
   */
  outsider?: boolean;
};

export type UnlockedAccount = {
  userId: string;
  handle: string;
  ak: Bytes;
  signing: KeyPair;
  encryption: KeyPair;
  privateData: PrivateData;
  /** Private data couldn't be decrypted (corrupted or overwritten); pins were reset and should be re-verified. */
  privateDataLost: boolean;
};

export type NewAccount = {
  ak: Bytes;
  bundle: AccountBundle;
  recoveryKey: string;
  recoveryWrap: B64;
  recoveryAuthHash: B64;
};

type PrivateKeys = { signPriv: B64; encPriv: B64 };

// Private blobs are bound to the account's signing key so they can't be swapped between accounts.
const accountAd = (signPub: B64) => utf8(signPub);

const pgpAd = (signPub: B64) => utf8(`${signPub}:pgp-keys`);

/** Seal armored PGP private keys to the account key; the server only ever stores the result. */
export const sealPgpKeys = (ak: Bytes, signPub: B64, keys: string[]): B64 =>
  toBase64Url(sealJson(ak, TAG.pgpKeys, { keys }, pgpAd(signPub)));

export const openPgpKeys = (ak: Bytes, signPub: B64, sealed: B64): string[] =>
  openJson<{ keys: string[] }>(ak, TAG.pgpKeys, fromBase64Url(sealed), pgpAd(signPub)).keys;

export function encryptPrivateData(ak: Bytes, signPub: B64, data: PrivateData): B64 {
  return toBase64Url(sealJson(ak, TAG.privateData, data, accountAd(signPub)));
}

export function createAccount(): NewAccount {
  const ak = generateKey();
  const signing = generateSigningKeyPair();
  const encryption = generateEncryptionKeyPair();
  const signPub = toBase64Url(signing.publicKey);
  const keys: PrivateKeys = {
    signPriv: toBase64Url(signing.privateKey),
    encPriv: toBase64Url(encryption.privateKey),
  };
  const bundle: AccountBundle = {
    signPub,
    encPub: toBase64Url(encryption.publicKey),
    encPubSig: toBase64Url(sign(signing.privateKey, SIG.identityEncKey, encryption.publicKey)),
    privateKeys: toBase64Url(sealJson(ak, TAG.privateKeys, keys, accountAd(signPub))),
    privateData: encryptPrivateData(ak, signPub, { pinnedKeys: {}, settings: {}, revision: 0 }),
  };
  return { ak, bundle, ...newRecoveryMaterial(ak) };
}

const passwordWrapKey = (exportKey: string) => derive(fromBase64Url(exportKey), KDF.passwordWrap);

export const passwordWrap = (ak: Bytes, exportKey: string): B64 =>
  toBase64Url(seal(passwordWrapKey(exportKey), TAG.akWrap, ak));

export const unwrapPasswordWrap = (wrap: B64, exportKey: string): Bytes =>
  open(passwordWrapKey(exportKey), TAG.akWrap, fromBase64Url(wrap));

export function verifyIdentity(id: Pick<PublicIdentity, "signPub" | "encPub" | "encPubSig">): boolean {
  try {
    return verify(fromBase64Url(id.signPub), SIG.identityEncKey, fromBase64Url(id.encPub), fromBase64Url(id.encPubSig));
  } catch {
    return false;
  }
}

export function unlockAccount(input: {
  userId: string;
  handle: string;
  ak: Bytes;
  bundle: AccountBundle;
}): UnlockedAccount {
  const { bundle, ak } = input;
  if (!verifyIdentity(bundle)) throw new Error("account identity signature is invalid");
  const ad = accountAd(bundle.signPub);
  const keys = openJson<PrivateKeys>(ak, TAG.privateKeys, fromBase64Url(bundle.privateKeys), ad);
  // Losing pins is recoverable; refusing to unlock would turn a corrupted blob into a lost account.
  let privateData: PrivateData = { pinnedKeys: {}, settings: {} };
  let privateDataLost = false;
  try {
    privateData = openJson<PrivateData>(ak, TAG.privateData, fromBase64Url(bundle.privateData), ad);
  } catch {
    privateDataLost = true;
  }
  return {
    userId: input.userId,
    handle: input.handle,
    ak,
    signing: { publicKey: fromBase64Url(bundle.signPub), privateKey: fromBase64Url(keys.signPriv) },
    encryption: { publicKey: fromBase64Url(bundle.encPub), privateKey: fromBase64Url(keys.encPriv) },
    privateData,
    privateDataLost,
  };
}

/**
 * The body of `POST /account/key-change`: the signing key moves to `next` and the account is re-sealed for it,
 * since its private blobs are bound to the signing key. The encryption key stays (grants and seals are made to it).
 * `privateDataRevision` is the server's revision + 1; `pgpKeys` are the account's opened PGP keys, if it has any.
 */
export function keyChangeRequest(
  account: UnlockedAccount,
  next: KeyPair,
  opts: { at: string; privateDataRevision: number; pgpKeys?: string[] },
): KeyChangeReq {
  const signPub = toBase64Url(next.publicKey);
  const keys: PrivateKeys = {
    signPriv: toBase64Url(next.privateKey),
    encPriv: toBase64Url(account.encryption.privateKey),
  };
  return {
    change: createKeyChange(account, next, opts.at),
    bundle: {
      signPub,
      encPub: toBase64Url(account.encryption.publicKey),
      encPubSig: toBase64Url(sign(next.privateKey, SIG.identityEncKey, account.encryption.publicKey)),
      privateKeys: toBase64Url(sealJson(account.ak, TAG.privateKeys, keys, accountAd(signPub))),
      privateData: encryptPrivateData(account.ak, signPub, {
        ...account.privateData,
        revision: opts.privateDataRevision,
      }),
    },
    privateDataRevision: opts.privateDataRevision,
    ...(opts.pgpKeys ? { pgpSealedKeys: sealPgpKeys(account.ak, signPub, opts.pgpKeys) } : {}),
  };
}
