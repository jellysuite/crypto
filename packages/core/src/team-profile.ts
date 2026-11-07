import {
  type Bytes,
  derive,
  fromBase64Url,
  type KeyPair,
  openJson,
  sealJson,
  sign,
  toBase64Url,
  utf8,
  verify,
} from "@jelly/crypto";
import { lengthPrefixed } from "./grants.ts";
import { KDF, SIG, TAG } from "./tags.ts";
import type { B64 } from "./wire.ts";

/*
 * A member's profile for one team (their photo and colour), readable by the team's members and nobody else: sealed
 * under a key derived from the team's current `everyone` group key, and signed by the member, since every member
 * holds that key.
 */

export type TeamProfile = { photo?: string; color?: string };
/** Where a profile belongs: the AD and the signature both bind it here. */
export type TeamProfileAt = { teamId: string; userId: string; version: number };
export type SealedTeamProfile = { data: B64; signature: B64 };

/** The cap on a photo's data URL (as in private settings). */
export const TEAM_PROFILE_PHOTO_MAX = 32_000;
const INLINE_IMAGE = /^data:image\/(jpeg|webp);base64,[A-Za-z0-9+/]+=*$/;
const HEX_COLOR = /^#[0-9a-f]{6}$/i;

export const teamProfileKey = (everyone: KeyPair): Bytes => derive(everyone.privateKey, KDF.teamProfile);

const ad = (at: TeamProfileAt): Bytes => utf8(`${at.teamId}:${at.userId}:${at.version}`);
const signed = (at: TeamProfileAt, data: B64): Bytes =>
  lengthPrefixed([at.teamId, at.userId, String(at.version), data]);

export function sealTeamProfile(key: Bytes, at: TeamProfileAt, p: TeamProfile, signing: KeyPair): SealedTeamProfile {
  const data = toBase64Url(sealJson(key, TAG.teamProfile, p, ad(at)));
  return { data, signature: toBase64Url(sign(signing.privateKey, SIG.teamProfile, signed(at, data))) };
}

/** The profile, with only a well-formed photo and colour kept; null unless it opens here and `signPub` signed it. */
export function openTeamProfile(
  key: Bytes,
  at: TeamProfileAt,
  s: SealedTeamProfile,
  signPub: Bytes,
): TeamProfile | null {
  try {
    if (!verify(signPub, SIG.teamProfile, signed(at, s.data), fromBase64Url(s.signature))) return null;
    const p = openJson<Record<string, unknown>>(key, TAG.teamProfile, fromBase64Url(s.data), ad(at));
    const out: TeamProfile = {};
    if (typeof p.photo === "string" && p.photo.length < TEAM_PROFILE_PHOTO_MAX && INLINE_IMAGE.test(p.photo))
      out.photo = p.photo;
    if (typeof p.color === "string" && HEX_COLOR.test(p.color)) out.color = p.color;
    return out;
  } catch {
    return null;
  }
}
