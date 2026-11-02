import { hashWith, toBase64Url } from "@jelly/crypto";
import { lengthPrefixed } from "../grants.ts";
import type { B64 } from "../wire.ts";

/**
 * The head a dep names for a group version: a hash of the version's stable fields (team, group, version number
 * and its encryption key), base64url. Not of its signature: a team key rotation re-signs the current version of
 * every group, and a head that changed with it would break every dep on that version. The signature still binds
 * these fields to the team key (`verifyGroupVersion`). Server and clients derive it the same way.
 */
export const groupHead = (v: { teamId: string; groupId: string; version: number; encPub: B64 }): B64 =>
  toBase64Url(hashWith("jelly-group-head@2", lengthPrefixed([v.teamId, v.groupId, String(v.version), v.encPub])));
