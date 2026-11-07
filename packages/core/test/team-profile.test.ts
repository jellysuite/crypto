import { generateEncryptionKeyPair, generateSigningKeyPair, ready } from "@jelly/crypto";
import { beforeAll, describe, expect, it } from "vitest";
import { openTeamProfile, sealTeamProfile, TEAM_PROFILE_PHOTO_MAX, teamProfileKey } from "../src/team-profile.ts";

beforeAll(async () => {
  await ready();
});

const photo = "data:image/jpeg;base64,/9j/4AAQSkZJRg==";

describe("team profiles", () => {
  it("opens what the member sealed, only under the same team, member and version, signed by them", () => {
    const everyone = generateEncryptionKeyPair();
    const me = generateSigningKeyPair();
    const key = teamProfileKey(everyone);
    const at = { teamId: "t1", userId: "u1", version: 3 };
    const sealed = sealTeamProfile(key, at, { photo, color: "#2348c9" }, me);
    const open = (over: Partial<typeof at> = {}, signPub = me.publicKey, s = sealed) =>
      openTeamProfile(key, { ...at, ...over }, s, signPub);
    expect(open()).toEqual({ photo, color: "#2348c9" });
    expect(open({ userId: "u2" })).toBeNull();
    expect(open({ teamId: "t2" })).toBeNull();
    expect(open({ version: 4 })).toBeNull();
    expect(open({}, generateSigningKeyPair().publicKey)).toBeNull();
    expect(openTeamProfile(teamProfileKey(generateEncryptionKeyPair()), at, sealed, me.publicKey)).toBeNull();
    expect(open({}, me.publicKey, { ...sealed, signature: sealed.signature.slice(0, -4) })).toBeNull();
  });
  it("keeps only a well-formed photo and colour", () => {
    const everyone = generateEncryptionKeyPair();
    const me = generateSigningKeyPair();
    const key = teamProfileKey(everyone);
    const at = { teamId: "t1", userId: "u1", version: 1 };
    const odd = sealTeamProfile(
      key,
      at,
      { photo: "javascript:alert(1)", color: "red; background:url(x)" } as never,
      me,
    );
    expect(openTeamProfile(key, at, odd, me.publicKey)).toEqual({});
    const big = sealTeamProfile(key, at, { photo: `data:image/jpeg;base64,${"A".repeat(TEAM_PROFILE_PHOTO_MAX)}` }, me);
    expect(openTeamProfile(key, at, big, me.publicKey)).toEqual({});
  });
});
