import { derive, generateKey, toBase64Url } from "@jelly/crypto";
import { describe, expect, it } from "vitest";
import { addressTag, suggestionKey } from "../src/index.ts";
import { KDF } from "../src/tags.ts";

describe("address tags (dismissed contact suggestions)", () => {
  it("are deterministic per account key, ignoring case and surrounding space", () => {
    const key = suggestionKey(generateKey());
    const a = addressTag(key, "Anna@Example.org");
    expect(addressTag(key, "  anna@example.org ")).toBe(a);
    expect(addressTag(key, "mailto:anna@example.org")).toBe(a);
    expect(addressTag(key, "anna@example.com")).not.toBe(a);
    expect(a).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(a).not.toContain("anna");
  });

  it("differ between accounts: another account key gives other tags", () => {
    const one = suggestionKey(generateKey());
    const two = suggestionKey(generateKey());
    expect(addressTag(one, "anna@example.org")).not.toBe(addressTag(two, "anna@example.org"));
  });

  it("use their own key, separate from the account key and its other subkeys", () => {
    const ak = generateKey();
    const key = suggestionKey(ak);
    expect(suggestionKey(ak)).toEqual(key);
    expect(toBase64Url(key)).not.toBe(toBase64Url(ak));
    for (const other of Object.values(KDF).filter((c) => c !== KDF.contactSuggestions)) {
      expect(toBase64Url(derive(ak, other))).not.toBe(toBase64Url(key));
    }
    // A tag made straight under the account key doesn't match one made under the suggestion key.
    expect(addressTag(ak, "anna@example.org")).not.toBe(addressTag(key, "anna@example.org"));
  });
});
