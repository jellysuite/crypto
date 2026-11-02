import { describe, expect, it } from "vitest";
import { concatBytes, hashWith, utf8 } from "../src/index.ts";
import { sodium } from "../src/sodium.ts";

describe("hashWith", () => {
  it("separates contexts and inputs", () => {
    const x = utf8("x");
    expect(hashWith("a", x)).toHaveLength(32);
    expect(hashWith("a", x)).not.toEqual(hashWith("b", x));
    expect(hashWith("a", x)).toEqual(
      sodium().crypto_generichash(32, concatBytes(utf8("a"), new Uint8Array([0]), x), null),
    );
    expect(hashWith("a", utf8("x"), utf8("y"))).toEqual(hashWith("a", utf8("xy")));
  });
});
