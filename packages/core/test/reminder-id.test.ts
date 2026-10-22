import { describe, expect, it } from "vitest";
import { reminderNoticeId } from "../src/reminder-id.ts";

/*
 * The id a reminder shows under on the Mac and the phone, the same whether the app scheduled it or our server
 * pushed it (as apns-collapse-id), so the two are one notification there.
 */
describe("reminderNoticeId", () => {
  it("is FNV-1a of the key inside the source's range, as the apps have always numbered them", () => {
    expect(reminderNoticeId("calendar", "e1@1792656000000#10")).toBe(1345952709);
    expect(reminderNoticeId("tasks", "p1/t1@abc")).toBe(1589328208);
  });

  it("keeps each source in a range of its own", () => {
    const c = reminderNoticeId("calendar", "x");
    const t = reminderNoticeId("tasks", "x");
    expect(c).toBeGreaterThanOrEqual(1_000_000_000);
    expect(c).toBeLessThan(1_500_000_000);
    expect(t).toBeGreaterThanOrEqual(1_500_000_000);
    expect(t).toBeLessThan(2_000_000_000);
  });
});
