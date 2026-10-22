/** Which list a reminder belongs to: calendar reminders or task dues. */
export type ReminderSource = "calendar" | "tasks";

/** Each source's ids live in a range of their own, so one source never cancels another's (or a plain notify). */
export const REMINDER_ID_RANGE: Record<ReminderSource, number> = { calendar: 1_000_000_000, tasks: 1_500_000_000 };
export const REMINDER_ID_RANGE_SIZE = 500_000_000;

/**
 * The id a reminder shows under on a device: FNV-1a of its stable key, inside its source's range. The apps schedule
 * their own reminders under it, and our server pushes the same reminder with it as `apns-collapse-id`, so where both
 * arrive (the Mac app) the system holds one notification, not two.
 */
export function reminderNoticeId(source: ReminderSource, key: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < key.length; i++) {
    h ^= key.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return REMINDER_ID_RANGE[source] + ((h >>> 0) % REMINDER_ID_RANGE_SIZE);
}
