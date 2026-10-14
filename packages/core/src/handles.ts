export const RESERVED_HANDLES: ReadonlySet<string> = new Set([
  "abuse",
  "admin",
  "administrator",
  "api",
  "billing",
  "help",
  "hostmaster",
  "info",
  "jelly",
  "jellysuite",
  "legal",
  "mail",
  "mailer-daemon",
  "no-reply",
  "noreply",
  "postmaster",
  "privacy",
  "root",
  "sales",
  "security",
  "support",
  "system",
  "team",
  "webmaster",
  "www",
]);

const HANDLE = /^[a-z][a-z0-9._-]{2,29}$/;

export const normalizeHandle = (s: string): string => s.trim().toLowerCase();

export function validateHandle(s: string): { ok: true } | { ok: false; reason: "format" | "reserved" } {
  if (!HANDLE.test(s)) return { ok: false, reason: "format" };
  if (RESERVED_HANDLES.has(s)) return { ok: false, reason: "reserved" };
  return { ok: true };
}

const ADDRESS_LOCAL = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const HOSTNAME = /^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

/**
 * A managed account's handle: its address, `local@domain` (lowercase). Only created through invite
 * activation; `validateHandle` (sign-up) refuses it, login accepts both forms.
 */
export function validateAddressHandle(s: string): boolean {
  const at = s.indexOf("@");
  if (at < 0 || at !== s.lastIndexOf("@")) return false;
  return ADDRESS_LOCAL.test(s.slice(0, at)) && HOSTNAME.test(s.slice(at + 1));
}
