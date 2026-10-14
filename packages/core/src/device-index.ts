// Device-side search indexes (Chat's messages, Tasks' tasks): the index lives only on the device. It is serialised,
// sealed by an injected cipher (web: the device's non-extractable AES-GCM key, with a tag and associated data per
// index) and handed to injected storage. The server never sees indexed text or search terms.
import type { Bytes } from "@jelly/crypto";

export interface SearchStorage {
  load(): Promise<Bytes | null>;
  save(data: Bytes): Promise<void>;
  clear(): Promise<void>;
}
export interface SearchCipher {
  seal(plain: Bytes): Promise<Bytes>;
  open(sealed: Bytes): Promise<Bytes>;
}

// Han, Hiragana, Katakana, Hangul and Thai have no spaces between words: index them per character.
const CJK = "\\p{Script=Han}\\p{Script=Hiragana}\\p{Script=Katakana}\\p{Script=Hangul}\\p{Script=Thai}";
const TOKEN_RE = new RegExp(`[${CJK}]|(?:(?![${CJK}])[\\p{L}\\p{N}\\p{M}])+`, "gu");

/** Words for a search index: letters and digits runs, CJK per character, lower case. */
export function tokenize(text: string): string[] {
  return [...text.toLowerCase().matchAll(TOKEN_RE)].map((m) => m[0]);
}

const FLUSH_DELAY_MS = 2000;
const FLUSH_MAX_WAIT_MS = 12000;
const enc = new TextEncoder();
const dec = new TextDecoder();

/**
 * Reads a sealed JSON payload (null when there is none; on anything unreadable the stored copy is cleared and
 * null returned, so the caller starts empty).
 */
export async function loadSealed(o: { storage: SearchStorage; cipher: SearchCipher }): Promise<unknown> {
  try {
    const sealed = await o.storage.load();
    if (sealed) return JSON.parse(dec.decode(await o.cipher.open(sealed))) as unknown;
  } catch {
    try {
      await o.storage.clear();
    } catch {
      // nothing more to do; start empty regardless
    }
  }
  return null;
}

/**
 * Saves a sealed JSON payload after changes: debounced (2 s, at most 12 s after the first unsaved change),
 * serialised so an older snapshot never overwrites a newer one, retried while it fails, and stopped by `close`.
 */
export class SealedSaver {
  private timer: ReturnType<typeof setTimeout> | null = null;
  private firstDirtyAt: number | null = null;
  private dirty = false;
  private closed = false;
  private saving: Promise<void> = Promise.resolve();
  private readonly o: { storage: SearchStorage; cipher: SearchCipher; payload: () => unknown };

  constructor(o: { storage: SearchStorage; cipher: SearchCipher; payload: () => unknown }) {
    this.o = o;
  }

  /** Something changed: save soon. */
  changed(): void {
    if (this.closed) return;
    this.dirty = true;
    const now = Date.now();
    this.firstDirtyAt ??= now;
    this.cancelTimer();
    const delay = Math.max(0, Math.min(FLUSH_DELAY_MS, this.firstDirtyAt + FLUSH_MAX_WAIT_MS - now));
    this.timer = setTimeout(() => {
      this.timer = null;
      this.flush().catch(() => {
        // stays dirty; retry on the next tick
        if (this.dirty) this.changed();
      });
    }, delay);
  }

  /** Persist now (cancels any pending debounced save). No-op once closed. */
  async flush(): Promise<void> {
    this.cancelTimer();
    if (this.closed) return;
    this.dirty = false;
    this.firstDirtyAt = null;
    const payload = this.o.payload();
    const run = async () => {
      if (this.closed) return;
      await this.o.storage.save(await this.o.cipher.seal(enc.encode(JSON.stringify(payload))));
    };
    const next = this.saving.then(run, run);
    this.saving = next.catch(() => {});
    try {
      await next;
    } catch (e) {
      this.dirty = true;
      this.firstDirtyAt ??= Date.now();
      throw e;
    }
  }

  /** Stop all persistence (e.g. on logout). With `clear`, wipe the stored copy after in-flight saves settle. */
  async close(o: { clear?: boolean } = {}): Promise<void> {
    this.closed = true;
    this.cancelTimer();
    await this.saving;
    if (o.clear) await this.o.storage.clear();
  }

  private cancelTimer(): void {
    if (this.timer !== null) {
      clearTimeout(this.timer);
      this.timer = null;
    }
  }
}
