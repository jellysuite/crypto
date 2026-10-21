/** One item of a normalised feed, as the fetcher returns it (Jelly Reader). */
export interface FeedItem {
  /** Stable per feed: the feed's guid/id, else the item link, else sha256(title, published). */
  guid: string;
  url: string | null;
  title: string;
  author: string | null;
  /** ISO 8601. */
  publishedAt: string | null;
  /** Sanitised, at most 64 KB, images rewritten to fetcher capability URLs. */
  summaryHtml: string;
  /** A fetcher capability URL. */
  imageUrl: string | null;
  enclosure: { url: string; type: string; length: number | null } | null;
  youtubeId: string | null;
}

/** RSS, Atom and JSON Feed normalised to one shape, at most 200 items, newest first. */
export interface ParsedFeed {
  title: string;
  siteUrl: string | null;
  /** A fetcher capability URL. */
  iconUrl: string | null;
  items: FeedItem[];
}
