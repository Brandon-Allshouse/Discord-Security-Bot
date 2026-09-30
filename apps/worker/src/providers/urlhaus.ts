import type { Redis } from 'ioredis';
import { normalizeUrl, URLHAUS_URLS_KEY, type IntelKind, type IntelProvider, type ProviderResult } from '@equinox/core';
import { getText, type FetchLike } from '../net/http.js';
import { recordUrlhausSync } from '../status.js';

/** Currently-online malware URLs. abuse.ch asks that this is fetched no more than every 5 minutes. */
export const URLHAUS_FEED_URL = 'https://urlhaus.abuse.ch/downloads/csv_online/';
export const URLHAUS_REASON = 'Listed by URLhaus as a malware link';

/** One CSV field list per line. The feed quotes every field and never embeds newlines. */
export function parseCsvLine(line: string): string[] {
  const fields: string[] = [];
  let field = '';
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const char = line[i]!;
    if (quoted) {
      if (char !== '"') field += char;
      else if (line[i + 1] === '"') {
        field += '"';
        i++;
      } else quoted = false;
    } else if (char === '"') quoted = true;
    else if (char === ',') {
      fields.push(field);
      field = '';
    } else field += char;
  }
  fields.push(field);
  return fields;
}

/** Normalized URLs from the URLhaus CSV. Column 3 is the URL; lines starting with # are comments. */
export function parseUrlhausCsv(csv: string): string[] {
  const urls = new Set<string>();
  for (const line of csv.split(/\r?\n/)) {
    if (line.length === 0 || line.startsWith('#')) continue;
    const raw = parseCsvLine(line)[2];
    const normalized = raw ? normalizeUrl(raw) : null;
    if (normalized) urls.add(normalized.url);
  }
  return [...urls];
}

/**
 * The URLhaus feed, synced into a Redis set. Matching is by exact URL, never by host:
 * URLhaus lists files on shared hosts (GitHub, Discord's CDN), and blocking the whole host would be a disaster.
 */
export class UrlhausFeed implements IntelProvider {
  readonly name = 'urlhaus';
  readonly supports = ['url'] as const;

  constructor(
    private readonly redis: Redis,
    private readonly options: { authKey?: string | undefined; fetch?: FetchLike } = {},
  ) {}

  /** Replaces the set in one step, so readers never see a half-loaded feed. Returns the entry count. */
  async sync(): Promise<number> {
    const csv = await getText(URLHAUS_FEED_URL, {
      headers: this.options.authKey ? { 'auth-key': this.options.authKey } : {},
      timeoutMs: 60_000,
      maxBytes: 64 * 1024 * 1024,
      ...(this.options.fetch ? { fetch: this.options.fetch } : {}),
    });
    const urls = parseUrlhausCsv(csv);
    if (urls.length === 0) return 0;
    const staging = `${URLHAUS_URLS_KEY}:staging`;
    await this.redis.del(staging);
    for (let i = 0; i < urls.length; i += 1000) await this.redis.sadd(staging, ...urls.slice(i, i + 1000));
    await this.redis.rename(staging, URLHAUS_URLS_KEY);
    await recordUrlhausSync(this.redis, urls.length);
    return urls.length;
  }

  async lookup(subject: string, kind: IntelKind): Promise<ProviderResult | null> {
    if (kind !== 'url') return null;
    const listed = (await this.redis.sismember(URLHAUS_URLS_KEY, subject)) === 1;
    return {
      provider: this.name,
      kind,
      subject,
      level: listed ? 'malicious' : 'unknown',
      weight: listed ? 0.95 : 0,
      reasons: listed ? [URLHAUS_REASON] : [],
      details: { listed },
    };
  }
}
