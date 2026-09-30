import {
  assessUrl,
  cacheTtlSeconds,
  defang,
  isKnownSafe,
  normalizeUrl,
  summarizeIntel,
  type IntelKind,
  type IntelProvider,
  type IntelSummary,
  type NormalizedUrl,
  type ProviderResult,
} from '@equinox/core';
import type { Logger } from './logger.js';
import { expandRedirects, type Expansion, type SafeFetchOptions } from './net/safe-fetch.js';

/** Link shorteners: always worth following, since the short link says nothing about the target. */
export const SHORTENERS = new Set([
  'bit.ly', 'bitly.com', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'v.gd', 'cutt.ly', 'rebrand.ly', 'shorturl.at',
  'rb.gy', 'ow.ly', 'buff.ly', 'tiny.cc', 's.id', 't.ly', 'shorturl.asia', 'lnkd.in', 'surl.li', 'qrco.de', 'bl.ink',
  'short.io', 'tr.ee', 'x.gd', 'u.to', 'clck.ru', 'shorte.st', 'adf.ly', 'ouo.io', 'urlz.fr', 'l.ead.me',
]);

/**
 * Following a link means our server visits it, so only do that when it's worth it:
 * shorteners, and links that already look a little off. Plain unknown links aren't fetched,
 * which also avoids consuming one-time links (password resets, invites) people share.
 */
export const EXPAND_MIN_SCORE = 0.2;

export function shouldExpand(url: NormalizedUrl, heuristicScore: number): boolean {
  if (url.isIp) return false;
  return (url.domain !== null && SHORTENERS.has(url.domain)) || SHORTENERS.has(url.host) || heuristicScore >= EXPAND_MIN_SCORE;
}

/** Redirect expansion as a provider, so its answer is cached like any other. */
export class RedirectProvider implements IntelProvider {
  readonly name = 'redirects';
  readonly supports = ['url'] as const;

  constructor(private readonly options: SafeFetchOptions = {}) {}

  async lookup(subject: string, kind: IntelKind): Promise<ProviderResult | null> {
    if (kind !== 'url') return null;
    const expansion: Expansion = await expandRedirects(subject, this.options);
    // Couldn't reach the site at all: an outage, not an answer, so it isn't cached.
    if ((expansion.stoppedBy === 'error' || expansion.stoppedBy === 'timeout') && expansion.hops.length === 1) {
      throw new Error(`link unreachable (${expansion.stoppedBy})`);
    }
    const result: ProviderResult = {
      provider: this.name,
      kind,
      subject,
      level: 'unknown',
      weight: 0,
      reasons: [],
      details: { finalUrl: expansion.finalUrl, hops: expansion.hops.length - 1, stoppedBy: expansion.stoppedBy },
    };
    if (expansion.stoppedBy === 'too_many_hops') {
      return { ...result, level: 'suspicious', weight: 0.2, reasons: ['Goes through a long chain of redirects'] };
    }
    if (expansion.stoppedBy === 'blocked' && expansion.hops.length > 1) {
      return { ...result, level: 'suspicious', weight: 0.3, reasons: ['Redirects to a private or internal address'] };
    }
    return result;
  }
}

/** Where cached provider answers live. ProviderResultStore in production. */
export interface ResultCache {
  get(provider: string, kind: IntelKind, subject: string): Promise<ProviderResult | null>;
  put(result: ProviderResult, ttlSeconds: number): Promise<void>;
}

export interface ChainDeps {
  cache: ResultCache;
  redirects: IntelProvider;
  urlhaus: IntelProvider;
  rdap: IntelProvider;
  logger: Pick<Logger, 'warn'>;
}

export interface Resolution {
  summary: IntelSummary;
  results: ProviderResult[];
  /** The URL a VirusTotal lookup should ask about: where the link really ends up. */
  finalUrl: string;
}

/**
 * Asks one provider, through the cache. A provider that is down or broken returns nothing
 * instead of failing the lookup: the other sources and the local heuristics still count.
 */
export async function ask(
  provider: IntelProvider,
  kind: IntelKind,
  subject: string,
  deps: Pick<ChainDeps, 'cache' | 'logger'>,
): Promise<ProviderResult | null> {
  try {
    const cached = await deps.cache.get(provider.name, kind, subject);
    if (cached) return cached;
    const result = await provider.lookup(subject, kind);
    if (result) await deps.cache.put(result, cacheTtlSeconds(result.level));
    return result;
  } catch (error) {
    deps.logger.warn(
      { provider: provider.name, err: { message: error instanceof Error ? error.message : 'unknown' } },
      'intel provider failed, continuing without it',
    );
    return null;
  }
}

/**
 * The lookup chain for one URL (spec §4), cheapest first. The bot has already checked the
 * blocklist, allowlist and local heuristics; this adds redirects, the URLhaus feed and domain age.
 * VirusTotal is not in here: it runs from its own rate-limited queue.
 */
export async function resolveUrl(subject: string, heuristicScore: number, deps: ChainDeps): Promise<Resolution> {
  const start = normalizeUrl(subject);
  if (!start) return { summary: summarizeIntel([]), results: [], finalUrl: subject };

  const results: ProviderResult[] = [];
  const targets: NormalizedUrl[] = [start];

  if (shouldExpand(start, heuristicScore)) {
    const redirect = await ask(deps.redirects, 'url', start.url, deps);
    if (redirect) {
      results.push(redirect);
      const final = typeof redirect.details.finalUrl === 'string' ? normalizeUrl(redirect.details.finalUrl) : null;
      if (final && final.url !== start.url) {
        targets.push(final);
        // The destination gets the same local checks as the link itself.
        const local = isKnownSafe(final) ? null : assessUrl(final);
        if (local && local.score > 0) {
          results.push({
            provider: 'redirect-target',
            kind: 'url',
            subject: final.url,
            level: 'unknown',
            weight: local.score,
            reasons: [`Leads to ${defang(final.host)}`, ...local.reasons],
            details: {},
          });
        }
      }
    }
  }

  const lookups: Promise<ProviderResult | null>[] = [];
  for (const target of targets) {
    lookups.push(ask(deps.urlhaus, 'url', target.url, deps));
    if (target.domain && !target.isIp && !isKnownSafe(target)) lookups.push(ask(deps.rdap, 'domain', target.domain, deps));
  }
  for (const result of await Promise.all(lookups)) if (result) results.push(result);

  return { summary: summarizeIntel(results), results, finalUrl: targets.at(-1)!.url };
}
