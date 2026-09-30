import { findLinks, isKnownSafe, type LinkFinding } from '../links/index.js';
import type { VerdictLevel } from '../types.js';
import { combineWeights, THRESHOLDS } from '../verdict.js';
import { intelSummaryKey, intelSummarySchema, URLHAUS_URLS_KEY } from './contract.js';
import type { IntelSummary } from './types.js';

/** The two Redis calls cached intel needs. ioredis satisfies it; core stays free of Redis. */
export interface IntelCacheReader {
  get(key: string): Promise<string | null>;
  sismember(key: string, member: string): Promise<number>;
}

export const URLHAUS_HIT: IntelSummary = {
  level: 'malicious',
  score: 0.95,
  sources: ['urlhaus'],
  reasons: ['Listed by URLhaus as a malware link'],
};

/**
 * What is already known about a URL: the worker's cached summary, or a URLhaus listing.
 * `url` must be normalized (normalizeUrl().url), as signal subjects are. Junk in the cache reads as nothing.
 */
export async function readCachedIntel(redis: IntelCacheReader, url: string): Promise<IntelSummary | null> {
  const [cached, listed] = await Promise.all([redis.get(intelSummaryKey(url)), redis.sismember(URLHAUS_URLS_KEY, url)]);
  if (listed === 1) return URLHAUS_HIT;
  if (!cached) return null;
  try {
    const parsed = intelSummarySchema.safeParse(JSON.parse(cached));
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

/** Turns what someone typed into a link to check, the same way for Discord and the dashboard. */
export function parseLinkInput(input: string): LinkFinding | null {
  const trimmed = input.trim();
  if (trimmed.length === 0 || trimmed.length > 2048) return null;
  return findLinks(trimmed.includes('://') ? trimmed : `http://${trimmed}`)[0] ?? null;
}

export type IntelState =
  /** Allowlisted, blocklisted or a well-known site: intel isn't consulted. */
  | 'not_needed'
  /** Intel sources have answered (possibly with nothing found). */
  | 'checked'
  /** Nothing known yet; a lookup should be queued. */
  | 'pending';

export interface LinkCheck {
  /** Normalized URL. Defang before showing it. */
  url: string;
  level: VerdictLevel;
  score: number;
  reasons: string[];
  allowlisted: boolean;
  blocklisted: boolean;
  knownSafe: boolean;
  intel: IntelSummary | null;
  intelState: IntelState;
}

/**
 * The result of "check this link" for a mod: local heuristics plus whatever intel is cached,
 * combined exactly as the pipeline combines them (see decideVerdict).
 */
export function checkLink(
  finding: LinkFinding,
  known: { allowlisted: boolean; blocklisted: boolean; intel: IntelSummary | null },
): LinkCheck {
  const knownSafe = isKnownSafe(finding.normalized);
  const base = { url: finding.normalized.url, allowlisted: known.allowlisted, blocklisted: known.blocklisted, knownSafe };

  if (known.allowlisted) {
    return { ...base, level: 'clean', score: 0, reasons: ['Allowlisted in this server'], intel: null, intelState: 'not_needed' };
  }
  if (known.blocklisted) {
    return { ...base, level: 'malicious', score: 1, reasons: ['On the network blocklist', ...finding.reasons], intel: null, intelState: 'not_needed' };
  }

  const intel = knownSafe ? null : known.intel;
  let score = finding.score;
  if (intel && intel.score > 0) {
    score = combineWeights([score, intel.score]);
    if (intel.level === 'malicious') score = Math.max(score, THRESHOLDS.malicious);
  }
  score = Number(score.toFixed(3));
  const level: VerdictLevel = score >= THRESHOLDS.malicious ? 'malicious' : score >= THRESHOLDS.suspicious ? 'suspicious' : 'clean';
  return {
    ...base,
    level,
    score,
    reasons: [...finding.reasons, ...(intel && intel.score > 0 ? intel.reasons : [])],
    intel,
    intelState: knownSafe ? 'not_needed' : intel ? 'checked' : 'pending',
  };
}
