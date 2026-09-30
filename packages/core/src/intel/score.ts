import { combineWeights, THRESHOLDS } from '../verdict.js';
import type { VerdictLevel } from '../types.js';
import type { IntelSummary, ProviderResult } from './types.js';

/** How long a result may be reused (spec §4): malicious for 30 days, everything else for 24 hours. */
export function cacheTtlSeconds(level: VerdictLevel | 'unknown'): number {
  return level === 'malicious' ? 30 * 24 * 3600 : 24 * 3600;
}

function levelFor(score: number): VerdictLevel {
  return score >= THRESHOLDS.malicious ? 'malicious' : score >= THRESHOLDS.suspicious ? 'suspicious' : 'clean';
}

/**
 * Combines provider results into one summary. Results only ever raise the score:
 * a clean answer from one source doesn't cancel a lookalike domain or another source's hit.
 * A source that says `malicious` makes the whole summary malicious.
 */
export function summarizeIntel(results: readonly ProviderResult[]): IntelSummary {
  const hits = results.filter((r) => r.weight > 0);
  let score = combineWeights(hits.map((r) => r.weight));
  if (hits.some((r) => r.level === 'malicious')) score = Math.max(score, THRESHOLDS.malicious);
  score = Number(score.toFixed(3));
  return {
    level: levelFor(score),
    score,
    sources: [...new Set(hits.map((r) => r.provider))],
    reasons: [...new Set(hits.flatMap((r) => r.reasons))].slice(0, 5),
  };
}
