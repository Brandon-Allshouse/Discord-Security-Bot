import { BRAND } from './brand.js';
import type { IntelSummary } from './intel/types.js';
import type { Signal, Verdict, VerdictLevel } from './types.js';

export const THRESHOLDS = {
  malicious: 0.8,
  suspicious: 0.5,
} as const;

export interface VerdictContext {
  /** Subject is on this guild's allowlist. */
  allowlisted: boolean;
  /** Subject is a confirmed indicator on the network blocklist. */
  blocklisted: boolean;
  /** Cached threat-intel summary for the subject, if there is one. */
  intel?: IntelSummary | null;
}

/** Noisy-OR: independent weak signals add up, but never past 1. */
export function combineWeights(weights: readonly number[]): number {
  return 1 - weights.reduce((acc, w) => acc * (1 - w), 1);
}

const LEVEL_RANK: Record<VerdictLevel, number> = { clean: 0, suspicious: 1, malicious: 2 };

/** True when `a` is a more serious verdict level than `b`. */
export function isWorse(a: VerdictLevel, b: VerdictLevel): boolean {
  return LEVEL_RANK[a] > LEVEL_RANK[b];
}

/**
 * Pure verdict decision. Precedence: guild allowlist > network blocklist > heuristics and intel.
 * The allowlist wins so a guild can always override a false positive locally.
 */
export function decideVerdict(signal: Signal, context: VerdictContext): Verdict {
  if (context.allowlisted) {
    return { level: 'clean', score: 0, sources: ['allowlist'], reasons: ['Allowlisted by this server'] };
  }

  if (context.blocklisted) {
    return {
      level: 'malicious',
      score: 1,
      sources: ['blocklist'],
      reasons: [`Known threat on the ${BRAND.name} network`, ...signal.reasons],
    };
  }

  const intel = context.intel;
  let score = signal.heuristicScore;
  if (intel && intel.score > 0) {
    score = combineWeights([score, intel.score]);
    // A malicious answer from an intel source stands on its own.
    if (intel.level === 'malicious') score = Math.max(score, THRESHOLDS.malicious);
    score = Number(score.toFixed(3));
  }
  const level = score >= THRESHOLDS.malicious ? 'malicious' : score >= THRESHOLDS.suspicious ? 'suspicious' : 'clean';
  const fromIntel = intel && intel.score > 0;
  return {
    level,
    score,
    sources: fromIntel ? ['heuristic', ...intel.sources] : ['heuristic'],
    reasons: fromIntel ? [...signal.reasons, ...intel.reasons].slice(0, 10) : [...signal.reasons],
  };
}
