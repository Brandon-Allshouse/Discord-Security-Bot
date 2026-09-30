import { BRAND } from './brand.js';
import type { Signal, Verdict } from './types.js';

export const THRESHOLDS = {
  malicious: 0.8,
  suspicious: 0.5,
} as const;

export interface VerdictContext {
  /** Subject is on this guild's allowlist. */
  allowlisted: boolean;
  /** Subject is a confirmed indicator on the network blocklist. */
  blocklisted: boolean;
}

/**
 * Pure verdict decision. Precedence: guild allowlist > network blocklist > heuristics.
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

  const score = signal.heuristicScore;
  const level = score >= THRESHOLDS.malicious ? 'malicious' : score >= THRESHOLDS.suspicious ? 'suspicious' : 'clean';
  return { level, score, sources: ['heuristic'], reasons: [...signal.reasons] };
}
