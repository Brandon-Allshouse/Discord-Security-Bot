import { describe, expect, it } from 'vitest';
import { makeSignal } from './testing.js';
import { decideVerdict, THRESHOLDS } from './verdict.js';

const none = { allowlisted: false, blocklisted: false };

describe('decideVerdict', () => {
  it.each([
    [0, 'clean'],
    [THRESHOLDS.suspicious - 0.01, 'clean'],
    [THRESHOLDS.suspicious, 'suspicious'],
    [THRESHOLDS.malicious - 0.01, 'suspicious'],
    [THRESHOLDS.malicious, 'malicious'],
    [1, 'malicious'],
  ] as const)('heuristic score %s -> %s', (score, level) => {
    expect(decideVerdict(makeSignal({ heuristicScore: score }), none).level).toBe(level);
  });

  it('blocklist makes a low-score signal malicious', () => {
    const verdict = decideVerdict(makeSignal({ heuristicScore: 0 }), { allowlisted: false, blocklisted: true });
    expect(verdict).toMatchObject({ level: 'malicious', score: 1, sources: ['blocklist'] });
  });

  it('guild allowlist overrides the network blocklist', () => {
    const verdict = decideVerdict(makeSignal({ heuristicScore: 1 }), { allowlisted: true, blocklisted: true });
    expect(verdict).toMatchObject({ level: 'clean', sources: ['allowlist'] });
  });
});
