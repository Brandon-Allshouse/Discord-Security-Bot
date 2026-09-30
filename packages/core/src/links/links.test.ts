import { describe, expect, it } from 'vitest';
import { THRESHOLDS } from '../verdict.js';
import { deobfuscate, extractUrls, MAX_URLS_PER_MESSAGE } from './extract.js';
import { LEGIT_MESSAGES, SCAM_MESSAGES } from './fixtures.js';
import { editDistance, foldHomoglyphs } from './heuristics.js';
import { findLinks } from './index.js';
import { domainCandidates, normalizeUrl } from './normalize.js';

const topScore = (text: string) => findLinks(text)[0]?.score ?? 0;

describe('fixture suite', () => {
  it('has at least 100 cases', () => {
    expect(SCAM_MESSAGES.length + LEGIT_MESSAGES.length).toBeGreaterThanOrEqual(100);
  });

  it.each(SCAM_MESSAGES)('flags scam: %s', (text) => {
    expect(topScore(text)).toBeGreaterThanOrEqual(THRESHOLDS.suspicious);
  });

  it.each(LEGIT_MESSAGES)('does not flag legit: %s', (text) => {
    expect(topScore(text)).toBeLessThan(THRESHOLDS.suspicious);
  });

  it('rates homoglyph lookalikes as malicious on their own', () => {
    for (const text of ['https://dlscord.com/', 'https://stearncommunity.com/', 'https://dіscord.com/']) {
      expect(topScore(text), text).toBeGreaterThanOrEqual(THRESHOLDS.malicious);
    }
  });

  it('scores fast enough to stay inside the 5 ms budget', () => {
    const corpus = [...SCAM_MESSAGES, ...LEGIT_MESSAGES];
    // Warm up first so JIT compilation isn't counted; shared CI runners are noisy enough already.
    for (let round = 0; round < 5; round++) {
      for (const text of corpus) findLinks(text);
    }
    // Best of three runs: a busy machine (parallel test suites, shared CI runners) can spoil one run,
    // but a real slowdown fails all three.
    const p95s: number[] = [];
    for (let run = 0; run < 3; run++) {
      const durations: number[] = [];
      for (let round = 0; round < 20; round++) {
        for (const text of corpus) {
          const start = performance.now();
          findLinks(text);
          durations.push(performance.now() - start);
        }
      }
      durations.sort((a, b) => a - b);
      p95s.push(durations[Math.floor(durations.length * 0.95)]!);
      if (p95s.at(-1)! < 5) break;
    }
    expect(Math.min(...p95s)).toBeLessThan(5);
  });
});

describe('extraction', () => {
  it('undoes common obfuscation', () => {
    expect(deobfuscate('hxxps://evil[.]com')).toBe('https://evil.com');
    expect(deobfuscate('evil(.)com')).toBe('evil.com');
    expect(deobfuscate('e​vil.com')).toBe('evil.com');
    expect(deobfuscate('evil . com')).toBe('evil.com');
  });

  it('pulls the real target out of markdown masked links', () => {
    expect(extractUrls('[discord.com](https://evil.example/x)')).toContain('https://evil.example/x');
  });

  it('caps the number of URLs per message', () => {
    const text = Array.from({ length: 50 }, (_, i) => `https://site${i}.com`).join(' ');
    expect(extractUrls(text)).toHaveLength(MAX_URLS_PER_MESSAGE);
  });

  it('ignores email addresses and file names', () => {
    expect(extractUrls('mail me at a@example.com, see notes.txt and app.js')).toEqual([]);
  });
});

describe('normalization', () => {
  it('lowercases, strips tracking params, fragments and credentials', () => {
    const n = normalizeUrl('HTTPS://User:Pass@Example.COM/Path?utm_source=x&id=1#frag');
    expect(n).toMatchObject({ url: 'https://example.com/Path?id=1', host: 'example.com', hadCredentials: true });
  });

  it('keeps both punycode and unicode forms of the host', () => {
    const n = normalizeUrl('https://dіscord.com/');
    expect(n?.host.startsWith('xn--')).toBe(true);
    expect(n?.unicodeHost).toBe('dіscord.com');
  });

  it('rejects non-http schemes', () => {
    expect(normalizeUrl('javascript:alert(1)')).toBeNull();
    expect(normalizeUrl('file:///etc/passwd')).toBeNull();
  });

  it('lists the host and its parents down to the registrable domain', () => {
    const n = normalizeUrl('https://a.b.example.co.uk/')!;
    expect(domainCandidates(n)).toEqual(['a.b.example.co.uk', 'b.example.co.uk', 'example.co.uk']);
  });
});

describe('string helpers', () => {
  it('folds homoglyphs', () => {
    expect(foldHomoglyphs('D1sc0rd')).toBe('discord');
    expect(foldHomoglyphs('dіscord')).toBe('discord');
    expect(foldHomoglyphs('stearncommunity')).toBe(foldHomoglyphs('steamcommunity'));
  });

  it('computes edit distance with transpositions', () => {
    expect(editDistance('discord', 'dicsord')).toBe(1);
    expect(editDistance('discord', 'discord')).toBe(0);
    expect(editDistance('a', 'abcdef', 2)).toBe(3);
    expect(editDistance('', 'ab')).toBe(2);
    expect(editDistance('steamcommunity', 'xxxxxxxxxxxxxx', 2)).toBe(3);
  });

  it('matches a plain full-matrix implementation exactly, up to the cap', () => {
    // The straightforward version: slow, but obviously right.
    const reference = (a: string, b: string): number => {
      const d = Array.from({ length: a.length + 1 }, (_, i) => Array.from({ length: b.length + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0)));
      for (let i = 1; i <= a.length; i++) {
        for (let j = 1; j <= b.length; j++) {
          const cost = a[i - 1] === b[j - 1] ? 0 : 1;
          d[i]![j] = Math.min(d[i - 1]![j]! + 1, d[i]![j - 1]! + 1, d[i - 1]![j - 1]! + cost);
          if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i]![j] = Math.min(d[i]![j]!, d[i - 2]![j - 2]! + 1);
        }
      }
      return d[a.length]![b.length]!;
    };
    // A small alphabet makes near-matches and transpositions common. Seeded, so failures reproduce.
    let seed = 42;
    const random = () => (seed = (seed * 1_103_515_245 + 12_345) % 2 ** 31) / 2 ** 31;
    const word = () => Array.from({ length: Math.floor(random() * 12) }, () => 'abcd'[Math.floor(random() * 4)]).join('');
    for (let n = 0; n < 5000; n++) {
      const [a, b, max] = [word(), word(), Math.floor(random() * 4)];
      expect(editDistance(a, b, max), `${a} / ${b} / ${max}`).toBe(Math.min(reference(a, b), max + 1));
    }
  });
});
