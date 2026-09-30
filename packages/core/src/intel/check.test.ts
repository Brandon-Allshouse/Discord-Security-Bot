import { describe, expect, it } from 'vitest';
import { createFakeDeps, makeGuild, makeSignal } from '../testing.js';
import { processSignal, reevaluateSignal } from '../pipeline.js';
import { checkLink, intelStatusSchema, intelSummaryKey, parseLinkInput, readCachedIntel, URLHAUS_HIT, URLHAUS_URLS_KEY, type IntelCacheReader } from './index.js';

function reader(values: Record<string, string>, members: string[] = []): IntelCacheReader {
  return {
    get: (key) => Promise.resolve(values[key] ?? null),
    sismember: (key, member) => Promise.resolve(key === URLHAUS_URLS_KEY && members.includes(member) ? 1 : 0),
  };
}

describe('readCachedIntel', () => {
  const url = 'https://a.test/';

  it('returns the cached summary, prefers a URLhaus listing, and nothing when unknown', async () => {
    const summary = { level: 'suspicious', score: 0.6, sources: ['rdap'], reasons: ['New'] };
    expect(await readCachedIntel(reader({}), url)).toBeNull();
    expect(await readCachedIntel(reader({ [intelSummaryKey(url)]: JSON.stringify(summary) }), url)).toEqual(summary);
    expect(await readCachedIntel(reader({ [intelSummaryKey(url)]: JSON.stringify(summary) }, [url]), url)).toEqual(URLHAUS_HIT);
  });

  it('reads junk as nothing instead of throwing', async () => {
    expect(await readCachedIntel(reader({ [intelSummaryKey(url)]: 'not json' }), url)).toBeNull();
    expect(await readCachedIntel(reader({ [intelSummaryKey(url)]: '{"level":"evil"}' }), url)).toBeNull();
  });
});

describe('parseLinkInput', () => {
  it('accepts links with or without a scheme and normalizes them', () => {
    expect(parseLinkInput('  https://Example.com/a?utm_source=x ')?.normalized.url).toBe('https://example.com/a');
    expect(parseLinkInput('example.com/page')?.normalized.url).toBe('http://example.com/page');
  });

  it('rejects empty, oversized and non-link input', () => {
    expect(parseLinkInput('')).toBeNull();
    expect(parseLinkInput('   ')).toBeNull();
    expect(parseLinkInput('!!!')).toBeNull();
    expect(parseLinkInput(`https://a.test/${'x'.repeat(2100)}`)).toBeNull();
    expect(parseLinkInput('javascript:alert(1)')).toBeNull();
  });
});

describe('checkLink', () => {
  const finding = (input: string) => parseLinkInput(input)!;
  const none = { allowlisted: false, blocklisted: false, intel: null };

  it('asks for a lookup when nothing is known', () => {
    expect(checkLink(finding('https://unknown.test/'), none)).toMatchObject({ level: 'clean', intelState: 'pending', score: 0 });
  });

  it('combines cached intel with the local score like the pipeline does', () => {
    const result = checkLink(finding('https://unknown.test/'), { ...none, intel: URLHAUS_HIT });
    expect(result).toMatchObject({ level: 'malicious', intelState: 'checked' });
    expect(result.reasons).toContain('Listed by URLhaus as a malware link');

    const weak = { level: 'clean' as const, score: 0.35, sources: ['rdap'], reasons: ['New domain'] };
    const lookalike = checkLink(finding('https://discord-events.test/'), { ...none, intel: weak });
    expect(lookalike.level).toBe('suspicious');
    expect(lookalike.reasons).toContain('New domain');
  });

  it('reports "checked" with no reasons when the sources found nothing', () => {
    const empty = { level: 'clean' as const, score: 0, sources: [], reasons: [] };
    expect(checkLink(finding('https://unknown.test/'), { ...none, intel: empty })).toMatchObject({ intelState: 'checked', reasons: [] });
  });

  it('lets the allowlist and blocklist decide without intel', () => {
    expect(checkLink(finding('https://dlscord.com/'), { ...none, allowlisted: true, intel: URLHAUS_HIT })).toMatchObject({
      level: 'clean',
      intelState: 'not_needed',
      intel: null,
    });
    expect(checkLink(finding('https://plain.test/'), { ...none, blocklisted: true })).toMatchObject({
      level: 'malicious',
      score: 1,
      intelState: 'not_needed',
    });
  });

  it('never involves outside sources for well-known sites', () => {
    expect(checkLink(finding('https://github.com/x'), { ...none, intel: URLHAUS_HIT })).toMatchObject({
      knownSafe: true,
      intelState: 'not_needed',
      level: 'clean',
    });
  });
});

describe('intel status', () => {
  it('only carries on/off and freshness, never budget numbers', () => {
    const status = { virustotal: true, urlhaus: { count: 5, syncedAt: new Date().toISOString() }, heartbeatAt: new Date().toISOString() };
    expect(intelStatusSchema.parse(status)).toEqual(status);
    expect(intelStatusSchema.parse({ ...status, budgetLeft: 3 })).not.toHaveProperty('budgetLeft');
    expect(intelStatusSchema.safeParse({ ...status, heartbeatAt: 'yesterday' }).success).toBe(false);
  });
});

describe('escalated alerts', () => {
  it('tells the executor which verdict the detection had before', async () => {
    const fake = createFakeDeps([makeGuild({ mode: 'protect' })]);
    const signal = makeSignal({ heuristicScore: 0.6 });
    await processSignal(signal, fake.deps);
    expect(fake.executed[0]).not.toHaveProperty('escalatedFrom');

    fake.intel.set(signal.subject, URLHAUS_HIT);
    await reevaluateSignal(signal, fake.deps);
    expect(fake.executed.slice(1)).toEqual([
      expect.objectContaining({ action: 'delete', escalatedFrom: 'suspicious' }),
      expect.objectContaining({ action: 'alert', escalatedFrom: 'suspicious' }),
    ]);
  });
});
