import { describe, expect, it } from 'vitest';
import { createFakeDeps, makeGuild, makeSignal } from '../testing.js';
import { processSignal, reevaluateSignal } from '../pipeline.js';
import { isKnownSafe, normalizeUrl } from '../links/index.js';
import { combineWeights, decideVerdict, isWorse } from '../verdict.js';
import {
  cacheTtlSeconds,
  intelResolvedSchema,
  intelSummaryKey,
  intelWaitersKey,
  subjectId,
  summarizeIntel,
  type IntelSummary,
  type ProviderResult,
} from './index.js';

const result = (overrides: Partial<ProviderResult>): ProviderResult => ({
  provider: 'test',
  kind: 'url',
  subject: 'https://example.test/',
  level: 'unknown',
  weight: 0,
  reasons: [],
  details: {},
  ...overrides,
});

const MALICIOUS: IntelSummary = { level: 'malicious', score: 0.95, sources: ['urlhaus'], reasons: ['Listed by URLhaus'] };

describe('summarizeIntel', () => {
  it('is clean with no hits', () => {
    expect(summarizeIntel([])).toEqual({ level: 'clean', score: 0, sources: [], reasons: [] });
    expect(summarizeIntel([result({ level: 'clean' }), result({ level: 'unknown' })]).level).toBe('clean');
  });

  it('keeps a single weak signal below suspicious', () => {
    const summary = summarizeIntel([result({ provider: 'rdap', level: 'suspicious', weight: 0.35, reasons: ['New domain'] })]);
    expect(summary).toEqual({ level: 'clean', score: 0.35, sources: ['rdap'], reasons: ['New domain'] });
  });

  it('adds weak signals up and lets one malicious source decide', () => {
    expect(summarizeIntel([result({ weight: 0.35 }), result({ weight: 0.3 })]).level).toBe('suspicious');
    const summary = summarizeIntel([
      result({ provider: 'virustotal', level: 'malicious', weight: 0.6 }),
      result({ provider: 'rdap', level: 'clean' }),
    ]);
    expect(summary.level).toBe('malicious');
    expect(summary.sources).toEqual(['virustotal']);
  });

  it('caches malicious results for 30 days and everything else for a day', () => {
    expect(cacheTtlSeconds('malicious')).toBe(30 * 24 * 3600);
    expect(cacheTtlSeconds('clean')).toBe(24 * 3600);
    expect(cacheTtlSeconds('unknown')).toBe(24 * 3600);
  });
});

describe('verdict helpers', () => {
  it('orders verdict levels', () => {
    expect(isWorse('malicious', 'suspicious')).toBe(true);
    expect(isWorse('suspicious', 'clean')).toBe(true);
    expect(isWorse('suspicious', 'suspicious')).toBe(false);
    expect(isWorse('clean', 'malicious')).toBe(false);
  });

  it('adds weak signals without ever passing 1', () => {
    expect(combineWeights([])).toBe(0);
    expect(combineWeights([0.5, 0.5])).toBeCloseTo(0.75);
    expect(combineWeights([1, 0.3])).toBe(1);
  });

  it('knows the brands\' own domains and popular sites, including their subdomains', () => {
    for (const safe of ['https://discord.com/x', 'https://cdn.discordapp.com/a', 'https://gist.github.com/', 'https://store.steampowered.com/']) {
      expect(isKnownSafe(normalizeUrl(safe)!), safe).toBe(true);
    }
    for (const other of ['https://dlscord.com/', 'https://discord.com.evil.test/', 'https://github.com.evil.test/']) {
      expect(isKnownSafe(normalizeUrl(other)!), other).toBe(false);
    }
  });
});

describe('decideVerdict with intel', () => {
  it('combines intel with the local score but never overrides the allowlist', () => {
    const signal = makeSignal({ heuristicScore: 0.45, reasons: ['Uses the Discord name'] });
    const weak: IntelSummary = { level: 'clean', score: 0.35, sources: ['rdap'], reasons: ['Registered 2 days ago'] };
    const verdict = decideVerdict(signal, { allowlisted: false, blocklisted: false, intel: weak });
    expect(verdict.level).toBe('suspicious');
    expect(verdict.sources).toEqual(['heuristic', 'rdap']);
    expect(verdict.reasons).toEqual(['Uses the Discord name', 'Registered 2 days ago']);

    expect(decideVerdict(signal, { allowlisted: true, blocklisted: false, intel: MALICIOUS }).level).toBe('clean');
  });

  it('treats a malicious intel answer as malicious on its own', () => {
    const verdict = decideVerdict(makeSignal({ heuristicScore: 0 }), { allowlisted: false, blocklisted: false, intel: MALICIOUS });
    expect(verdict.level).toBe('malicious');
  });

  it('ignores intel that found nothing', () => {
    const clean: IntelSummary = { level: 'clean', score: 0, sources: [], reasons: [] };
    const verdict = decideVerdict(makeSignal({ heuristicScore: 0.2 }), { allowlisted: false, blocklisted: false, intel: clean });
    expect(verdict).toMatchObject({ level: 'clean', score: 0.2, sources: ['heuristic'] });
  });
});

describe('pipeline and intel', () => {
  it('asks for a lookup only when nothing is known yet', async () => {
    const fake = createFakeDeps([makeGuild()]);
    const unknown = await processSignal(makeSignal({ heuristicScore: 0.1 }), fake.deps);
    expect(unknown).toMatchObject({ status: 'clean', needsIntel: true });

    const cachedSignal = makeSignal({ heuristicScore: 0.1, subject: 'https://cached.test/' });
    fake.intel.set(cachedSignal.subject, { level: 'clean', score: 0, sources: [], reasons: [] });
    expect(await processSignal(cachedSignal, fake.deps)).toMatchObject({ status: 'clean', needsIntel: false });

    const blocked = makeSignal({ heuristicScore: 0.1, subject: 'https://blocked.test/' });
    fake.blocklist.add(blocked.subject);
    expect(await processSignal(blocked, fake.deps)).toMatchObject({ status: 'detected', needsIntel: false });
  });

  it('uses cached intel in the first verdict', async () => {
    const fake = createFakeDeps([makeGuild({ mode: 'protect' })]);
    const signal = makeSignal({ heuristicScore: 0 });
    fake.intel.set(signal.subject, MALICIOUS);
    const result = await processSignal(signal, fake.deps);
    expect(result).toMatchObject({ status: 'detected', verdict: { level: 'malicious' } });
    expect(fake.executed.map((e) => e.action)).toEqual(['delete', 'alert']);
  });

  it('falls back to local information when the intel cache is down', async () => {
    const fake = createFakeDeps([makeGuild()]);
    fake.intelDown.value = true;
    const result = await processSignal(makeSignal({ heuristicScore: 0.9 }), fake.deps);
    expect(result).toMatchObject({ status: 'detected', verdict: { level: 'malicious', sources: ['heuristic'] } });
  });

  it('does not ask for lookups without an intel port', async () => {
    const fake = createFakeDeps([makeGuild()]);
    const deps = { ...fake.deps };
    delete deps.intel;
    expect(await processSignal(makeSignal({ heuristicScore: 0.1 }), deps)).toMatchObject({ needsIntel: false });
  });
});

describe('reevaluateSignal', () => {
  it('creates a detection when late intel turns a clean link bad', async () => {
    const fake = createFakeDeps([makeGuild({ mode: 'protect' })]);
    const signal = makeSignal({ heuristicScore: 0.1 });
    expect((await processSignal(signal, fake.deps)).status).toBe('clean');

    fake.intel.set(signal.subject, MALICIOUS);
    const result = await reevaluateSignal({ ...signal, id: crypto.randomUUID() }, fake.deps);
    expect(result.status).toBe('detected');
    expect(fake.executed.map((e) => e.action)).toEqual(['delete', 'alert']);
  });

  it('escalates an open detection, running only what the new verdict adds', async () => {
    const fake = createFakeDeps([makeGuild({ mode: 'protect' })]);
    const signal = makeSignal({ heuristicScore: 0.6 });
    const first = await processSignal(signal, fake.deps);
    expect(first).toMatchObject({ status: 'detected', verdict: { level: 'suspicious' } });
    expect(fake.executed.map((e) => e.action)).toEqual(['alert']);

    fake.intel.set(signal.subject, MALICIOUS);
    const result = await reevaluateSignal(signal, fake.deps);
    expect(result.status).toBe('escalated');
    expect(fake.executed.map((e) => e.action)).toEqual(['alert', 'delete', 'alert']);

    const stored = fake.detections.get(first.status === 'detected' ? first.detection.id : '')!;
    expect(stored.verdict.level).toBe('malicious');
    expect(stored.actionsTaken.map((o) => o.action)).toEqual(['alert', 'delete', 'alert']);
    expect(fake.audit.map((a) => a.action)).toContain('detection.escalated');
    expect(fake.detections.size).toBe(1);
  });

  it('leaves detections alone once mods have handled them, or when nothing got worse', async () => {
    const fake = createFakeDeps([makeGuild({ mode: 'protect' })]);
    const signal = makeSignal({ heuristicScore: 0.6 });
    const first = await processSignal(signal, fake.deps);
    const id = first.status === 'detected' ? first.detection.id : '';

    expect((await reevaluateSignal(signal, fake.deps)).status).toBe('unchanged');

    fake.detections.get(id)!.status = 'false_positive';
    fake.intel.set(signal.subject, MALICIOUS);
    expect((await reevaluateSignal(signal, fake.deps)).status).toBe('unchanged');
    expect(fake.executed.map((e) => e.action)).toEqual(['alert']);
  });

  it('ignores servers that are not tenants', async () => {
    const fake = createFakeDeps([]);
    expect(await reevaluateSignal(makeSignal(), fake.deps)).toEqual({ status: 'ignored', reason: 'guild_not_registered' });
  });

  it('ignores signals that are not tied to a message', async () => {
    const fake = createFakeDeps([makeGuild()]);
    const signal: Partial<ReturnType<typeof makeSignal>> = makeSignal();
    delete signal.messageId;
    expect(await reevaluateSignal(signal, fake.deps)).toEqual({ status: 'ignored', reason: 'no_message' });
  });
});

describe('contract', () => {
  it('derives stable, fixed-length keys from the URL', () => {
    expect(subjectId('https://a.test/')).toHaveLength(32);
    expect(intelSummaryKey('https://a.test/')).toBe(intelSummaryKey('https://a.test/'));
    expect(intelSummaryKey('https://a.test/')).not.toBe(intelSummaryKey('https://b.test/'));
    expect(intelWaitersKey('https://a.test/')).not.toBe(intelSummaryKey('https://a.test/'));
    // The raw URL never appears in a key.
    expect(intelSummaryKey('https://a.test/secret?token=1')).not.toContain('secret');
  });

  it('rejects resolved messages with junk in them', () => {
    const waiter = {
      guildId: '100000000000000001',
      userId: '200000000000000001',
      channelId: '300000000000000001',
      messageId: '400000000000000001',
      heuristicScore: 0.2,
      reasons: [],
    };
    expect(intelResolvedSchema.safeParse({ subject: 'https://a.test/', summary: MALICIOUS, waiters: [waiter] }).success).toBe(true);
    expect(
      intelResolvedSchema.safeParse({ subject: 'https://a.test/', summary: MALICIOUS, waiters: [{ ...waiter, guildId: 'x' }] })
        .success,
    ).toBe(false);
  });
});
