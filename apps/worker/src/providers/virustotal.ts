import { z } from 'zod';
import type { IntelKind, IntelProvider, ProviderResult } from '@equinox/core';
import { getJson, HttpError, type FetchLike } from '../net/http.js';

const API = 'https://www.virustotal.com/api/v3';

const reportSchema = z.object({
  data: z.object({
    attributes: z.object({
      last_analysis_stats: z.object({
        malicious: z.number().int().min(0),
        suspicious: z.number().int().min(0),
        harmless: z.number().int().min(0).default(0),
        undetected: z.number().int().min(0).default(0),
      }),
      last_analysis_date: z.number().optional(),
    }),
  }),
});

/** VirusTotal's URL identifier: the URL, base64url-encoded without padding. */
export function vtUrlId(url: string): string {
  return Buffer.from(url).toString('base64url');
}

/** VT refused the key. Retrying won't help, so the worker stops asking. */
export class VirusTotalAuthError extends Error {
  constructor() {
    super('VirusTotal rejected the API key');
    this.name = 'VirusTotalAuthError';
  }
}

/**
 * VirusTotal report lookups (spec §4). Lookups only: it never submits URLs or files,
 * because anything submitted becomes visible to other VirusTotal users.
 * One weighted source, not a final verdict: three or more engines is a strong signal.
 * Budgets and rate limits are enforced by the caller (see budget.ts), not here.
 */
export class VirusTotalProvider implements IntelProvider {
  readonly name = 'virustotal';
  readonly supports = ['url'] as const;
  readonly quota: { perMinute: number; perDay: number };

  constructor(
    private readonly apiKey: string,
    quota: { perMinute: number; perDay: number },
    private readonly options: { fetch?: FetchLike } = {},
  ) {
    this.quota = quota;
  }

  async lookup(subject: string, kind: IntelKind): Promise<ProviderResult | null> {
    if (kind !== 'url') return null;
    const base: ProviderResult = { provider: this.name, kind, subject, level: 'unknown', weight: 0, reasons: [], details: {} };

    let body: unknown;
    try {
      body = await getJson(`${API}/urls/${vtUrlId(subject)}`, {
        headers: { 'x-apikey': this.apiKey, accept: 'application/json' },
        timeoutMs: 10_000,
        ...(this.options.fetch ? { fetch: this.options.fetch } : {}),
      });
    } catch (error) {
      if (error instanceof HttpError && error.status === 404) return { ...base, details: { found: false } };
      if (error instanceof HttpError && (error.status === 401 || error.status === 403)) throw new VirusTotalAuthError();
      throw error;
    }

    const { last_analysis_stats: stats, last_analysis_date } = reportSchema.parse(body).data.attributes;
    const details = { found: true, ...stats, ...(last_analysis_date ? { analyzedAt: last_analysis_date } : {}) };
    const engines = (n: number) => `${n} VirusTotal engine${n === 1 ? '' : 's'}`;

    if (stats.malicious >= 3) {
      return { ...base, level: 'malicious', weight: 0.9, reasons: [`Flagged as malicious by ${engines(stats.malicious)}`], details };
    }
    if (stats.malicious > 0) {
      const weight = stats.malicious === 1 ? 0.3 : 0.45;
      return { ...base, level: 'suspicious', weight, reasons: [`Flagged as malicious by ${engines(stats.malicious)}`], details };
    }
    if (stats.suspicious >= 3) {
      return { ...base, level: 'suspicious', weight: 0.25, reasons: [`Flagged as suspicious by ${engines(stats.suspicious)}`], details };
    }
    return { ...base, level: 'clean', details };
  }
}
