import { vi } from 'vitest';
import type { IntelKind, IntelProvider, ProviderResult } from '@equinox/core';
import type { ResultCache } from './chain.js';

/** Test-only fakes for the worker. Excluded from the build. */

export function silentLogger() {
  return { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn(), fatal: vi.fn() };
}

export class MemoryCache implements ResultCache {
  readonly entries = new Map<string, ProviderResult>();

  get(provider: string, kind: IntelKind, subject: string) {
    return Promise.resolve(this.entries.get(`${provider}|${kind}|${subject}`) ?? null);
  }

  put(result: ProviderResult) {
    this.entries.set(`${result.provider}|${result.kind}|${result.subject}`, result);
    return Promise.resolve();
  }
}

/** A provider whose answers are set per subject. Counts calls; can be made to fail. */
export class FakeProvider implements IntelProvider {
  readonly answers = new Map<string, Partial<ProviderResult>>();
  calls = 0;
  down = false;

  constructor(
    readonly name: string,
    readonly supports: readonly IntelKind[],
  ) {}

  lookup(subject: string, kind: IntelKind): Promise<ProviderResult | null> {
    this.calls++;
    if (this.down) return Promise.reject(new Error(`${this.name} is down`));
    return Promise.resolve({
      provider: this.name,
      kind,
      subject,
      level: 'unknown',
      weight: 0,
      reasons: [],
      details: {},
      ...this.answers.get(subject),
    });
  }
}
