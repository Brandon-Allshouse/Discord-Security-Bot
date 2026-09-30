import { z } from 'zod';
import type { IntelKind, IntelProvider, ProviderResult } from '@equinox/core';
import { getJson, HttpError, type FetchLike } from '../net/http.js';

const BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';
const BOOTSTRAP_TTL_MS = 24 * 3600 * 1000;

const bootstrapSchema = z.object({
  services: z.array(z.tuple([z.array(z.string()), z.array(z.string())])),
});

const domainSchema = z.object({
  events: z.array(z.object({ eventAction: z.string(), eventDate: z.string() })).optional(),
});

/** Newly registered domains are a classic sign of a throwaway scam site. */
const AGE_WEIGHTS = [
  { maxDays: 7, weight: 0.4 },
  { maxDays: 30, weight: 0.2 },
] as const;

/**
 * Domain age from RDAP, the registries' own structured WHOIS. The IANA bootstrap file
 * says which registry server answers for each TLD.
 */
export class RdapProvider implements IntelProvider {
  readonly name = 'rdap';
  readonly supports = ['domain'] as const;
  private bootstrap: { servers: Map<string, string>; fetchedAt: number } | null = null;

  constructor(
    private readonly options: { fetch?: FetchLike; now?: () => Date } = {},
  ) {}

  async lookup(domain: string, kind: IntelKind): Promise<ProviderResult | null> {
    if (kind !== 'domain') return null;
    const base: ProviderResult = { provider: this.name, kind, subject: domain, level: 'unknown', weight: 0, reasons: [], details: {} };

    const server = await this.serverFor(domain);
    if (!server) return base;

    let body: unknown;
    try {
      body = await getJson(`${server.replace(/\/?$/, '/')}domain/${encodeURIComponent(domain)}`, {
        headers: { accept: 'application/rdap+json' },
        ...(this.options.fetch ? { fetch: this.options.fetch } : {}),
      });
    } catch (error) {
      // Not found is an answer (the domain isn't registered, or the registry won't say), not an outage.
      if (error instanceof HttpError && error.status === 404) return base;
      throw error;
    }

    const parsed = domainSchema.safeParse(body);
    const registered = parsed.success
      ? parsed.data.events?.find((e) => e.eventAction === 'registration')?.eventDate
      : undefined;
    const registeredAt = registered ? new Date(registered) : null;
    if (!registeredAt || Number.isNaN(registeredAt.getTime())) return base;

    const now = this.options.now?.() ?? new Date();
    const ageDays = Math.max(0, Math.floor((now.getTime() - registeredAt.getTime()) / 86_400_000));
    const details = { registeredAt: registeredAt.toISOString(), ageDays };
    const band = AGE_WEIGHTS.find((b) => ageDays < b.maxDays);
    if (!band) return { ...base, level: 'clean', details };
    const when = ageDays === 0 ? 'today' : ageDays === 1 ? '1 day ago' : `${ageDays} days ago`;
    return { ...base, level: 'suspicious', weight: band.weight, reasons: [`Domain was registered ${when}`], details };
  }

  private async serverFor(domain: string): Promise<string | null> {
    const now = Date.now();
    if (!this.bootstrap || now - this.bootstrap.fetchedAt > BOOTSTRAP_TTL_MS) {
      const body = bootstrapSchema.parse(
        await getJson(BOOTSTRAP_URL, this.options.fetch ? { fetch: this.options.fetch } : {}),
      );
      const servers = new Map<string, string>();
      for (const [tlds, urls] of body.services) {
        const url = urls.find((u) => u.startsWith('https://')) ?? urls[0];
        if (url) for (const tld of tlds) servers.set(tld.toLowerCase(), url);
      }
      this.bootstrap = { servers, fetchedAt: now };
    }
    // Longest match first, so "co.uk" style entries win over "uk".
    const labels = domain.toLowerCase().split('.');
    for (let i = 1; i < labels.length; i++) {
      const server = this.bootstrap.servers.get(labels.slice(i).join('.'));
      if (server) return server;
    }
    return null;
  }
}
