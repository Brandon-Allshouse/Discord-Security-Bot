import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { normalizeUrl } from '@equinox/core';
import { ask, RedirectProvider, resolveUrl, shouldExpand, type ChainDeps } from './chain.js';
import { isBlockedAddress } from './net/address-policy.js';
import { FakeProvider, MemoryCache, silentLogger } from './test-helpers.js';

const url = (raw: string) => normalizeUrl(raw)!;

describe('shouldExpand', () => {
  it('follows shorteners and links that already look off, and nothing else', () => {
    expect(shouldExpand(url('https://bit.ly/abc'), 0)).toBe(true);
    expect(shouldExpand(url('https://www.tinyurl.com/abc'), 0)).toBe(true);
    expect(shouldExpand(url('https://odd-site.test/'), 0.2)).toBe(true);
    expect(shouldExpand(url('https://odd-site.test/'), 0.19)).toBe(false);
    expect(shouldExpand(url('https://docs.example.com/reset?token=abc'), 0)).toBe(false);
  });

  it('never fetches raw IP links', () => {
    expect(shouldExpand(url('http://93.184.216.34/'), 0.9)).toBe(false);
  });
});

describe('ask', () => {
  const deps = () => ({ cache: new MemoryCache(), logger: silentLogger() });

  it('answers from the cache when it can, and caches fresh answers', async () => {
    const d = deps();
    const provider = new FakeProvider('rdap', ['domain']);
    provider.answers.set('a.test', { level: 'suspicious', weight: 0.4 });
    expect(await ask(provider, 'domain', 'a.test', d)).toMatchObject({ weight: 0.4 });
    expect(await ask(provider, 'domain', 'a.test', d)).toMatchObject({ weight: 0.4 });
    expect(provider.calls).toBe(1);
  });

  it('does not cache when a provider has no answer', async () => {
    const d = deps();
    const provider = { name: 'off', supports: ['url'] as const, lookup: () => Promise.resolve(null) };
    expect(await ask(provider, 'url', 'https://a.test/', d)).toBeNull();
    expect(d.cache.entries.size).toBe(0);
  });

  it('turns a failing provider into no answer, logs it, and caches nothing', async () => {
    const d = deps();
    const provider = new FakeProvider('rdap', ['domain']);
    provider.down = true;
    expect(await ask(provider, 'domain', 'a.test', d)).toBeNull();
    expect(d.logger.warn).toHaveBeenCalledOnce();
    expect(d.cache.entries.size).toBe(0);
  });
});

describe('resolveUrl', () => {
  function deps(): ChainDeps & { redirects: FakeProvider; urlhaus: FakeProvider; rdap: FakeProvider } {
    return {
      cache: new MemoryCache(),
      logger: silentLogger(),
      redirects: new FakeProvider('redirects', ['url']),
      urlhaus: new FakeProvider('urlhaus', ['url']),
      rdap: new FakeProvider('rdap', ['domain']),
    };
  }

  it('checks where a shortened link leads with the local heuristics, defanging the host', async () => {
    const d = deps();
    d.redirects.answers.set('https://bit.ly/x', { details: { finalUrl: 'https://dlscord-nitro.test/claim' } });
    const resolution = await resolveUrl('https://bit.ly/x', 0, d);
    const target = resolution.results.find((r) => r.provider === 'redirect-target');
    expect(target?.reasons[0]).toBe('Leads to dlscord-nitro[.]test');
    expect(target?.weight).toBeGreaterThan(0.5);
    expect(resolution.finalUrl).toBe('https://dlscord-nitro.test/claim');
    // Both the link and its destination are checked against the feed.
    expect(d.urlhaus.calls).toBe(2);
    expect(resolution.summary.level).not.toBe('clean');
  });

  it('adds nothing for destinations that are well-known safe sites, and skips their domain age', async () => {
    const d = deps();
    d.redirects.answers.set('https://bit.ly/y', { details: { finalUrl: 'https://github.com/org/repo' } });
    const resolution = await resolveUrl('https://bit.ly/y', 0, d);
    expect(resolution.results.some((r) => r.provider === 'redirect-target')).toBe(false);
    expect(resolution.summary.score).toBe(0);
    expect(d.rdap.calls).toBe(1); // bit.ly only, not github.com
  });

  it('does not follow ordinary links and skips domain age for IPs', async () => {
    const d = deps();
    await resolveUrl('https://plain.test/page', 0, d);
    await resolveUrl('http://93.184.216.34/', 0.9, d);
    expect(d.redirects.calls).toBe(0);
    expect(d.rdap.calls).toBe(1);
  });

  it('treats anything that is not an http(s) URL as clean without asking anyone', async () => {
    const d = deps();
    expect((await resolveUrl('javascript:alert(1)', 0.9, d)).summary.level).toBe('clean');
    expect(d.urlhaus.calls + d.rdap.calls + d.redirects.calls).toBe(0);
  });
});

describe('RedirectProvider', () => {
  let server: Server;
  let port: number;

  beforeAll(async () => {
    server = createServer((req, res) => {
      const path = req.url ?? '/';
      if (path === '/ok') res.writeHead(302, { location: `http://final.test:${port}/end` }).end();
      else if (path.startsWith('/loop')) res.writeHead(302, { location: `/loop${path.length}` }).end();
      else if (path === '/internal') res.writeHead(302, { location: 'http://169.254.169.254/latest/' }).end();
      else res.writeHead(200, { 'content-type': 'text/plain' }).end('end');
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    port = (server.address() as AddressInfo).port;
  });

  afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

  const provider = () =>
    new RedirectProvider({
      resolve: (host, cb) =>
        host.endsWith('.test') ? cb(null, [{ address: '127.0.0.1', family: 4 }]) : cb(new Error('ENOTFOUND'), []),
      isBlocked: (address) => address !== '127.0.0.1' && isBlockedAddress(address),
      allowedPorts: [port],
    });

  it('reports the destination, with no weight for an ordinary redirect', async () => {
    expect(await provider().lookup(`http://short.test:${port}/ok`, 'url')).toMatchObject({
      level: 'unknown',
      weight: 0,
      details: { finalUrl: `http://final.test:${port}/end`, hops: 1, stoppedBy: 'final' },
    });
  });

  it('counts long redirect chains and redirects into private networks against the link', async () => {
    expect(await provider().lookup(`http://short.test:${port}/loop`, 'url')).toMatchObject({
      level: 'suspicious',
      weight: 0.2,
      reasons: ['Goes through a long chain of redirects'],
    });
    expect(await provider().lookup(`http://short.test:${port}/internal`, 'url')).toMatchObject({
      level: 'suspicious',
      weight: 0.3,
      reasons: ['Redirects to a private or internal address'],
    });
  });

  it('throws when the link cannot be reached at all, so nothing gets cached', async () => {
    await expect(provider().lookup(`http://nowhere.example:${port}/`, 'url')).rejects.toThrow(/unreachable/);
  });

  it('ignores kinds it does not support', async () => {
    expect(await provider().lookup('example.com', 'domain')).toBeNull();
  });
});
