import { describe, expect, it } from 'vitest';
import type { FetchLike } from '../net/http.js';
import { RdapProvider } from './rdap.js';
import { parseCsvLine, parseUrlhausCsv } from './urlhaus.js';
import { VirusTotalAuthError, VirusTotalProvider, vtUrlId } from './virustotal.js';

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });

/** A fetch that answers from a map of URL -> response factory, and records what it was asked. */
function fakeFetch(routes: Record<string, () => Response>) {
  const calls: { url: string; headers: Record<string, string> }[] = [];
  const fn: FetchLike = (url, init) => {
    calls.push({ url, headers: (init?.headers ?? {}) as Record<string, string> });
    const route = routes[url];
    return Promise.resolve(route ? route() : new Response('not found', { status: 404 }));
  };
  return { fn, calls };
}

describe('RdapProvider', () => {
  const bootstrap = {
    services: [
      [['com', 'net'], ['https://rdap.verisign.test/com/v1/']],
      [['co.uk', 'uk'], ['http://insecure.test/', 'https://rdap.nominet.test/']],
    ],
  };
  const now = () => new Date('2026-09-30T00:00:00Z');
  const domain = (date: string) => json({ events: [{ eventAction: 'registration', eventDate: date }] });

  it('flags very new domains, less so for a month, and not at all after that', async () => {
    const fake = fakeFetch({
      'https://data.iana.org/rdap/dns.json': () => json(bootstrap),
      'https://rdap.verisign.test/com/v1/domain/brand-new.com': () => domain('2026-09-28T00:00:00Z'),
      'https://rdap.verisign.test/com/v1/domain/recent.com': () => domain('2026-09-10T00:00:00Z'),
      'https://rdap.verisign.test/com/v1/domain/old.com': () => domain('2015-01-01T00:00:00Z'),
    });
    const rdap = new RdapProvider({ fetch: fake.fn, now });
    expect(await rdap.lookup('brand-new.com', 'domain')).toMatchObject({
      level: 'suspicious',
      weight: 0.4,
      reasons: ['Domain was registered 2 days ago'],
      details: { ageDays: 2 },
    });
    expect(await rdap.lookup('recent.com', 'domain')).toMatchObject({ level: 'suspicious', weight: 0.2 });
    expect(await rdap.lookup('old.com', 'domain')).toMatchObject({ level: 'clean', weight: 0 });
    // The bootstrap file is fetched once and reused.
    expect(fake.calls.filter((c) => c.url.includes('iana')).length).toBe(1);
  });

  it('prefers https servers and the longest matching suffix', async () => {
    const fake = fakeFetch({
      'https://data.iana.org/rdap/dns.json': () => json(bootstrap),
      'https://rdap.nominet.test/domain/shop.co.uk': () => domain('2026-09-29T00:00:00Z'),
    });
    expect(await new RdapProvider({ fetch: fake.fn, now }).lookup('shop.co.uk', 'domain')).toMatchObject({ weight: 0.4 });
  });

  it('answers unknown for TLDs without RDAP and for unregistered domains, but throws on outages', async () => {
    const fake = fakeFetch({
      'https://data.iana.org/rdap/dns.json': () => json(bootstrap),
      'https://rdap.verisign.test/com/v1/domain/down.com': () => new Response('oops', { status: 503 }),
    });
    const rdap = new RdapProvider({ fetch: fake.fn, now });
    expect(await rdap.lookup('example.zz', 'domain')).toMatchObject({ level: 'unknown' });
    expect(await rdap.lookup('missing.com', 'domain')).toMatchObject({ level: 'unknown' });
    await expect(rdap.lookup('down.com', 'domain')).rejects.toThrow(/503/);
    expect(await rdap.lookup('https://x.test/', 'url')).toBeNull();
  });
});

describe('URLhaus feed parsing', () => {
  it('parses quoted CSV fields', () => {
    expect(parseCsvLine('"1","2026-09-30","http://a.test/x,y","online"')).toEqual(['1', '2026-09-30', 'http://a.test/x,y', 'online']);
    expect(parseCsvLine('"a ""quoted"" b",c')).toEqual(['a "quoted" b', 'c']);
  });

  it('takes the URL column, normalizes it, and skips comments and junk', () => {
    const csv = [
      '################################################################',
      '# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter',
      '"3001","2026-09-30 10:00:00","http://Evil.test/payload.exe?utm_source=x","online","2026-09-30","malware_download","exe","https://urlhaus.abuse.ch/url/3001/","someone"',
      '"3002","2026-09-30 10:00:00","not a url","online","","","","",""',
      '"3003","2026-09-30 10:00:00","ftp://files.test/a","online","","","","",""',
      '',
    ].join('\r\n');
    expect(parseUrlhausCsv(csv)).toEqual(['http://evil.test/payload.exe']);
  });
});

describe('VirusTotalProvider', () => {
  const key = 'k'.repeat(64);
  const url = 'https://scam.test/login';
  const endpoint = `https://www.virustotal.com/api/v3/urls/${vtUrlId(url)}`;
  const report = (malicious: number, suspicious = 0) =>
    json({ data: { attributes: { last_analysis_stats: { malicious, suspicious, harmless: 60, undetected: 10 } } } });
  const provider = (response: () => Response) => {
    const fake = fakeFetch({ [endpoint]: response });
    return { vt: new VirusTotalProvider(key, { perMinute: 4, perDay: 500 }, { fetch: fake.fn }), fake };
  };

  it('uses the unpadded base64url URL id', () => {
    expect(vtUrlId('https://a.test/')).toBe('aHR0cHM6Ly9hLnRlc3Qv');
  });

  it('treats 3+ engines as malicious, 1-2 as a weaker signal, and none as clean', async () => {
    expect(await provider(() => report(5)).vt.lookup(url, 'url')).toMatchObject({
      level: 'malicious',
      weight: 0.9,
      reasons: ['Flagged as malicious by 5 VirusTotal engines'],
    });
    expect(await provider(() => report(1)).vt.lookup(url, 'url')).toMatchObject({ level: 'suspicious', weight: 0.3 });
    expect(await provider(() => report(2)).vt.lookup(url, 'url')).toMatchObject({ level: 'suspicious', weight: 0.45 });
    expect(await provider(() => report(0, 4)).vt.lookup(url, 'url')).toMatchObject({ level: 'suspicious', weight: 0.25 });
    expect(await provider(() => report(0)).vt.lookup(url, 'url')).toMatchObject({ level: 'clean', weight: 0 });
  });

  it('sends the key only as a header, and never submits anything', async () => {
    const { vt, fake } = provider(() => report(0));
    await vt.lookup(url, 'url');
    expect(fake.calls).toHaveLength(1);
    expect(fake.calls[0]!.url).not.toContain(key);
    expect(fake.calls[0]!.headers['x-apikey']).toBe(key);
  });

  it('answers unknown for URLs VirusTotal has never seen', async () => {
    expect(await provider(() => json({ error: {} }, 404)).vt.lookup(url, 'url')).toMatchObject({
      level: 'unknown',
      details: { found: false },
    });
  });

  it('reports a rejected key separately from outages', async () => {
    await expect(provider(() => json({}, 401)).vt.lookup(url, 'url')).rejects.toBeInstanceOf(VirusTotalAuthError);
    await expect(provider(() => json({}, 500)).vt.lookup(url, 'url')).rejects.toThrow(/500/);
    await expect(provider(() => json({ data: {} })).vt.lookup(url, 'url')).rejects.toThrow();
  });

  it('ignores kinds it does not support', async () => {
    const { vt, fake } = provider(() => report(0));
    expect(await vt.lookup('example.com', 'domain')).toBeNull();
    expect(fake.calls).toHaveLength(0);
  });
});
