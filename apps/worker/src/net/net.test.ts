import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { isBlockedAddress, isBlockedHostname } from './address-policy.js';
import { expandRedirects, metaRefreshTarget, type Resolver, type SafeFetchOptions } from './safe-fetch.js';

describe('isBlockedAddress', () => {
  it.each([
    '127.0.0.1',
    '10.1.2.3',
    '172.16.0.1',
    '172.31.255.255',
    '192.168.1.1',
    '169.254.169.254', // AWS/GCP/Azure metadata
    '100.64.0.1',
    '0.0.0.0',
    '224.0.0.1',
    '255.255.255.255',
    '::1',
    '::',
    'fe80::1',
    'fd00:ec2::254', // AWS metadata over IPv6
    'fc00::1',
    '::ffff:127.0.0.1',
    '::ffff:7f00:1',
    '::ffff:169.254.169.254',
    '64:ff9b::a9fe:a9fe', // NAT64 wrapping 169.254.169.254
    '[::1]',
    'not-an-ip',
  ])('blocks %s', (address) => {
    expect(isBlockedAddress(address)).toBe(true);
  });

  it.each(['1.1.1.1', '8.8.8.8', '172.32.0.1', '2606:4700:4700::1111', '::ffff:1.1.1.1'])('allows %s', (address) => {
    expect(isBlockedAddress(address)).toBe(false);
  });

  it('blocks internal host names before DNS', () => {
    for (const host of ['localhost', 'foo.localhost', 'printer.local', 'metadata.google.internal', 'router.lan', 'intranet']) {
      expect(isBlockedHostname(host), host).toBe(true);
    }
    expect(isBlockedHostname('example.com')).toBe(false);
  });
});

describe('metaRefreshTarget', () => {
  it('finds meta refresh redirects in either attribute order', () => {
    expect(metaRefreshTarget('<meta http-equiv="refresh" content="0; url=https://a.test/x?a=1&amp;b=2">')).toBe(
      'https://a.test/x?a=1&b=2',
    );
    expect(metaRefreshTarget("<META CONTENT='3;URL=/next' HTTP-EQUIV='Refresh'>")).toBe('/next');
    expect(metaRefreshTarget('<meta name="description" content="url=https://nope.test">')).toBeNull();
  });
});

/*
 * A local server stands in for the internet. Test names resolve to 127.0.0.1 through a fake
 * resolver, and the policy lets only that one loopback address through, so these tests
 * exercise the real code path without touching the network.
 */
describe('expandRedirects', () => {
  let server: Server;
  let port: number;
  let requests: { url: string; cookie: string | undefined; auth: string | undefined }[] = [];

  beforeAll(async () => {
    server = createServer((req, res) => {
      requests.push({ url: req.url ?? '', cookie: req.headers.cookie, auth: req.headers.authorization });
      const url = new URL(req.url ?? '/', 'http://local');
      const to = url.searchParams.get('to');
      if (url.pathname === '/redirect' && to) {
        res.writeHead(302, { location: to, 'set-cookie': 'session=abc' }).end();
      } else if (url.pathname === '/loop') {
        res.writeHead(301, { location: `/loop?n=${Number(url.searchParams.get('n') ?? 0) + 1}` }).end();
      } else if (url.pathname === '/meta') {
        res.writeHead(200, { 'content-type': 'text/html' }).end(`<meta http-equiv="refresh" content="0;url=${to}">`);
      } else if (url.pathname === '/slow') {
        setTimeout(() => res.writeHead(200).end('late'), 3000);
      } else if (url.pathname === '/huge') {
        res.writeHead(200, { 'content-type': 'text/html' });
        res.write('x'.repeat(200_000));
        res.end(`<meta http-equiv="refresh" content="0;url=https://hidden.test/">`);
      } else {
        res.writeHead(200, { 'content-type': 'text/plain' }).end('final');
      }
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    port = (server.address() as AddressInfo).port;
  });

  afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

  const resolveTo =
    (map: Record<string, string>): Resolver =>
    (hostname, callback) => {
      const address = map[hostname];
      if (!address) return callback(new Error('ENOTFOUND'), []);
      callback(null, [{ address, family: address.includes(':') ? 6 : 4 }]);
    };

  const options = (overrides: Partial<SafeFetchOptions> = {}): SafeFetchOptions => ({
    resolve: resolveTo({ 'short.test': '127.0.0.1', 'final.test': '127.0.0.1', 'evil.test': '10.0.0.5' }),
    // The real policy, except the local test server's own address.
    isBlocked: (address) => address !== '127.0.0.1' && isBlockedAddress(address),
    allowedPorts: [port],
    ...overrides,
  });
  const at = (host: string, path: string) => `http://${host}:${port}${path}`;

  it('follows redirects to the final URL without sending or keeping cookies', async () => {
    requests = [];
    const final = at('final.test', '/landing');
    const result = await expandRedirects(at('short.test', `/redirect?to=${encodeURIComponent(final)}`), options());
    expect(result).toEqual({ hops: [at('short.test', `/redirect?to=${encodeURIComponent(final)}`), final], finalUrl: final, stoppedBy: 'final' });
    expect(requests.every((r) => r.cookie === undefined && r.auth === undefined)).toBe(true);
  });

  it('follows meta refresh redirects', async () => {
    const final = at('final.test', '/done');
    const result = await expandRedirects(at('short.test', `/meta?to=${encodeURIComponent(final)}`), options());
    expect(result.finalUrl).toBe(final);
  });

  it('stops after 5 hops', async () => {
    requests = [];
    const result = await expandRedirects(at('short.test', '/loop'), options());
    expect(result.stoppedBy).toBe('too_many_hops');
    expect(requests).toHaveLength(5);
    expect(result.hops).toHaveLength(6);
  });

  it('refuses a redirect into a private network, after DNS', async () => {
    requests = [];
    const target = at('evil.test', '/admin');
    const result = await expandRedirects(at('short.test', `/redirect?to=${encodeURIComponent(target)}`), options());
    expect(result).toMatchObject({ stoppedBy: 'blocked', finalUrl: target });
    expect(requests).toHaveLength(1);
  });

  it('refuses redirects to metadata IPs, internal names, other schemes and ports', async () => {
    for (const target of [
      'http://169.254.169.254/latest/meta-data/',
      'http://[::ffff:169.254.169.254]/',
      `http://localhost:${port}/`,
      'file:///etc/passwd',
      `http://final.test:${port + 1}/`,
    ]) {
      const result = await expandRedirects(at('short.test', `/redirect?to=${encodeURIComponent(target)}`), options());
      expect(result.stoppedBy, target).toBe('blocked');
    }
  });

  it('refuses a host that resolves to any private address, even alongside a public one', async () => {
    const mixed: Resolver = (_host, callback) =>
      callback(null, [
        { address: '93.184.216.34', family: 4 },
        { address: '127.0.0.1', family: 4 },
      ]);
    const result = await expandRedirects(at('short.test', '/x'), { ...options(), resolve: mixed, isBlocked: isBlockedAddress });
    expect(result.stoppedBy).toBe('blocked');
  });

  it('catches loopback written in odd ways (decimal, hex, short forms)', async () => {
    for (const host of ['2130706433', '0x7f.1', '0177.0.0.1', '127.1']) {
      const result = await expandRedirects(`http://${host}:${port}/`, { allowedPorts: [port] });
      expect(result.stoppedBy, host).toBe('blocked');
    }
  });

  it('stops with an error when a name does not resolve or a redirect is garbage', async () => {
    expect((await expandRedirects(at('missing.test', '/'), options())).stoppedBy).toBe('error');
    const garbage = await expandRedirects(at('short.test', `/redirect?to=${encodeURIComponent('http://[not-an-ip')}`), options());
    expect(garbage.stoppedBy).toBe('error');
  });

  it('uses the real policy by default: loopback is off limits', async () => {
    const result = await expandRedirects(`http://127.0.0.1:${port}/`, { allowedPorts: [port] });
    expect(result.stoppedBy).toBe('blocked');
  });

  it('gives up after the time limit', async () => {
    const result = await expandRedirects(at('short.test', '/slow'), options({ limits: { timeoutMs: 300 } }));
    expect(result.stoppedBy).toBe('timeout');
  });

  it('reads at most the byte cap', async () => {
    const result = await expandRedirects(at('short.test', '/huge'), options({ limits: { maxBytes: 100_000 } }));
    expect(result).toMatchObject({ stoppedBy: 'final', hops: [at('short.test', '/huge')] });
  });
});
