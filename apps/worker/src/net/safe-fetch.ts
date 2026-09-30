import { lookup as dnsLookup, type LookupAddress } from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import { isIP, type LookupFunction } from 'node:net';
import { isBlockedAddress, isBlockedHostname } from './address-policy.js';

/**
 * Follows redirects on links posted in Discord, safely (spec §8):
 * - only http and https on the standard ports
 * - every address is checked at connect time, after DNS, on every hop, so DNS rebinding
 *   and redirects into private networks are refused
 * - at most 5 hops, 5 seconds in total, and at most 1 MB read from any response
 * - no cookies, no credentials, no connection reuse, and nothing is ever executed
 */

export interface FetchLimits {
  maxHops: number;
  timeoutMs: number;
  maxBytes: number;
}

export const FETCH_LIMITS: Readonly<FetchLimits> = { maxHops: 5, timeoutMs: 5000, maxBytes: 1024 * 1024 };
const USER_AGENT = 'Mozilla/5.0 (compatible; EquinoxLinkCheck/1.0)';

export type Resolver = (hostname: string, callback: (err: Error | null, addresses: LookupAddress[]) => void) => void;

export interface SafeFetchOptions {
  /** Test hooks. Production uses the real policy, real DNS and ports 80/443. */
  isBlocked?: (address: string) => boolean;
  resolve?: Resolver;
  allowedPorts?: readonly number[];
  limits?: Partial<FetchLimits>;
}

export class BlockedDestinationError extends Error {
  constructor(reason: string) {
    super(`blocked destination: ${reason}`);
    this.name = 'BlockedDestinationError';
  }
}

const systemResolve: Resolver = (hostname, callback) =>
  dnsLookup(hostname, { all: true, verbatim: true }, (err, addresses) => callback(err, addresses ?? []));

/** A DNS lookup for http.request that refuses if any answer is a blocked address. */
function guardedLookup(resolve: Resolver, isBlocked: (address: string) => boolean): LookupFunction {
  return (hostname, options, callback) => {
    resolve(hostname, (err, addresses) => {
      if (err) return callback(err, '', 0);
      // Refuse if ANY answer is private, so a record listing a public and a private address can't sneak through.
      if (addresses.length === 0 || addresses.some((a) => isBlocked(a.address))) {
        return callback(new BlockedDestinationError('resolves to a private or reserved address'), '', 0);
      }
      const usable = options.family ? addresses.filter((a) => a.family === options.family) : addresses;
      if (usable.length === 0) return callback(new BlockedDestinationError('no usable address'), '', 0);
      if (options.all) return (callback as unknown as (e: null, a: LookupAddress[]) => void)(null, usable);
      callback(null, usable[0]!.address, usable[0]!.family);
    });
  };
}

interface HopResult {
  status: number;
  location: string | null;
  /** Only read for HTML pages, to find meta refresh redirects. */
  body: string | null;
}

function checkUrl(url: URL, options: SafeFetchOptions): void {
  if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new BlockedDestinationError('not http(s)');
  const port = url.port ? Number(url.port) : url.protocol === 'https:' ? 443 : 80;
  if (!(options.allowedPorts ?? [80, 443]).includes(port)) throw new BlockedDestinationError('non-standard port');
  const host = url.hostname.replace(/^\[|\]$/g, '');
  const isBlocked = options.isBlocked ?? isBlockedAddress;
  if (isIP(host)) {
    if (isBlocked(host)) throw new BlockedDestinationError('private or reserved address');
  } else if (isBlockedHostname(host)) {
    throw new BlockedDestinationError('internal host name');
  }
}

function fetchOnce(url: URL, signal: AbortSignal, options: SafeFetchOptions): Promise<HopResult> {
  checkUrl(url, options);
  const maxBytes = options.limits?.maxBytes ?? FETCH_LIMITS.maxBytes;
  const client = url.protocol === 'https:' ? https : http;
  return new Promise<HopResult>((resolvePromise, reject) => {
    const request = client.request(
      url,
      {
        method: 'GET',
        agent: false,
        signal,
        lookup: guardedLookup(options.resolve ?? systemResolve, options.isBlocked ?? isBlockedAddress),
        headers: { 'user-agent': USER_AGENT, accept: 'text/html,*/*;q=0.5', 'accept-encoding': 'identity' },
      },
      (response) => {
        const status = response.statusCode ?? 0;
        const location = status >= 300 && status < 400 ? (response.headers.location ?? null) : null;
        const isHtml = /^text\/html/i.test(response.headers['content-type'] ?? '');
        if (location !== null || !isHtml || status !== 200) {
          response.destroy();
          return resolvePromise({ status, location, body: null });
        }
        const chunks: Buffer[] = [];
        let size = 0;
        const finish = () => resolvePromise({ status, location: null, body: Buffer.concat(chunks).toString('utf8') });
        response.on('data', (chunk: Buffer) => {
          const room = maxBytes - size;
          chunks.push(chunk.length > room ? chunk.subarray(0, room) : chunk);
          size += Math.min(chunk.length, room);
          if (size >= maxBytes) {
            response.destroy();
            finish();
          }
        });
        response.on('end', finish);
        response.on('error', reject);
      },
    );
    request.on('error', reject);
    request.end();
  });
}

/** `<meta http-equiv="refresh" content="0; url=...">`, the one redirect that lives in the page. */
export function metaRefreshTarget(html: string): string | null {
  for (const [tag] of html.slice(0, 64 * 1024).matchAll(/<meta\b[^>]*>/gi)) {
    if (!/http-equiv\s*=\s*["']?refresh/i.test(tag)) continue;
    const match = /content\s*=\s*["']?\s*\d*\s*;?\s*url\s*=\s*['"]?([^"'>\s]+)/i.exec(tag);
    if (match) return match[1]!.replace(/&amp;/g, '&');
  }
  return null;
}

export type ExpansionStop = 'final' | 'too_many_hops' | 'blocked' | 'error' | 'timeout';

export interface Expansion {
  /** The URL we started from, then every URL it redirected to. */
  hops: string[];
  finalUrl: string;
  stoppedBy: ExpansionStop;
}

export async function expandRedirects(start: string, options: SafeFetchOptions = {}): Promise<Expansion> {
  const maxHops = options.limits?.maxHops ?? FETCH_LIMITS.maxHops;
  const signal = AbortSignal.timeout(options.limits?.timeoutMs ?? FETCH_LIMITS.timeoutMs);
  const hops = [start];
  let current = new URL(start);
  current.username = '';
  current.password = '';

  for (let hop = 0; ; hop++) {
    let result: HopResult;
    try {
      result = await fetchOnce(current, signal, options);
    } catch (error) {
      const stoppedBy: ExpansionStop =
        error instanceof BlockedDestinationError ? 'blocked' : signal.aborted ? 'timeout' : 'error';
      return { hops, finalUrl: hops.at(-1)!, stoppedBy };
    }

    const target = result.location ?? (result.body ? metaRefreshTarget(result.body) : null);
    if (!target) return { hops, finalUrl: hops.at(-1)!, stoppedBy: 'final' };

    let next: URL;
    try {
      next = new URL(target, current);
    } catch {
      return { hops, finalUrl: hops.at(-1)!, stoppedBy: 'error' };
    }
    next.username = '';
    next.password = '';
    // Where it points is worth knowing even if we won't go there.
    hops.push(next.toString());
    if (hop + 1 >= maxHops) return { hops, finalUrl: next.toString(), stoppedBy: 'too_many_hops' };
    current = next;
  }
}
