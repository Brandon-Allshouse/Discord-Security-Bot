import { domainToUnicode } from 'node:url';
import { parse } from 'tldts';

export interface NormalizedUrl {
  /** Canonical URL used as the signal subject: lowercase punycode host, no tracking params, no fragment. */
  url: string;
  /** ASCII (punycode) hostname. */
  host: string;
  /** Unicode form of the host, for homoglyph checks. */
  unicodeHost: string;
  /** Registrable domain, e.g. "example.co.uk". Null for IPs and unknown suffixes. */
  domain: string | null;
  /** Label left of the public suffix, e.g. "example". */
  domainLabel: string | null;
  publicSuffix: string | null;
  isIp: boolean;
  hadCredentials: boolean;
}

const TRACKING_PARAMS = /^(?:utm_\w+|fbclid|gclid|dclid|msclkid|mc_eid|mc_cid|igshid|yclid|_hsenc|_hsmi|ref_src)$/i;

/** Returns null for anything that isn't a well-formed http(s) URL. */
export function normalizeUrl(raw: string): NormalizedUrl | null {
  let url: URL;
  try {
    url = new URL(raw.length > 2048 ? raw.slice(0, 2048) : raw);
  } catch {
    return null;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
  if (!url.hostname) return null;

  const hadCredentials = url.username !== '' || url.password !== '';
  url.username = '';
  url.password = '';
  url.hash = '';
  url.hostname = url.hostname.replace(/\.$/, '');
  for (const key of [...url.searchParams.keys()]) {
    if (TRACKING_PARAMS.test(key)) url.searchParams.delete(key);
  }

  const host = url.hostname.toLowerCase();
  const parsed = parse(host);
  const isIp = parsed.isIp === true || /^\[.*\]$/.test(host);

  return {
    url: url.toString(),
    host,
    unicodeHost: domainToUnicode(host) || host,
    domain: isIp ? null : parsed.domain,
    domainLabel: isIp ? null : parsed.domainWithoutSuffix,
    publicSuffix: isIp ? null : parsed.publicSuffix,
    isIp,
    hadCredentials,
  };
}

/** The host and each parent domain down to the registrable domain, for allowlist/blocklist matching. */
export function domainCandidates(normalized: Pick<NormalizedUrl, 'host' | 'domain'>): string[] {
  const { host, domain } = normalized;
  if (!domain) return [host];
  const candidates = [host];
  let current = host;
  while (current !== domain && current.includes('.')) {
    current = current.slice(current.indexOf('.') + 1);
    candidates.push(current);
  }
  return [...new Set(candidates)];
}
