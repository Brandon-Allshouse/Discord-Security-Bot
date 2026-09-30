import { parse } from 'tldts';

/** Hard cap on work per message, so a message stuffed with links can't stall a shard. */
export const MAX_URLS_PER_MESSAGE = 10;
const MAX_INPUT_LENGTH = 8000;

// Zero-width and other invisible characters used to break up links.
const INVISIBLE = /[​-‏⁠-⁤﻿­͏᠎]/g;

/**
 * Undoes common link obfuscation so hidden links become visible:
 * hxxp, [.] (.) {.} [dot], "dot", spaced-out dots and invisible characters.
 */
export function deobfuscate(text: string): string {
  return text
    .slice(0, MAX_INPUT_LENGTH)
    .normalize('NFKC')
    .replace(INVISIBLE, '')
    .replace(/\bh(?:xx|\*\*|tt)p(s?)(?::|\[:\])\/\//gi, 'http$1://')
    .replace(/\s*(?:\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\})\s*/gi, '.')
    .replace(/(?<=[a-z0-9-])\s+\.\s*(?=[a-z0-9-]{2,}\b)/gi, '.')
    .replace(/(?<=[a-z0-9-])\s*\.\s+(?=[a-z0-9-]{2,}\b)/gi, '.');
}

const SCHEME_URL = /\bhttps?:\/\/[^\s<>"'`|\\^{}]+/gi;
// Bare domains like "dlscord.gift/abc": host with at least one dot, optional path.
const BARE_DOMAIN = /(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}(?:\/[^\s<>"'`|\\^{}]*)?/gi;

function trimTrailing(url: string): string {
  // Drop trailing punctuation that's almost always sentence punctuation, and
  // unbalanced closing brackets from markdown like [text](url).
  let result = url.replace(/[.,;:!?'"]+$/, '');
  while (result.endsWith(')') && (result.match(/\(/g)?.length ?? 0) < (result.match(/\)/g)?.length ?? 0)) {
    result = result.slice(0, -1);
  }
  return result.replace(/[.,;:!?'"]+$/, '');
}

/**
 * Extracts candidate URLs from message text: plain links, markdown links, <angle> links,
 * obfuscated links and bare domains with a real public suffix.
 */
export function extractUrls(text: string): string[] {
  const clean = deobfuscate(text);
  const found = new Set<string>();

  for (const match of clean.matchAll(SCHEME_URL)) {
    found.add(trimTrailing(match[0]));
    if (found.size >= MAX_URLS_PER_MESSAGE) return [...found];
  }

  // Remove scheme URLs so their hosts aren't matched again as bare domains.
  const withoutSchemeUrls = clean.replace(SCHEME_URL, ' ');
  for (const match of withoutSchemeUrls.matchAll(BARE_DOMAIN)) {
    const candidate = trimTrailing(match[0]);
    const host = candidate.split('/')[0]!;
    const parsed = parse(host);
    // Only real ICANN suffixes, so "file.txt" or "node.js" in chat aren't treated as links.
    if (!parsed.domain || !parsed.isIcann || parsed.publicSuffix === host) continue;
    if (/^(?:js|ts|py|txt|md|json|exe|zip|png|jpg|gif)$/i.test(parsed.publicSuffix ?? '')) continue;
    found.add(`http://${candidate}`);
    if (found.size >= MAX_URLS_PER_MESSAGE) break;
  }

  return [...found];
}
