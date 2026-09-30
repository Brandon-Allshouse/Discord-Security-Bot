import { describe, expect, it } from 'vitest';
import { BRAND, slash } from './brand.js';
import { defang, truncate } from './display.js';
import { safeErrorMessage } from './errors.js';
import { parseDomainInput } from './links/normalize.js';
import { RateLimiter } from './rate-limit.js';

describe('RateLimiter', () => {
  it('allows up to the limit per window, then resets', () => {
    let now = 0;
    const limiter = new RateLimiter(2, 1000, () => now);
    expect(limiter.take('a')).toBe(true);
    expect(limiter.take('a')).toBe(true);
    expect(limiter.take('a')).toBe(false);
    expect(limiter.take('b')).toBe(true);
    now = 1000;
    expect(limiter.take('a')).toBe(true);
  });

  it('stays bounded in memory when flooded with new keys', () => {
    let now = 0;
    const limiter = new RateLimiter(1, 1000, () => now);
    for (let i = 0; i < 10_000; i++) limiter.take(`old-${i}`);
    now = 2000;
    limiter.take('new');
    const hits = (limiter as unknown as { hits: Map<string, unknown> }).hits;
    expect(hits.size).toBe(1);
    expect(limiter.take('old-0')).toBe(true);
  });
});

describe('brand', () => {
  it('writes slash commands the way users type them, and keeps the test domain unresolvable', () => {
    expect(slash('setup')).toBe(`/${BRAND.command} setup`);
    expect(BRAND.command).toMatch(/^[a-z0-9_-]{1,32}$/);
    expect(BRAND.testDomain.endsWith('.invalid')).toBe(true);
  });
});

describe('display helpers', () => {
  it('defangs URLs so they are not clickable', () => {
    expect(defang('https://evil.example.com/x')).toBe('hxxps://evil[.]example[.]com/x');
  });
  it('truncates without splitting emoji', () => {
    expect(truncate('ab😀cd', 4)).toBe('ab😀…');
    expect(truncate('short', 10)).toBe('short');
  });
});

describe('parseDomainInput', () => {
  it.each([
    ['example.com', 'example.com'],
    ['  Example.COM  ', 'example.com'],
    ['sub.example.co.uk', 'sub.example.co.uk'],
    ['example.com.', 'example.com'],
    ['bücher.de', 'xn--bcher-kva.de'],
  ])('accepts %s', (input, expected) => {
    expect(parseDomainInput(input)).toBe(expected);
  });

  it.each([
    '',
    'https://example.com',
    'example.com/path',
    'example',
    '192.168.0.1',
    'exa mple.com',
    'example.com;drop table',
    '<script>.com',
    `${'a'.repeat(250)}.com`,
  ])('rejects %s', (input) => {
    expect(parseDomainInput(input)).toBeNull();
  });
});

describe('safeErrorMessage', () => {
  it('hides error internals', () => {
    expect(safeErrorMessage(new Error('password=hunter2'))).toBe('Action failed');
    expect(safeErrorMessage(Object.assign(new Error('x'), { code: 50013 }))).toBe('Discord API error 50013');
  });
});
