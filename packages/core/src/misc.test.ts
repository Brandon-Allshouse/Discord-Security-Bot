import { describe, expect, it } from 'vitest';
import { defang, truncate } from './display.js';
import { safeErrorMessage } from './errors.js';
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

describe('safeErrorMessage', () => {
  it('hides error internals', () => {
    expect(safeErrorMessage(new Error('password=hunter2'))).toBe('Action failed');
    expect(safeErrorMessage(Object.assign(new Error('x'), { code: 50013 }))).toBe('Discord API error 50013');
  });
});
