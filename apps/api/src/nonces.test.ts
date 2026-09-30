import { describe, expect, it, vi } from 'vitest';
import { API_REQUEST_MAX_AGE_MS } from '@equinox/core';
import { RedisNonceStore } from './nonces.js';

describe('RedisNonceStore', () => {
  it('claims a nonce once, atomically, and keeps it longer than a request may be old', async () => {
    const taken = new Set<string>();
    const set = vi.fn((key: string, _value: string, _px: string, ms: number, _nx: string) => {
      expect(ms).toBeGreaterThan(API_REQUEST_MAX_AGE_MS);
      if (taken.has(key)) return Promise.resolve(null);
      taken.add(key);
      return Promise.resolve('OK' as const);
    });
    const nonces = new RedisNonceStore({ set } as never);
    expect(await nonces.claim('abc')).toBe(true);
    expect(await nonces.claim('abc')).toBe(false);
    expect(await nonces.claim('def')).toBe(true);
    expect(set).toHaveBeenCalledWith('equinox:api:nonce:abc', '1', 'PX', expect.any(Number), 'NX');
  });
});
