import type { Redis } from 'ioredis';
import { API_REQUEST_MAX_AGE_MS } from '@equinox/core';
import type { NonceStore } from './app.js';

/**
 * Nonces are kept for longer than a request may be old, so a captured request can't be
 * replayed: while it's still fresh enough, its nonce is already taken.
 */
const KEEP_MS = API_REQUEST_MAX_AGE_MS * 3;

export class RedisNonceStore implements NonceStore {
  constructor(private readonly redis: Pick<Redis, 'set'>) {}

  async claim(nonce: string): Promise<boolean> {
    return (await this.redis.set(`equinox:api:nonce:${nonce}`, '1', 'PX', KEEP_MS, 'NX')) === 'OK';
  }
}
