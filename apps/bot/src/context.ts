import type { Client } from 'discord.js';
import type { Redis } from 'ioredis';
import { RateLimiter, type PipelineDeps } from '@equinox/core';
import type { Stores } from '@equinox/db';
import type { CachedGuildRepository, IndicatorService } from './indicators.js';
import type { IntelCache, IntelRequests } from './intel.js';
import type { Logger } from './logger.js';

export interface BotContext {
  client: Client;
  logger: Logger;
  redis: Redis;
  stores: Stores;
  guildCache: CachedGuildRepository;
  indicators: IndicatorService;
  /** Cached intel for the fast path, and lookup requests to the intel worker. */
  intelCache: IntelCache;
  intel: Pick<IntelRequests, 'request' | 'lookup'>;
  deps: PipelineDeps;
  limits: {
    /** Per user: commands and buttons. */
    interactions: RateLimiter;
  };
}

export function createLimits() {
  return { interactions: new RateLimiter(10, 60_000) };
}
