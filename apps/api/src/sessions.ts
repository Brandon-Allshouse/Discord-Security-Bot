import { createHash, randomBytes } from 'node:crypto';
import type { Redis } from 'ioredis';
import { z } from 'zod';

/**
 * Who is logged in and which servers they may manage. The server list is taken from
 * Discord at login and not refreshed, so sessions are short: losing Manage Server in
 * Discord takes effect here within SESSION_TTL_SECONDS at the latest.
 */
const sessionSchema = z.object({
  userId: z.string(),
  username: z.string(),
  /** Sent back in every form, so another site can't submit one on the user's behalf. */
  csrf: z.string(),
  guilds: z.array(z.object({ id: z.string(), name: z.string() })),
});

export type Session = z.infer<typeof sessionSchema>;

export const SESSION_TTL_SECONDS = 60 * 60;

const SESSION_ID = /^[A-Za-z0-9_-]{43}$/;

export function newToken(): string {
  return randomBytes(32).toString('base64url');
}

export interface SessionStore {
  /** Returns the new session ID, which goes in the cookie. */
  create(session: Session): Promise<string>;
  get(id: string): Promise<Session | null>;
  destroy(id: string): Promise<void>;
}

/** Sessions live in Redis under a hash of the ID, so reading Redis doesn't hand out usable cookies. */
export class RedisSessionStore implements SessionStore {
  constructor(private readonly redis: Redis) {}

  private key(id: string): string {
    return `equinox:session:${createHash('sha256').update(id).digest('hex')}`;
  }

  async create(session: Session): Promise<string> {
    const id = newToken();
    await this.redis.set(this.key(id), JSON.stringify(session), 'EX', SESSION_TTL_SECONDS);
    return id;
  }

  async get(id: string): Promise<Session | null> {
    if (!SESSION_ID.test(id)) return null;
    const raw = await this.redis.get(this.key(id));
    if (!raw) return null;
    const parsed = sessionSchema.safeParse(JSON.parse(raw));
    return parsed.success ? parsed.data : null;
  }

  async destroy(id: string): Promise<void> {
    if (SESSION_ID.test(id)) await this.redis.del(this.key(id));
  }
}
