import type { Redis } from 'ioredis';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { canManage, DiscordOAuthClient } from './discord-oauth.js';
import { newToken, RedisSessionStore, SESSION_TTL_SECONDS, type Session } from './sessions.js';

const CLIENT_ID = '123456789012345678';
const SECRET = 's'.repeat(32);
const USER = { id: '200000000000000001', username: 'mod' };
const guild = (id: string, permissions: string, owner = false) => ({ id, name: `g${id}`, owner, permissions });

interface Call {
  url: string;
  init: RequestInit | undefined;
}

/** Stubs global fetch with Discord's endpoints. `overrides` replaces a route's response. */
function stubDiscord(overrides: Partial<Record<string, () => Response>> = {}) {
  const calls: Call[] = [];
  const routes: Record<string, () => Response> = {
    '/oauth2/token': () => Response.json({ access_token: 'user-access-token' }),
    '/users/@me': () => Response.json(USER),
    '/users/@me/guilds': () =>
      Response.json([
        guild('100000000000000001', '32'), // Manage Server
        guild('100000000000000002', '8'), // Administrator
        guild('100000000000000003', '0', true), // owner
        guild('100000000000000004', '1024'), // View Channel only
      ]),
    '/oauth2/token/revoke': () => new Response(null, { status: 200 }),
    ...overrides,
  };
  vi.stubGlobal('fetch', (url: string, init?: RequestInit) => {
    calls.push({ url, init });
    const path = new URL(url).pathname.replace('/api/v10', '');
    return Promise.resolve(routes[path]?.() ?? new Response('not found', { status: 404 }));
  });
  return calls;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('canManage', () => {
  it('matches the bot’s idea of an admin: owner, Administrator or Manage Server', () => {
    expect(canManage({ permissions: '32' })).toBe(true);
    expect(canManage({ permissions: '8' })).toBe(true);
    expect(canManage({ owner: true, permissions: '0' })).toBe(true);
    expect(canManage({ permissions: String(1024 | 2048) })).toBe(false);
    expect(canManage({ owner: false, permissions: '0' })).toBe(false);
  });
});

describe('DiscordOAuthClient', () => {
  const client = () => new DiscordOAuthClient(CLIENT_ID, SECRET, 'https://dash.example');

  it('asks only for identify and guilds, with the state and the fixed redirect', () => {
    const url = new URL(client().authorizeUrl('state-123'));
    expect(url.origin).toBe('https://discord.com');
    expect(url.searchParams.get('scope')).toBe('identify guilds');
    expect(url.searchParams.get('state')).toBe('state-123');
    expect(url.searchParams.get('redirect_uri')).toBe('https://dash.example/auth/callback');
    expect(url.searchParams.get('response_type')).toBe('code');
    expect(url.toString()).not.toContain(SECRET);
  });

  it('logs in, keeps only manageable servers, and revokes the access token afterwards', async () => {
    const calls = stubDiscord();
    const login = await client().login('the-code');
    expect(login.user).toEqual(USER);
    expect(login.manageableGuilds.map((g) => g.id)).toEqual(['100000000000000001', '100000000000000002', '100000000000000003']);

    const paths = calls.map((c) => new URL(c.url).pathname);
    expect(paths.at(-1)).toBe('/api/v10/oauth2/token/revoke');
    // The client secret goes in the POST body, never the URL.
    expect(calls.every((c) => !c.url.includes(SECRET))).toBe(true);
    expect((calls[0]?.init?.body as URLSearchParams).get('client_secret')).toBe(SECRET);
    // The user's token is only ever sent as a header.
    const me = calls.find((c) => c.url.endsWith('/users/@me'));
    expect((me?.init?.headers as Record<string, string>).authorization).toBe('Bearer user-access-token');
    expect(calls.every((c) => c.init?.signal instanceof AbortSignal)).toBe(true);
  });

  it('revokes the token even when reading the profile fails', async () => {
    const calls = stubDiscord({ '/users/@me': () => new Response('boom', { status: 500 }) });
    await expect(client().login('code')).rejects.toThrow('Discord API error 500');
    expect(calls.some((c) => c.url.endsWith('/oauth2/token/revoke'))).toBe(true);
  });

  it('reports a failed code exchange by status only, never echoing the response', async () => {
    stubDiscord({ '/oauth2/token': () => new Response(`{"error":"invalid_grant","code":"the-code"}`, { status: 400 }) });
    await expect(client().login('the-code')).rejects.toThrow(/^Discord OAuth error 400$/);
  });

  it('rejects malformed answers from Discord', async () => {
    stubDiscord({ '/users/@me': () => Response.json({ id: 'not-a-snowflake', username: 'x' }) });
    await expect(client().login('code')).rejects.toThrow();
    stubDiscord({ '/oauth2/token': () => Response.json({}) });
    await expect(client().login('code')).rejects.toThrow();
  });

  it('caps how many servers a session can carry', async () => {
    const many = Array.from({ length: 250 }, (_, i) => guild(String(100000000000000000n + BigInt(i)), '32'));
    stubDiscord({ '/users/@me/guilds': () => Response.json(many) });
    expect((await client().login('code')).manageableGuilds).toHaveLength(200);
  });
});

/** Just enough of Redis for the session store, recording what was written. */
function fakeRedis() {
  const data = new Map<string, string>();
  const ttls = new Map<string, number>();
  const redis = {
    set: vi.fn((key: string, value: string, _ex: string, ttl: number) => {
      data.set(key, value);
      ttls.set(key, ttl);
      return Promise.resolve('OK');
    }),
    get: vi.fn((key: string) => Promise.resolve(data.get(key) ?? null)),
    del: vi.fn((key: string) => Promise.resolve(data.delete(key) ? 1 : 0)),
  };
  return { redis: redis as unknown as Redis, data, ttls, spy: redis };
}

describe('RedisSessionStore', () => {
  const session: Session = { userId: USER.id, username: 'mod', csrf: newToken(), guilds: [{ id: '100000000000000001', name: 'A' }] };

  it('issues random 256-bit IDs, stores sessions under a hash, and expires them after an hour', async () => {
    const { redis, data, ttls } = fakeRedis();
    const store = new RedisSessionStore(redis);
    const id = await store.create(session);
    expect(id).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(await store.create(session)).not.toBe(id);

    const [key] = [...data.keys()];
    expect(key).toMatch(/^equinox:session:[0-9a-f]{64}$/);
    expect(key).not.toContain(id);
    expect(ttls.get(key!)).toBe(SESSION_TTL_SECONDS);
    expect(await store.get(id)).toEqual(session);
  });

  it('never touches Redis for malformed IDs', async () => {
    const { redis, spy } = fakeRedis();
    const store = new RedisSessionStore(redis);
    for (const bad of ['', 'short', 'x'.repeat(43) + '*', '../../etc', 'a'.repeat(44)]) {
      expect(await store.get(bad)).toBeNull();
      await store.destroy(bad);
    }
    expect(spy.get).not.toHaveBeenCalled();
    expect(spy.del).not.toHaveBeenCalled();
  });

  it('logs out by deleting the session', async () => {
    const { redis } = fakeRedis();
    const store = new RedisSessionStore(redis);
    const id = await store.create(session);
    await store.destroy(id);
    expect(await store.get(id)).toBeNull();
  });

  it('treats a tampered session record as no session', async () => {
    const { redis, data } = fakeRedis();
    const store = new RedisSessionStore(redis);
    const id = await store.create(session);
    const [key] = [...data.keys()];
    data.set(key!, JSON.stringify({ userId: USER.id }));
    expect(await store.get(id)).toBeNull();
  });
});
