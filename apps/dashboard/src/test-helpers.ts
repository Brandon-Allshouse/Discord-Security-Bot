import type { AuditEntry, Detection, GuildMode, GuildSettings } from '@equinox/core';
import { makeGuild } from '@equinox/core/testing';
import { buildApp, type DashboardStores } from './app.js';
import type { DiscordLogin, DiscordOAuth } from './discord-oauth.js';
import { newToken, type Session, type SessionStore } from './sessions.js';

export const TENANT = '100000000000000001';
export const OTHER_TENANT = '100000000000000002';
export const ADMIN = '500000000000000001';
/** The Host header of the public address the test app is configured with. */
export const HOST = { host: 'localhost:3000' };

export class MemorySessionStore implements SessionStore {
  readonly sessions = new Map<string, Session>();

  create(session: Session): Promise<string> {
    const id = newToken();
    this.sessions.set(id, session);
    return Promise.resolve(id);
  }
  get(id: string): Promise<Session | null> {
    return Promise.resolve(this.sessions.get(id) ?? null);
  }
  destroy(id: string): Promise<void> {
    this.sessions.delete(id);
    return Promise.resolve();
  }
}

/** The dashboard with in-memory stores, two tenants and a Discord that logs ADMIN in as a manager of TENANT only. */
export async function createTestApp() {
  const guilds = new Map<string, GuildSettings>([
    [TENANT, makeGuild({ id: TENANT })],
    [OTHER_TENANT, makeGuild({ id: OTHER_TENANT })],
  ]);
  const detections: Detection[] = [];
  const audit: (AuditEntry & { createdAt: Date })[] = [];
  const allowlist: { guildId: string; type: string; value: string; addedBy: string; createdAt: Date; id: string }[] = [];

  const stores: DashboardStores = {
    guilds: {
      get: (id) => Promise.resolve(guilds.get(id) ?? null),
      setMode: (id, mode: GuildMode) => {
        const guild = guilds.get(id);
        if (guild) guilds.set(id, { ...guild, mode });
        return Promise.resolve();
      },
    },
    detections: {
      recent: (id) => Promise.resolve(detections.filter((d) => d.guildId === id)),
      countOpen: (id) => Promise.resolve(detections.filter((d) => d.guildId === id && d.status === 'open').length),
    },
    audit: {
      write: (entry) => {
        audit.push({ ...entry, createdAt: new Date() });
        return Promise.resolve();
      },
      recent: (id) => Promise.resolve(audit.filter((a) => a.guildId === id).map((a) => ({ ...a, id: 'x' }))),
    },
    allowlist: {
      list: (id) => Promise.resolve(allowlist.filter((a) => a.guildId === id)),
      add: (input) => {
        allowlist.push({ ...input, createdAt: new Date(), id: 'x' });
        return Promise.resolve();
      },
      remove: (id, _type, value) => {
        const index = allowlist.findIndex((a) => a.guildId === id && a.value === value);
        if (index >= 0) allowlist.splice(index, 1);
        return Promise.resolve(index >= 0);
      },
    },
  };

  const sessions = new MemorySessionStore();
  const discord: { login: DiscordLogin | Error; states: string[] } = {
    login: { user: { id: ADMIN, username: 'admin' }, manageableGuilds: [{ id: TENANT, name: 'Test server' }] },
    states: [],
  };
  const oauth: DiscordOAuth = {
    authorizeUrl: (state) => {
      discord.states.push(state);
      return `https://discord.test/authorize?state=${state}`;
    },
    login: () => (discord.login instanceof Error ? Promise.reject(discord.login) : Promise.resolve(discord.login)),
  };

  const app = await buildApp({ stores, sessions, oauth, publicUrl: 'http://localhost:3000' });

  /** Goes through the real login routes and returns the session cookie and CSRF token. */
  async function logIn() {
    const start = await app.inject({ method: 'GET', url: '/auth/login', headers: HOST });
    const state = discord.states.at(-1)!;
    const callback = await app.inject({
      method: 'GET',
      url: `/auth/callback?code=abc&state=${state}`,
      cookies: { eq_oauth_state: start.cookies.find((c) => c.name === 'eq_oauth_state')!.value },
    });
    const id = callback.cookies.find((c) => c.name === 'eq_session')!.value;
    return { cookies: { eq_session: id }, csrf: sessions.sessions.get(id)!.csrf, callback };
  }

  return { app, guilds, detections, audit, allowlist, sessions, discord, logIn };
}
