import type {
  AuditEntry,
  BotOutcome,
  DashboardAction,
  Detection,
  GuildMode,
  GuildSettings,
  GuildSnapshot,
  IntelStatus,
  IntelSummary,
} from '@equinox/core';
import { makeGuild } from '@equinox/core/testing';
import { buildApi, type ApiStores, type NonceStore } from './app.js';
import type { BotLink } from './bot-link.js';
import type { DiscordLogin, DiscordOAuth } from './discord-oauth.js';
import type { DashboardIntel } from './intel.js';
import { newToken, type Session, type SessionStore } from './sessions.js';

/*
 * In-memory stand-ins for everything behind the API, for tests (the API's own, and the
 * dashboard's end-to-end tests, which run the real API in-process). Nothing here touches a
 * database, Redis or Discord.
 */

export const TENANT = '100000000000000001';
export const OTHER_TENANT = '100000000000000002';
export const ADMIN = '500000000000000001';
export const TEST_API_KEY = 'cd'.repeat(32);

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

export class MemoryNonceStore implements NonceStore {
  readonly seen = new Set<string>();
  claim(nonce: string): Promise<boolean> {
    if (this.seen.has(nonce)) return Promise.resolve(false);
    this.seen.add(nonce);
    return Promise.resolve(true);
  }
}

/** The API with in-memory stores, two tenants, and a Discord that logs ADMIN in as a manager of TENANT only. */
export async function createTestApi(options: { now?: () => number } = {}) {
  const guilds = new Map<string, GuildSettings>([
    [TENANT, makeGuild({ id: TENANT })],
    [OTHER_TENANT, makeGuild({ id: OTHER_TENANT })],
  ]);
  const detections: Detection[] = [];
  const audit: (AuditEntry & { createdAt: Date })[] = [];
  const allowlist: { guildId: string; type: string; value: string; addedBy: string; createdAt: Date; id: string }[] = [];

  const stores: ApiStores = {
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
      hasAny: (id, _type, values) => Promise.resolve(allowlist.some((a) => a.guildId === id && values.includes(a.value))),
    },
  };

  /** Threat intel as the API sees it. Set `down` to make every call fail. */
  const intelState = {
    status: null as IntelStatus | null,
    cached: new Map<string, IntelSummary>(),
    blocklist: new Set<string>(),
    lookups: [] as { url: string; heuristicScore: number }[],
    down: false,
  };
  const fail = () => Promise.reject(new Error('redis down'));
  const intel: DashboardIntel = {
    status: () => (intelState.down ? fail() : Promise.resolve(intelState.status)),
    cached: (url) => (intelState.down ? fail() : Promise.resolve(intelState.cached.get(url) ?? null)),
    isBlocklisted: (candidates) => (intelState.down ? fail() : Promise.resolve(candidates.some((c) => intelState.blocklist.has(c)))),
    requestLookup: (url, heuristicScore) => {
      if (intelState.down) return fail();
      intelState.lookups.push({ url, heuristicScore });
      return Promise.resolve();
    },
  };

  const sessions = new MemorySessionStore();
  const nonces = new MemoryNonceStore();
  const discord: { login: DiscordLogin | Error; states: string[] } = {
    login: { user: { id: ADMIN, username: 'admin' }, manageableGuilds: [{ id: TENANT, name: 'Test server' }] },
    states: [],
  };
  const oauth: DiscordOAuth = {
    authorizeUrl: (state) => {
      discord.states.push(state);
      return `https://discord.com/oauth2/authorize?state=${state}`;
    },
    login: () => (discord.login instanceof Error ? Promise.reject(discord.login) : Promise.resolve(discord.login)),
  };

  /** The bot as the API sees it: a snapshot per server, and requests with a canned answer. Set `down` to make it fail. */
  const botState = {
    enabled: true,
    down: false,
    snapshots: new Map<string, GuildSnapshot>(),
    sent: [] as DashboardAction[],
    answer: 'reviewed' as BotOutcome,
  };
  const bot: BotLink = {
    get enabled() {
      return botState.enabled;
    },
    snapshot: (guildId) => (botState.down ? fail() : Promise.resolve(botState.snapshots.get(guildId) ?? null)),
    send: (action) => {
      if (botState.down) return fail();
      botState.sent.push(action);
      return Promise.resolve(botState.enabled ? botState.answer : 'off');
    },
  };

  const api = await buildApi({
    stores,
    sessions,
    oauth,
    intel,
    bot,
    nonces,
    signingKey: TEST_API_KEY,
    ...(options.now ? { now: options.now } : {}),
  });
  return { api, guilds, detections, audit, allowlist, sessions, nonces, discord, intel: intelState, bot: botState };
}
