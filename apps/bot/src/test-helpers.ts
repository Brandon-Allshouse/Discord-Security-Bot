import type { Interaction } from 'discord.js';
import { vi } from 'vitest';
import { BRAND, RateLimiter, type GuildSettings } from '@equinox/core';
import { createFakeDeps, makeGuild } from '@equinox/core/testing';
import type { BotContext } from './context.js';

/** Test-only fakes for the bot. Excluded from the build. */

export const TENANT = '100000000000000001';
export const OTHER_TENANT = '100000000000000099';
export const MOD_ROLE = '600000000000000001';
export const USER = '500000000000000001';

export function silentLogger() {
  return { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn(), fatal: vi.fn() };
}

export function createFakeContext(guild: GuildSettings = makeGuild({ id: TENANT, modRoleIds: [MOD_ROLE] })) {
  const fake = createFakeDeps([guild]);
  const allowlist = new Set<string>();
  const stores = {
    guilds: {
      get: vi.fn((id: string) => fake.deps.guilds.get(id)),
      register: vi.fn(({ id }: { id: string }) => {
        const settings = fake.guildMap.get(id) ?? makeGuild({ id });
        fake.guildMap.set(id, settings);
        return Promise.resolve(settings);
      }),
      markLeft: vi.fn(() => Promise.resolve()),
      setMode: vi.fn((id: string, mode: GuildSettings['mode']) => {
        const g = fake.guildMap.get(id);
        if (g) g.mode = mode;
        return Promise.resolve();
      }),
      configure: vi.fn((id: string, settings: Partial<GuildSettings>) => {
        const g = fake.guildMap.get(id);
        if (g) Object.assign(g, settings);
        return Promise.resolve();
      }),
    },
    detections: { ...fake.deps.detections, countOpen: vi.fn(() => Promise.resolve(0)) },
    audit: { write: vi.fn(fake.deps.audit.write), recent: vi.fn(() => Promise.resolve([])) },
    allowlist: {
      has: vi.fn((g: string, _t: string, v: string) => Promise.resolve(allowlist.has(`${g}:${v}`))),
      hasAny: vi.fn((g: string, _t: string, vs: string[]) => Promise.resolve(vs.some((v) => allowlist.has(`${g}:${v}`)))),
      add: vi.fn(({ guildId, value }: { guildId: string; value: string }) => {
        allowlist.add(`${guildId}:${value}`);
        return Promise.resolve();
      }),
      remove: vi.fn((g: string, _t: string, v: string) => Promise.resolve(allowlist.delete(`${g}:${v}`))),
      list: vi.fn((g: string) =>
        Promise.resolve([...allowlist].filter((k) => k.startsWith(`${g}:`)).map((k) => ({ value: k.split(':')[1] }))),
      ),
    },
  };
  const guildCache = { get: (id: string) => fake.deps.guilds.get(id), invalidate: vi.fn() };
  const indicators = {
    isAllowlisted: fake.deps.indicators.isAllowlisted,
    isBlocklisted: fake.deps.indicators.isBlocklisted,
    isDomainBlocklisted: vi.fn((candidates: string[]) => Promise.resolve(candidates.some((c) => fake.blocklist.has(c)))),
  };
  const logger = silentLogger();
  const ctx = {
    client: { user: { id: '999999999999999999' } },
    logger,
    redis: {},
    stores,
    guildCache,
    indicators,
    deps: { ...fake.deps, guilds: guildCache },
    limits: { interactions: new RateLimiter(10, 60_000) },
  } as unknown as BotContext;
  return { ctx, fake, stores, logger, allowlist, guildCache };
}

interface FakeInteractionOptions {
  userId?: string;
  guildId?: string;
  manageGuild?: boolean;
  roleIds?: string[];
}

function baseInteraction(opts: FakeInteractionOptions) {
  const state = { deferred: false, replied: false };
  const replies: unknown[] = [];
  const interaction = {
    user: { id: opts.userId ?? USER },
    guildId: opts.guildId ?? TENANT,
    channelId: '300000000000000001',
    guild: { name: 'Test server' },
    inCachedGuild: () => true,
    memberPermissions: { has: () => opts.manageGuild ?? false },
    member: { roles: { cache: new Map((opts.roleIds ?? []).map((id) => [id, {}])) } },
    get deferred() {
      return state.deferred;
    },
    get replied() {
      return state.replied;
    },
    reply: vi.fn((m: unknown) => {
      state.replied = true;
      replies.push(m);
      return Promise.resolve();
    }),
    deferReply: vi.fn(() => {
      state.deferred = true;
      return Promise.resolve();
    }),
    deferUpdate: vi.fn(() => {
      state.deferred = true;
      return Promise.resolve();
    }),
    editReply: vi.fn((m: unknown) => {
      replies.push(m);
      return Promise.resolve();
    }),
    followUp: vi.fn((m: unknown) => {
      replies.push(m);
      return Promise.resolve();
    }),
  };
  return { interaction, replies };
}

/** Text of every reply, edit and follow-up, for assertions. */
export function replyText(replies: unknown[]): string {
  return replies.map((r) => (typeof r === 'string' ? r : JSON.stringify(r))).join('\n');
}

export function fakeCommand(
  route: { sub: string; group?: string },
  options: Record<string, unknown> = {},
  opts: FakeInteractionOptions = {},
) {
  const { interaction, replies } = baseInteraction(opts);
  Object.assign(interaction, {
    isChatInputCommand: () => true,
    isButton: () => false,
    commandName: BRAND.command,
    options: {
      getSubcommandGroup: () => route.group ?? null,
      getSubcommand: () => route.sub,
      getString: (name: string) => options[name] ?? null,
      getChannel: (name: string) => options[name] ?? null,
      getRole: (name: string) => options[name] ?? null,
    },
  });
  return { interaction: interaction as unknown as Interaction, raw: interaction, replies };
}

export function fakeButton(customId: string, opts: FakeInteractionOptions = {}, embeds: object[] = [{ title: 'Alert' }]) {
  const { interaction, replies } = baseInteraction(opts);
  Object.assign(interaction, {
    isChatInputCommand: () => false,
    isButton: () => true,
    customId,
    message: { embeds },
  });
  return { interaction: interaction as unknown as Interaction, raw: interaction, replies };
}
