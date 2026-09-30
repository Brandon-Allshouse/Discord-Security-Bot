import type { Guild } from 'discord.js';
import { describe, expect, it, vi } from 'vitest';
import { makeGuild } from '@equinox/core/testing';
import { createFakeContext, TENANT } from '../test-helpers.js';
import { offboardGuild, onboardGuild } from './guilds.js';

function fakeGuild(create = vi.fn(() => Promise.resolve({ id: '700000000000000001' }))) {
  return { guild: { id: TENANT, name: 'Test server', roles: { create } } as unknown as Guild, create };
}

describe('tenant onboarding', () => {
  it('creates the tenant and a permissionless quarantine role', async () => {
    const t = createFakeContext(makeGuild({ id: TENANT, quarantineRoleId: null }));
    const { guild, create } = fakeGuild();
    await onboardGuild(guild, t.ctx);
    expect(t.stores.guilds.register).toHaveBeenCalledWith({ id: TENANT, name: 'Test server' });
    expect(create).toHaveBeenCalledWith(expect.objectContaining({ permissions: [] }));
    expect(t.stores.guilds.configure).toHaveBeenCalledWith(TENANT, { quarantineRoleId: '700000000000000001' });
    expect(t.fake.audit.at(-1)).toMatchObject({ action: 'guild.joined', details: { mode: 'alert_only' } });
  });

  it('keeps an existing quarantine role', async () => {
    const t = createFakeContext(makeGuild({ id: TENANT }));
    const { guild, create } = fakeGuild();
    await onboardGuild(guild, t.ctx);
    expect(create).not.toHaveBeenCalled();
  });

  it('still onboards when it lacks Manage Roles', async () => {
    const t = createFakeContext(makeGuild({ id: TENANT, quarantineRoleId: null }));
    const { guild } = fakeGuild(vi.fn(() => Promise.reject(new Error('Missing Permissions'))));
    await onboardGuild(guild, t.ctx);
    expect(t.logger.warn).toHaveBeenCalled();
    expect(t.fake.audit.at(-1)).toMatchObject({ action: 'guild.joined' });
  });

  it('marks the tenant as left on removal and audits it', async () => {
    const t = createFakeContext();
    const { guild } = fakeGuild();
    await offboardGuild(guild, t.ctx);
    expect(t.stores.guilds.markLeft).toHaveBeenCalledWith(TENANT);
    expect(t.guildCache.invalidate).toHaveBeenCalledWith(TENANT);
    expect(t.fake.audit.at(-1)).toMatchObject({ action: 'guild.left' });
  });
});
