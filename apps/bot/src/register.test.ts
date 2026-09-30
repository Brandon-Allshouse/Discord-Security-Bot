import { describe, expect, it, vi } from 'vitest';
import { inviteUrl, registerCommands } from './register.js';

const base = { DISCORD_TOKEN: 'x'.repeat(70), DISCORD_CLIENT_ID: '123456789012345678' };
const DEV = '100000000000000001';

const failWith = (status: number) => ({
  put: vi.fn(() => Promise.reject(Object.assign(new Error('Discord error'), { status }))),
});

describe('registerCommands', () => {
  it('registers to the dev server when DEV_GUILD_ID is set', async () => {
    const rest = { put: vi.fn(() => Promise.resolve([])) };
    expect(await registerCommands({ ...base, DEV_GUILD_ID: DEV }, rest)).toBe('registered');
    expect(rest.put).toHaveBeenCalledWith(`/applications/${base.DISCORD_CLIENT_ID}/guilds/${DEV}/commands`, expect.anything());
  });

  it('registers globally without DEV_GUILD_ID', async () => {
    const rest = { put: vi.fn(() => Promise.resolve([])) };
    await registerCommands(base, rest);
    expect(rest.put).toHaveBeenCalledWith(`/applications/${base.DISCORD_CLIENT_ID}/commands`, expect.anything());
  });

  it('reports "not in the dev server yet" instead of crashing on a first run', async () => {
    expect(await registerCommands({ ...base, DEV_GUILD_ID: DEV }, failWith(403))).toBe('not_in_dev_guild');
  });

  it('still fails on a bad token', async () => {
    await expect(registerCommands({ ...base, DEV_GUILD_ID: DEV }, failWith(401))).rejects.toThrow();
  });

  it('still fails on 403 for global registration', async () => {
    await expect(registerCommands(base, failWith(403))).rejects.toThrow();
  });
});

describe('inviteUrl', () => {
  it('asks for bot + slash commands with exactly the needed permissions', () => {
    expect(inviteUrl(base.DISCORD_CLIENT_ID)).toBe(
      `https://discord.com/oauth2/authorize?client_id=${base.DISCORD_CLIENT_ID}&scope=bot+applications.commands&permissions=1099780090880`,
    );
  });
});
