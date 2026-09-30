import { ApplicationCommandOptionType } from 'discord.js';
import { describe, expect, it } from 'vitest';
import { COMMAND_ACCESS, isAuthorized, requiredAccess } from './authz.js';
import { commandDefinitions } from './commands.js';

const admin = { hasManageGuild: true, roleIds: [] };
const mod = { hasManageGuild: false, roleIds: ['1'] };
const member = { hasManageGuild: false, roleIds: ['2'] };

describe('command access table', () => {
  it('covers every registered subcommand', () => {
    const routes: string[] = [];
    for (const option of commandDefinitions[0]?.options ?? []) {
      if (option.type === ApplicationCommandOptionType.Subcommand) routes.push(option.name);
      if (option.type === ApplicationCommandOptionType.SubcommandGroup) for (const sub of option.options ?? []) routes.push(`${option.name}.${sub.name}`);
    }
    expect(routes.sort()).toEqual(Object.keys(COMMAND_ACCESS).sort());
  });

  it('treats unknown routes as admin-only (deny by default)', () => {
    expect(requiredAccess('something.new')).toBe('admin');
  });

  it('keeps settings changes admin-only', () => {
    for (const route of ['setup', 'mode', 'allow.add', 'allow.remove']) expect(requiredAccess(route)).toBe('admin');
  });
});

describe('isAuthorized', () => {
  it.each([
    ['admin', admin, true],
    ['admin', mod, false],
    ['admin', member, false],
    ['mod', admin, true],
    ['mod', mod, true],
    ['mod', member, false],
  ] as const)('%s level, member %# -> %s', (level, who, expected) => {
    expect(isAuthorized(level, who, ['1'])).toBe(expected);
  });

  it('denies mods when no mod role is configured', () => {
    expect(isAuthorized('mod', mod, [])).toBe(false);
  });
});
