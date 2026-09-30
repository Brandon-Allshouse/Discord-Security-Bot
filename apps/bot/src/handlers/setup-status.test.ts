import { PermissionFlagsBits, PermissionsBitField } from 'discord.js';
import { describe, expect, it } from 'vitest';
import { createFakeContext, fakeCommand, MOD_ROLE, replyText, TENANT } from '../test-helpers.js';
import { handleInteraction } from './interactions.js';

const ADMIN = { manageGuild: true };
const MOD = { roleIds: [MOD_ROLE] };
const CHANNEL_ID = '300000000000000055';

const alertPerms = new PermissionsBitField([
  PermissionFlagsBits.ViewChannel,
  PermissionFlagsBits.SendMessages,
  PermissionFlagsBits.EmbedLinks,
]);

function channel(perms = alertPerms, textBased = true) {
  return {
    id: CHANNEL_ID,
    isTextBased: () => textBased,
    toString: () => `<#${CHANNEL_ID}>`,
    guild: { members: { me: {} } },
    permissionsFor: () => perms,
  };
}

const role = (id: string, overrides: { editable?: boolean; managed?: boolean } = {}) => ({
  id,
  editable: true,
  managed: false,
  toString: () => `<@&${id}>`,
  ...overrides,
});

describe('/equinox setup', () => {
  it('saves the channel and roles, refreshes the cache and audits the change', async () => {
    const t = createFakeContext();
    const { interaction, replies } = fakeCommand(
      { sub: 'setup' },
      { alert_channel: channel(), mod_role: role('600000000000000777'), quarantine_role: role('600000000000000888') },
      ADMIN,
    );
    await handleInteraction(interaction, t.ctx);
    const update = { alertChannelId: CHANNEL_ID, modRoleIds: ['600000000000000777'], quarantineRoleId: '600000000000000888' };
    expect(t.stores.guilds.configure).toHaveBeenCalledWith(TENANT, update);
    expect(t.guildCache.invalidate).toHaveBeenCalledWith(TENANT);
    expect(t.fake.audit.at(-1)).toMatchObject({ action: 'settings.setup', details: update });
    expect(replyText(replies)).toMatch(/Alerts will go to/);
  });

  it('refuses a channel it cannot post alerts in', async () => {
    const t = createFakeContext();
    const noEmbeds = new PermissionsBitField([PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages]);
    for (const alert_channel of [channel(noEmbeds), channel(alertPerms, false)]) {
      const { interaction, replies } = fakeCommand({ sub: 'setup' }, { alert_channel }, ADMIN);
      await handleInteraction(interaction, t.ctx);
      expect(replyText(replies)).toMatch(/can’t post in/);
    }
    expect(t.stores.guilds.configure).not.toHaveBeenCalled();
  });

  it('refuses a quarantine role above its own, and @everyone or bot roles as the mod role', async () => {
    const t = createFakeContext();
    const cases = [
      { options: { quarantine_role: role('600000000000000888', { editable: false }) }, reply: /Move my role above it/ },
      { options: { mod_role: role(TENANT) }, reply: /not @everyone or a bot role/ },
      { options: { mod_role: role('600000000000000777', { managed: true }) }, reply: /not @everyone or a bot role/ },
    ];
    for (const { options, reply } of cases) {
      const { interaction, replies } = fakeCommand({ sub: 'setup' }, { alert_channel: channel(), ...options }, ADMIN);
      await handleInteraction(interaction, t.ctx);
      expect(replyText(replies)).toMatch(reply);
    }
    expect(t.stores.guilds.configure).not.toHaveBeenCalled();
  });

  it('is admin-only', async () => {
    const t = createFakeContext();
    const { interaction, replies } = fakeCommand({ sub: 'setup' }, { alert_channel: channel() }, MOD);
    await handleInteraction(interaction, t.ctx);
    expect(replyText(replies)).toMatch(/don’t have permission/);
    expect(t.stores.guilds.configure).not.toHaveBeenCalled();
  });
});

describe('/equinox status', () => {
  it('shows the settings and every missing permission', async () => {
    const t = createFakeContext();
    const { interaction, raw, replies } = fakeCommand({ sub: 'status' }, {}, MOD);
    raw.guild = { name: 'Test server', members: { me: { permissions: new PermissionsBitField([PermissionFlagsBits.ViewChannel]) } } } as never;
    await handleInteraction(interaction, t.ctx);
    const text = replyText(replies);
    expect(text).toMatch(/alert_only/);
    expect(text).toMatch(/ManageMessages/);
    expect(text).not.toMatch(/ViewChannel,/);
  });
});

describe('other commands', () => {
  it('lists the allowlist, or says it is empty', async () => {
    const t = createFakeContext();
    const empty = fakeCommand({ sub: 'list', group: 'allow' }, {}, MOD);
    await handleInteraction(empty.interaction, t.ctx);
    expect(replyText(empty.replies)).toMatch(/allowlist is empty/);

    t.allowlist.add(`${TENANT}:example.com`);
    const listed = fakeCommand({ sub: 'list', group: 'allow' }, {}, MOD);
    await handleInteraction(listed.interaction, t.ctx);
    expect(replyText(listed.replies)).toContain('example.com');
  });

  it('answers unknown subcommands, and only for admins', async () => {
    const t = createFakeContext();
    const { interaction, replies } = fakeCommand({ sub: 'bogus' }, {}, ADMIN);
    await handleInteraction(interaction, t.ctx);
    expect(replyText(replies)).toMatch(/Unknown command/);
  });

  it('tells mods when a check input is not a URL', async () => {
    const t = createFakeContext();
    const { interaction, replies } = fakeCommand({ sub: 'check' }, { url: '!!!' }, MOD);
    await handleInteraction(interaction, t.ctx);
    expect(replyText(replies)).toMatch(/doesn’t look like a URL/);
  });

  it('still answers a check when the intel queue is down', async () => {
    const t = createFakeContext();
    t.intel.lookup.mockRejectedValueOnce(new Error('redis down'));
    const { interaction, replies } = fakeCommand({ sub: 'check' }, { url: 'https://unknown-site.test/' }, MOD);
    await handleInteraction(interaction, t.ctx);
    expect(replyText(replies)).toMatch(/No known issues/);
    expect(t.logger.warn).toHaveBeenCalledWith(expect.anything(), 'could not queue intel lookup');
  });
});

describe('when something breaks', () => {
  it('gives the user a reference ID, never the error, and logs the details', async () => {
    const t = createFakeContext();
    t.stores.guilds.configure.mockRejectedValueOnce(new Error('connection to 10.0.0.5:5432 refused, password=hunter2'));
    const { interaction, replies } = fakeCommand({ sub: 'setup' }, { alert_channel: channel() }, ADMIN);
    await handleInteraction(interaction, t.ctx);
    const text = replyText(replies);
    expect(text).toMatch(/Something went wrong \(ref `[\w-]+`\)/);
    expect(text).not.toMatch(/10\.0\.0\.5|hunter2|refused/);
    const [fields, message] = t.logger.error.mock.calls[0] as [{ ref: unknown }, string];
    expect(message).toBe('interaction failed');
    expect(typeof fields.ref).toBe('string');
  });

  it('ignores interactions outside a server and other interaction types', async () => {
    const t = createFakeContext();
    const dm = fakeCommand({ sub: 'status' }, {}, ADMIN);
    dm.raw.inCachedGuild = () => false;
    await handleInteraction(dm.interaction, t.ctx);
    const other = fakeCommand({ sub: 'status' }, {}, ADMIN);
    (other.raw as unknown as { isChatInputCommand: () => boolean }).isChatInputCommand = () => false;
    await handleInteraction(other.interaction, t.ctx);
    expect(dm.replies).toHaveLength(0);
    expect(other.replies).toHaveLength(0);
  });
});
