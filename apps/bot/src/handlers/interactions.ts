import { randomUUID } from 'node:crypto';
import {
  EmbedBuilder,
  MessageFlags,
  PermissionFlagsBits,
  type ButtonInteraction,
  type ChatInputCommandInteraction,
  type Interaction,
} from 'discord.js';
import {
  BRAND,
  checkLink,
  defang,
  domainCandidates,
  GUILD_MODES,
  parseLinkInput,
  parseDomainInput,
  slash,
  truncate,
  type GuildMode,
  type GuildSettings,
  type LinkCheck,
} from '@equinox/core';
import { parseReviewCustomId, resolvedAlertEmbed } from '../alerts.js';
import { isAuthorized, requiredAccess, type MemberAccess } from '../authz.js';
import type { BotContext } from '../context.js';
import { reviewWithFollowUps, resolveAlertMessages, saveSetup, sendTestSignal, setupProblem } from '../moderation.js';
import { missingGuildPermissions } from '../permissions.js';

type CachedInteraction = ChatInputCommandInteraction<'cached'> | ButtonInteraction<'cached'>;

const ephemeral = (content: string) => ({
  content,
  flags: MessageFlags.Ephemeral as const,
  allowedMentions: { parse: [] as never[] },
});

function memberAccess(interaction: CachedInteraction): MemberAccess {
  return {
    hasManageGuild: interaction.memberPermissions.has(PermissionFlagsBits.ManageGuild),
    roleIds: [...interaction.member.roles.cache.keys()],
  };
}

export async function handleInteraction(interaction: Interaction, ctx: BotContext): Promise<void> {
  if (!interaction.isChatInputCommand() && !interaction.isButton()) return;
  if (!interaction.inCachedGuild()) return;

  if (!ctx.limits.interactions.take(interaction.user.id)) {
    await interaction.reply(ephemeral('You’re doing that too fast. Try again in a minute.'));
    return;
  }

  try {
    if (interaction.isChatInputCommand()) await handleCommand(interaction, ctx);
    else await handleButton(interaction, ctx);
  } catch (error) {
    // Full details go to the log. The user just gets a short ref they can pass to us.
    const ref = randomUUID().slice(0, 8);
    ctx.logger.error({ err: error, ref, guildId: interaction.guildId, userId: interaction.user.id }, 'interaction failed');
    const message = ephemeral(`Something went wrong (ref \`${ref}\`).`);
    if (interaction.deferred || interaction.replied) await interaction.followUp(message).catch(() => undefined);
    else await interaction.reply(message).catch(() => undefined);
  }
}

async function handleCommand(interaction: ChatInputCommandInteraction<'cached'>, ctx: BotContext): Promise<void> {
  if (interaction.commandName !== BRAND.command) return;
  const guildId = interaction.guildId;

  let settings = await ctx.guildCache.get(guildId);
  if (!settings) {
    await ctx.stores.guilds.register({ id: guildId, name: interaction.guild.name });
    ctx.guildCache.invalidate(guildId);
    settings = (await ctx.guildCache.get(guildId))!;
  }

  const group = interaction.options.getSubcommandGroup(false);
  const sub = interaction.options.getSubcommand(true);
  const route = group ? `${group}.${sub}` : sub;

  if (!isAuthorized(requiredAccess(route), memberAccess(interaction), settings.modRoleIds)) {
    await ctx.stores.audit.write({
      guildId,
      actor: interaction.user.id,
      action: 'authz.denied',
      target: null,
      details: { command: route },
    });
    await interaction.reply(ephemeral('You don’t have permission to use this command.'));
    return;
  }

  switch (route) {
    case 'setup':
      return setup(interaction, ctx);
    case 'mode':
      return setMode(interaction, ctx, settings);
    case 'status':
      return status(interaction, ctx, settings);
    case 'test':
      return testSignal(interaction, ctx);
    case 'check':
      return check(interaction, ctx);
    case 'allow.add':
    case 'allow.remove':
      return changeAllowlist(interaction, ctx, sub);
    case 'allow.list':
      return listAllowlist(interaction, ctx);
    default:
      await interaction.reply(ephemeral('Unknown command.'));
  }
}

async function setup(interaction: ChatInputCommandInteraction<'cached'>, ctx: BotContext): Promise<void> {
  const channel = interaction.options.getChannel('alert_channel', true);
  const modRole = interaction.options.getRole('mod_role');
  const quarantineRole = interaction.options.getRole('quarantine_role');

  const problem = setupProblem(interaction.guildId, channel, modRole, quarantineRole);
  if (problem === 'setup_bad_channel') {
    await interaction.reply(ephemeral(`I can’t post in ${channel.toString()}. I need View Channel, Send Messages and Embed Links there.`));
    return;
  }
  if (problem === 'setup_bad_quarantine_role') {
    await interaction.reply(ephemeral(`I can’t manage ${quarantineRole!.toString()}. Move my role above it.`));
    return;
  }
  if (problem === 'setup_bad_mod_role') {
    await interaction.reply(ephemeral('Pick a regular role for moderators, not @everyone or a bot role.'));
    return;
  }

  await saveSetup(ctx, {
    guildId: interaction.guildId,
    actorId: interaction.user.id,
    alertChannelId: channel.id,
    modRoleId: modRole?.id ?? null,
    quarantineRoleId: quarantineRole?.id ?? null,
    via: 'discord',
  });
  await interaction.reply(
    ephemeral(
      `Alerts will go to ${channel.toString()}.` +
        (modRole ? ` ${modRole.toString()} can act on alerts.` : '') +
        (quarantineRole ? ` Quarantine role: ${quarantineRole.toString()}.` : ''),
    ),
  );
}

async function setMode(
  interaction: ChatInputCommandInteraction<'cached'>,
  ctx: BotContext,
  settings: GuildSettings,
): Promise<void> {
  const mode = interaction.options.getString('mode', true) as GuildMode;
  if (!GUILD_MODES.includes(mode)) {
    await interaction.reply(ephemeral('Unknown mode.'));
    return;
  }
  const from = settings.mode;
  await ctx.stores.guilds.setMode(interaction.guildId, mode);
  ctx.guildCache.invalidate(interaction.guildId);
  await ctx.stores.audit.write({
    guildId: interaction.guildId,
    actor: interaction.user.id,
    action: 'settings.mode',
    target: null,
    details: { from, to: mode },
  });
  await interaction.reply(ephemeral(`Mode set to **${mode}**.`));
}

async function status(
  interaction: ChatInputCommandInteraction<'cached'>,
  ctx: BotContext,
  settings: GuildSettings,
): Promise<void> {
  const missing = missingGuildPermissions(interaction.guild);
  const open = await ctx.stores.detections.countOpen(interaction.guildId);
  const embed = new EmbedBuilder()
    .setTitle(`${BRAND.name} status`)
    .addFields(
      { name: 'Mode', value: settings.mode, inline: true },
      { name: 'Open detections', value: String(open), inline: true },
      { name: 'Alert channel', value: settings.alertChannelId ? `<#${settings.alertChannelId}>` : `Not set, run \`${slash('setup')}\`` },
      { name: 'Mod roles', value: settings.modRoleIds.map((id) => `<@&${id}>`).join(', ') || 'Manage Server only' },
      { name: 'Quarantine role', value: settings.quarantineRoleId ? `<@&${settings.quarantineRoleId}>` : 'Not set' },
      { name: 'Missing permissions', value: missing.length ? missing.join(', ') : 'None' },
    );
  await interaction.reply({ embeds: [embed], flags: MessageFlags.Ephemeral, allowedMentions: { parse: [] } });
}

async function testSignal(interaction: ChatInputCommandInteraction<'cached'>, ctx: BotContext): Promise<void> {
  await interaction.deferReply({ flags: MessageFlags.Ephemeral });
  const result = await sendTestSignal(ctx, {
    guildId: interaction.guildId,
    actorId: interaction.user.id,
    channelId: interaction.channelId,
    via: 'discord',
  });
  if (result.status !== 'detected') {
    await interaction.editReply(`Test signal was not detected (${result.status}).`);
    return;
  }
  const summary = result.outcomes.map((o) => `${o.ok ? '✅' : '❌'} ${o.action}${o.detail ? ` (${o.detail})` : ''}`);
  await interaction.editReply(`Test signal processed. Detection \`${result.detection.id}\`\n${summary.join('\n')}`);
}

async function check(interaction: ChatInputCommandInteraction<'cached'>, ctx: BotContext): Promise<void> {
  const finding = parseLinkInput(interaction.options.getString('url', true));
  if (!finding) {
    await interaction.reply(ephemeral('That doesn’t look like a URL.'));
    return;
  }
  const candidates = domainCandidates(finding.normalized);
  const [blocklisted, allowlisted, intel] = await Promise.all([
    ctx.indicators.isDomainBlocklisted(candidates),
    ctx.stores.allowlist.hasAny(interaction.guildId, 'domain', candidates),
    ctx.intelCache.forUrl(finding.normalized.url).catch(() => null),
  ]);
  const result = checkLink(finding, { allowlisted, blocklisted, intel });
  if (result.intelState === 'pending') {
    await ctx.intel
      .lookup(result.url, finding.score)
      .catch((err: unknown) =>
        ctx.logger.warn({ err: { message: err instanceof Error ? err.message : 'unknown' } }, 'could not queue intel lookup'),
      );
  }
  await interaction.reply(ephemeral(truncate(formatLinkCheck(result), 1900)));
}

const CHECK_LEVEL: Record<LinkCheck['level'], string> = {
  malicious: 'Malicious',
  suspicious: 'Suspicious',
  clean: 'No known issues',
};

/** The /check reply. Exported for tests. */
export function formatLinkCheck(result: LinkCheck): string {
  const level = result.allowlisted
    ? 'Clean (allowlisted here)'
    : result.blocklisted
      ? `Malicious (on the ${BRAND.name} blocklist)`
      : CHECK_LEVEL[result.level];
  const reasons = result.reasons.map((r) => `• ${r}`).join('\n');
  const intel =
    result.intelState === 'checked'
      ? `Threat intel: ${result.intel?.sources.length ? result.intel.sources.join(', ') : 'no source knows of problems'}`
      : result.intelState === 'pending'
        ? 'Threat intel: not checked yet. Looking it up now; run this again in a minute.'
        : '';
  return [`\`${defang(result.url).replace(/`/g, 'ˋ')}\``, `**${level}** · score ${Math.round(result.score * 100)}%`, reasons, intel]
    .filter((line) => line.length > 0)
    .join('\n');
}

async function changeAllowlist(
  interaction: ChatInputCommandInteraction<'cached'>,
  ctx: BotContext,
  sub: string,
): Promise<void> {
  const domain = parseDomainInput(interaction.options.getString('domain', true));
  if (!domain) {
    await interaction.reply(ephemeral('Enter a domain like `example.com` (no path, no IP address).'));
    return;
  }
  if (sub === 'add') {
    await ctx.stores.allowlist.add({ guildId: interaction.guildId, type: 'domain', value: domain, addedBy: interaction.user.id });
  } else if (!(await ctx.stores.allowlist.remove(interaction.guildId, 'domain', domain))) {
    await interaction.reply(ephemeral(`\`${domain}\` isn’t on the allowlist.`));
    return;
  }
  await ctx.stores.audit.write({
    guildId: interaction.guildId,
    actor: interaction.user.id,
    action: `allowlist.${sub}`,
    target: domain,
    details: {},
  });
  await interaction.reply(ephemeral(sub === 'add' ? `\`${domain}\` won’t be flagged in this server.` : `Removed \`${domain}\`.`));
}

async function listAllowlist(interaction: ChatInputCommandInteraction<'cached'>, ctx: BotContext): Promise<void> {
  const rows = await ctx.stores.allowlist.list(interaction.guildId);
  const text = rows.length ? rows.map((row) => `\`${row.value}\``).join(', ') : 'The allowlist is empty.';
  await interaction.reply(ephemeral(truncate(text, 1900)));
}

async function handleButton(interaction: ButtonInteraction<'cached'>, ctx: BotContext): Promise<void> {
  const parsed = parseReviewCustomId(interaction.customId);
  if (!parsed) return;

  const settings = await ctx.guildCache.get(interaction.guildId);
  if (!settings || !isAuthorized('mod', memberAccess(interaction), settings.modRoleIds)) {
    await ctx.stores.audit.write({
      guildId: interaction.guildId,
      actor: interaction.user.id,
      action: 'authz.denied',
      target: null,
      details: { button: parsed.decision, detectionId: parsed.detectionId },
    });
    await interaction.reply(ephemeral('Only moderators can act on alerts.'));
    return;
  }

  await interaction.deferUpdate();
  const { result, notes } = await reviewWithFollowUps(
    {
      guildId: interaction.guildId,
      detectionId: parsed.detectionId,
      decision: parsed.decision,
      actorId: interaction.user.id,
      via: 'discord',
    },
    ctx,
  );

  if (result.status === 'not_found') {
    await interaction.followUp(ephemeral('That detection no longer exists.'));
    return;
  }
  if (result.status === 'already_resolved') {
    await interaction.followUp(ephemeral('That alert was already resolved.'));
    return;
  }

  // An escalated detection has more than one alert: resolve the others too.
  await resolveAlertMessages(ctx.client, result.detection, result.detection.status, interaction.user.id, notes.join('\n'), interaction.message.id);

  const original = interaction.message.embeds[0];
  if (original) {
    const embed = resolvedAlertEmbed(EmbedBuilder.from(original), result.detection.status, interaction.user.id, notes.join('\n'));
    await interaction.editReply({ embeds: [embed], components: [], allowedMentions: { parse: [] } });
  }
}
