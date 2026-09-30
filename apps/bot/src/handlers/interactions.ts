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
  defang,
  domainCandidates,
  findLinks,
  GUILD_MODES,
  normalizeUrl,
  parseDomainInput,
  processSignal,
  reviewDetection,
  slash,
  THRESHOLDS,
  truncate,
  type GuildMode,
  type GuildSettings,
} from '@equinox/core';
import { parseReviewCustomId, resolvedAlertEmbed } from '../alerts.js';
import { isAuthorized, requiredAccess, type MemberAccess } from '../authz.js';
import type { BotContext } from '../context.js';
import { canPostAlerts, missingGuildPermissions } from '../permissions.js';

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

  if (!channel.isTextBased() || !canPostAlerts(channel)) {
    await interaction.reply(ephemeral(`I can’t post in ${channel.toString()}. I need View Channel, Send Messages and Embed Links there.`));
    return;
  }
  if (quarantineRole && !quarantineRole.editable) {
    await interaction.reply(ephemeral(`I can’t manage ${quarantineRole.toString()}. Move my role above it.`));
    return;
  }
  if (modRole?.managed || modRole?.id === interaction.guildId) {
    await interaction.reply(ephemeral('Pick a regular role for moderators, not @everyone or a bot role.'));
    return;
  }

  const update = {
    alertChannelId: channel.id,
    ...(modRole ? { modRoleIds: [modRole.id] } : {}),
    ...(quarantineRole ? { quarantineRoleId: quarantineRole.id } : {}),
  };
  await ctx.stores.guilds.configure(interaction.guildId, update);
  ctx.guildCache.invalidate(interaction.guildId);
  await ctx.stores.audit.write({
    guildId: interaction.guildId,
    actor: interaction.user.id,
    action: 'settings.setup',
    target: null,
    details: update,
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
  const result = await processSignal(
    {
      id: randomUUID(),
      kind: 'url',
      guildId: interaction.guildId,
      userId: interaction.user.id,
      channelId: interaction.channelId,
      subject: `https://${BRAND.testDomain}/`,
      heuristicScore: 0.9,
      reasons: [`Test signal sent by ${slash('test')}`],
      createdAt: new Date(),
    },
    ctx.deps,
  );
  if (result.status !== 'detected') {
    await interaction.editReply(`Test signal was not detected (${result.status}).`);
    return;
  }
  const summary = result.outcomes.map((o) => `${o.ok ? '✅' : '❌'} ${o.action}${o.detail ? ` (${o.detail})` : ''}`);
  await interaction.editReply(`Test signal processed. Detection \`${result.detection.id}\`\n${summary.join('\n')}`);
}

async function check(interaction: ChatInputCommandInteraction<'cached'>, ctx: BotContext): Promise<void> {
  const input = interaction.options.getString('url', true);
  const [finding] = findLinks(input.includes('://') ? input : `http://${input}`);
  if (!finding) {
    await interaction.reply(ephemeral('That doesn’t look like a URL.'));
    return;
  }
  const candidates = domainCandidates(finding.normalized);
  const [blocked, allowed] = await Promise.all([
    ctx.indicators.isDomainBlocklisted(candidates),
    ctx.stores.allowlist.hasAny(interaction.guildId, 'domain', candidates),
  ]);
  const level = allowed
    ? 'Clean (allowlisted here)'
    : blocked
      ? `Malicious (on the ${BRAND.name} blocklist)`
      : finding.score >= THRESHOLDS.malicious
        ? 'Malicious'
        : finding.score >= THRESHOLDS.suspicious
          ? 'Suspicious'
          : 'No known issues';
  const reasons = finding.reasons.length ? finding.reasons.map((r) => `• ${r}`).join('\n') : '';
  await interaction.reply(
    ephemeral(
      truncate(
        `\`${defang(finding.normalized.url).replace(/`/g, 'ˋ')}\`\n**${level}** · score ${Math.round(finding.score * 100)}%\n${reasons}`,
        1900,
      ),
    ),
  );
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
  const result = await reviewDetection(
    { guildId: interaction.guildId, detectionId: parsed.detectionId, decision: parsed.decision, actorId: interaction.user.id },
    ctx.deps,
  );

  if (result.status === 'not_found') {
    await interaction.followUp(ephemeral('That detection no longer exists.'));
    return;
  }
  if (result.status === 'already_resolved') {
    await interaction.followUp(ephemeral('That alert was already resolved.'));
    return;
  }

  const notes: string[] = result.reverted.map((r) => `${r.ok ? '↩️' : '❌'} undo ${r.action}${r.detail ? ` (${r.detail})` : ''}`);

  // Discord has no undelete and we don't keep message text, so say so instead of implying it came back.
  if (parsed.decision !== 'confirm' && result.detection.actionsTaken.some((a) => a.action === 'delete' && a.ok)) {
    notes.push(`⚠️ The deleted message can’t be brought back. <@${result.detection.userId}> has to post it again.`);
  }

  // A false positive on a link means that host is fine here: allowlist it so it isn't flagged again.
  // Exact host only, never the parent domain, so one click can't open up every subdomain.
  if (parsed.decision === 'false_positive' && result.detection.signalKind === 'url') {
    const normalized = normalizeUrl(result.detection.subject);
    if (normalized?.domain) {
      await ctx.stores.allowlist.add({
        guildId: interaction.guildId,
        type: 'domain',
        value: normalized.host,
        addedBy: interaction.user.id,
      });
      await ctx.stores.audit.write({
        guildId: interaction.guildId,
        actor: interaction.user.id,
        action: 'allowlist.add',
        target: normalized.host,
        details: { via: 'false_positive', detectionId: result.detection.id },
      });
      notes.push(`Allowlisted \`${normalized.host}\` in this server`);
    }
  }

  const original = interaction.message.embeds[0];
  if (original) {
    const embed = resolvedAlertEmbed(EmbedBuilder.from(original), result.detection.status, interaction.user.id, notes.join('\n'));
    await interaction.editReply({ embeds: [embed], components: [], allowedMentions: { parse: [] } });
  }
}
