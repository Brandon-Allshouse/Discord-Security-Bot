import { randomUUID } from 'node:crypto';
import { EmbedBuilder, type Client, type GuildTextBasedChannel } from 'discord.js';
import {
  BRAND,
  normalizeUrl,
  processSignal,
  reviewDetection,
  slash,
  type ActionOutcome,
  type Detection,
  type DetectionStatus,
  type PipelineResult,
  type ReviewDecision,
  type ReviewResult,
} from '@equinox/core';
import { resolvedAlertEmbed } from './alerts.js';
import type { BotContext } from './context.js';
import { canPostAlerts } from './permissions.js';

/*
 * The moderation actions that both Discord (commands, buttons) and the dashboard can start.
 * Keeping them here means the two can't drift apart: same checks, same audit entries.
 */

export type Via = 'discord' | 'dashboard';

export interface ReviewInput {
  guildId: string;
  detectionId: string;
  decision: ReviewDecision;
  actorId: string;
  via: Via;
}

/**
 * Applies a review decision, then the follow-ups: a false positive on a link allowlists that
 * exact host. Returns notes for the alert (what was undone, what wasn't possible).
 */
export async function reviewWithFollowUps(
  input: ReviewInput,
  ctx: Pick<BotContext, 'deps' | 'stores'>,
): Promise<{ result: ReviewResult; notes: string[] }> {
  const result = await reviewDetection(input, ctx.deps);
  if (result.status !== 'done') return { result, notes: [] };

  const notes = result.reverted.map((r) => `${r.ok ? '↩️' : '❌'} undo ${r.action}${r.detail ? ` (${r.detail})` : ''}`);

  // Discord has no undelete and we don't keep message text, so say so instead of implying it came back.
  if (input.decision !== 'confirm' && result.detection.actionsTaken.some((a) => a.action === 'delete' && a.ok)) {
    notes.push(`⚠️ The deleted message can’t be brought back. <@${result.detection.userId}> has to post it again.`);
  }

  // A false positive on a link means that host is fine here: allowlist it so it isn't flagged again.
  // Exact host only, never the parent domain, so one click can't open up every subdomain.
  if (input.decision === 'false_positive' && result.detection.signalKind === 'url') {
    const normalized = normalizeUrl(result.detection.subject);
    if (normalized?.domain) {
      await ctx.stores.allowlist.add({ guildId: input.guildId, type: 'domain', value: normalized.host, addedBy: input.actorId });
      await ctx.stores.audit.write({
        guildId: input.guildId,
        actor: input.actorId,
        action: 'allowlist.add',
        target: normalized.host,
        details: { via: 'false_positive', detectionId: result.detection.id, from: input.via },
      });
      notes.push(`Allowlisted \`${normalized.host}\` in this server`);
    }
  }
  return { result, notes };
}

/** Alert messages posted for a detection (the first alert, plus any escalation alerts). */
export function alertRefs(actions: readonly ActionOutcome[]): { channelId: string; messageId: string }[] {
  return actions.filter((a) => a.action === 'alert' && a.ok && a.ref).map((a) => a.ref!);
}

/**
 * Marks a detection's alerts in Discord as resolved and removes their buttons, so nobody acts on
 * a stale alert. Best effort: an alert someone deleted is skipped. Returns how many were updated.
 */
export async function resolveAlertMessages(
  client: Pick<Client, 'channels'>,
  detection: Detection,
  status: DetectionStatus,
  actorId: string,
  note: string,
  skipMessageId?: string,
): Promise<number> {
  let updated = 0;
  for (const ref of alertRefs(detection.actionsTaken)) {
    if (ref.messageId === skipMessageId) continue;
    try {
      const channel = await client.channels.fetch(ref.channelId);
      if (!channel?.isTextBased()) continue;
      const message = await channel.messages.fetch(ref.messageId);
      const original = message.embeds[0];
      if (!original) continue;
      await message.edit({
        embeds: [resolvedAlertEmbed(EmbedBuilder.from(original), status, actorId, note)],
        components: [],
        allowedMentions: { parse: [] },
      });
      updated++;
    } catch {
      // Deleted alert or lost access: nothing to update.
    }
  }
  return updated;
}

export type SetupProblem = 'setup_bad_channel' | 'setup_bad_mod_role' | 'setup_bad_quarantine_role';

/**
 * The same rules for /equinox setup and the dashboard: the bot must be able to post alerts in
 * the channel, hand out the quarantine role, and the mod role must be a real role.
 */
export function setupProblem(
  guildId: string,
  channel: { isTextBased(): boolean } | null,
  modRole: { id: string; managed: boolean } | null,
  quarantineRole: { editable: boolean } | null,
): SetupProblem | null {
  if (!channel || !channel.isTextBased() || !canPostAlerts(channel as GuildTextBasedChannel)) return 'setup_bad_channel';
  if (quarantineRole && !quarantineRole.editable) return 'setup_bad_quarantine_role';
  if (modRole && (modRole.managed || modRole.id === guildId)) return 'setup_bad_mod_role';
  return null;
}

export async function saveSetup(
  ctx: Pick<BotContext, 'stores' | 'guildCache'>,
  input: { guildId: string; actorId: string; alertChannelId: string; modRoleId: string | null; quarantineRoleId: string | null; via: Via },
): Promise<void> {
  const update = {
    alertChannelId: input.alertChannelId,
    ...(input.modRoleId ? { modRoleIds: [input.modRoleId] } : {}),
    ...(input.quarantineRoleId ? { quarantineRoleId: input.quarantineRoleId } : {}),
  };
  await ctx.stores.guilds.configure(input.guildId, update);
  ctx.guildCache.invalidate(input.guildId);
  await ctx.stores.audit.write({
    guildId: input.guildId,
    actor: input.actorId,
    action: 'settings.setup',
    target: null,
    details: { ...update, via: input.via },
  });
}

/** A harmless test signal through the whole pipeline, as /equinox test and the dashboard send it. */
export function sendTestSignal(
  ctx: Pick<BotContext, 'deps'>,
  input: { guildId: string; actorId: string; channelId?: string; via: Via },
): Promise<PipelineResult> {
  return processSignal(
    {
      id: randomUUID(),
      kind: 'url',
      guildId: input.guildId,
      userId: input.actorId,
      ...(input.channelId ? { channelId: input.channelId } : {}),
      subject: `https://${BRAND.testDomain}/`,
      heuristicScore: 0.9,
      reasons: [input.via === 'dashboard' ? `Test signal sent from the ${BRAND.name} dashboard` : `Test signal sent by ${slash('test')}`],
      createdAt: new Date(),
    },
    ctx.deps,
  );
}
