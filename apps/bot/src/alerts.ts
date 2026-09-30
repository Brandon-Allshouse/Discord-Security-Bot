import {
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle,
  EmbedBuilder,
  escapeMarkdown,
  type MessageCreateOptions,
} from 'discord.js';
import {
  defang,
  REVIEW_DECISIONS,
  truncate,
  type ActionOutcome,
  type Detection,
  type DetectionStatus,
  type GuildMode,
  type ReviewDecision,
  type SignalKind,
  type VerdictLevel,
} from '@equinox/core';

const KIND_LABEL: Record<SignalKind, string> = {
  url: 'link',
  file: 'file',
  message_fingerprint: 'spam message',
  member_join: 'join',
  report: 'report',
};

const COLOR = { malicious: 0xd83c3e, suspicious: 0xf0b232, clean: 0x23a55a, resolved: 0x80848e } as const;

const STATUS_LABEL: Record<DetectionStatus, string> = {
  open: 'Open',
  confirmed: 'Confirmed',
  false_positive: 'Marked false positive',
  restored: 'Restored',
};

/** Text shown to mods: markdown-escaped, backticks neutralized, length-capped. */
function safeText(value: string, max: number): string {
  return truncate(escapeMarkdown(value).replace(/`/g, 'ˋ'), max);
}

function safeCode(value: string, max: number): string {
  return `\`${truncate(value.replace(/`/g, 'ˋ'), max)}\``;
}

function formatOutcomes(outcomes: readonly ActionOutcome[]): string {
  if (outcomes.length === 0) return 'None';
  return outcomes
    .map((o) => `${o.ok ? '✅' : '❌'} ${o.action}${o.detail ? ` (${safeText(o.detail, 80)})` : ''}`)
    .join('\n');
}

/** Intel sources that are not the sensor's own checks, for the "found by threat intel" note. */
const LOCAL_SOURCES = new Set(['heuristic', 'allowlist', 'blocklist']);

export function buildAlertEmbed(
  detection: Detection,
  mode: GuildMode,
  outcomes: readonly ActionOutcome[],
  escalatedFrom?: VerdictLevel,
) {
  const { verdict } = detection;
  const level = verdict.level === 'malicious' ? 'Malicious' : 'Suspicious';
  const subject = detection.signalKind === 'url' ? defang(detection.subject) : detection.subject;
  const intelSources = verdict.sources.filter((s) => !LOCAL_SOURCES.has(s));
  const title = escalatedFrom
    ? `⬆️ Now ${level.toLowerCase()}: ${KIND_LABEL[detection.signalKind]} updated by threat intel`
    : `${verdict.level === 'malicious' ? '🚨' : '⚠️'} ${level} ${KIND_LABEL[detection.signalKind]} detected`;

  const embed = new EmbedBuilder()
    .setTitle(title)
    .setColor(COLOR[verdict.level])
    .addFields(
      ...(escalatedFrom
        ? [
            {
              name: 'Update',
              value: `This detection was ${escalatedFrom} until threat intel came back (${intelSources.join(', ') || 'intel'}). Same detection, same buttons; this alert shows the new verdict.`,
            },
          ]
        : intelSources.length > 0
          ? [{ name: 'Threat intel', value: `Found by ${intelSources.join(', ')}` }]
          : []),
      { name: 'User', value: `<@${detection.userId}> (${detection.userId})`, inline: true },
      ...(detection.channelId ? [{ name: 'Channel', value: `<#${detection.channelId}>`, inline: true }] : []),
      { name: 'Score', value: `${Math.round(verdict.score * 100)}% · ${verdict.sources.join(', ')}`, inline: true },
      { name: 'Subject', value: safeCode(subject, 500) },
      {
        name: 'Why',
        value: verdict.reasons.length ? safeText(verdict.reasons.map((r) => `• ${r}`).join('\n'), 1000) : '—',
      },
      { name: 'Actions taken', value: formatOutcomes(outcomes) },
    )
    .setFooter({ text: `Mode: ${mode} · Detection ${detection.id}` })
    .setTimestamp(detection.createdAt);

  return embed;
}

export function buildAlertMessage(
  detection: Detection,
  mode: GuildMode,
  outcomes: readonly ActionOutcome[],
  escalatedFrom?: VerdictLevel,
): MessageCreateOptions {
  const buttons = new ActionRowBuilder<ButtonBuilder>().addComponents(
    new ButtonBuilder().setCustomId(reviewCustomId('restore', detection.id)).setLabel('Restore').setStyle(ButtonStyle.Secondary),
    new ButtonBuilder()
      .setCustomId(reviewCustomId('false_positive', detection.id))
      .setLabel('Mark false positive')
      .setStyle(ButtonStyle.Secondary),
    new ButtonBuilder().setCustomId(reviewCustomId('confirm', detection.id)).setLabel('Confirm').setStyle(ButtonStyle.Danger),
  );
  return {
    embeds: [buildAlertEmbed(detection, mode, outcomes, escalatedFrom)],
    components: [buttons],
    // Alerts never ping anyone, whatever ends up in the text.
    allowedMentions: { parse: [] },
  };
}

/** Marks an alert as resolved: recolors, records who decided, removes the buttons. */
export function resolvedAlertEmbed(original: EmbedBuilder, status: DetectionStatus, actorId: string, note?: string) {
  return original
    .setColor(COLOR.resolved)
    .addFields({ name: 'Review', value: `${STATUS_LABEL[status]} by <@${actorId}>${note ? `\n${note}` : ''}` });
}

const CUSTOM_ID = /^eq:(restore|false_positive|confirm):([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/;

export function reviewCustomId(decision: ReviewDecision, detectionId: string): string {
  return `eq:${decision}:${detectionId}`;
}

/** Strict parse of button IDs: the client controls this string, so treat it as untrusted. */
export function parseReviewCustomId(customId: string): { decision: ReviewDecision; detectionId: string } | null {
  const match = CUSTOM_ID.exec(customId);
  if (!match) return null;
  const decision = match[1] as ReviewDecision;
  if (!REVIEW_DECISIONS.includes(decision)) return null;
  return { decision, detectionId: match[2]! };
}
