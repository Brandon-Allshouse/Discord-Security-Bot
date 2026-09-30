import { randomUUID } from 'node:crypto';
import type { Message } from 'discord.js';
import { findLinks, processSignal } from '@equinox/core';
import type { BotContext } from '../context.js';

/**
 * Remembers which edits were already scanned. Messages aren't cached, so an update can't be
 * compared with the old text, and link previews loading arrive as updates too.
 * In-memory per shard, bounded by dropping the oldest entry.
 */
export class SeenEdits {
  private readonly seen = new Map<string, number>();

  constructor(private readonly max = 5000) {}

  /** True the first time a given edit of a message shows up. */
  isNew(messageId: string, editedTimestamp: number | null): boolean {
    if (editedTimestamp === null || this.seen.get(messageId) === editedTimestamp) return false;
    this.seen.delete(messageId);
    this.seen.set(messageId, editedTimestamp);
    if (this.seen.size > this.max) this.seen.delete(this.seen.keys().next().value!);
    return true;
  }
}

/**
 * Link detector: every link in a message becomes a url Signal and goes through the pipeline.
 * Stops at the first detection, since the message is handled (and maybe deleted) by then.
 */
export async function scanMessage(message: Message, ctx: BotContext): Promise<void> {
  if (!message.inGuild() || !message.content) return;
  if (message.author.id === ctx.client.user?.id) return;

  const findings = findLinks(message.content);
  for (const finding of findings) {
    const result = await processSignal(
      {
        id: randomUUID(),
        kind: 'url',
        guildId: message.guildId,
        userId: message.author.id,
        channelId: message.channelId,
        messageId: message.id,
        subject: finding.normalized.url,
        heuristicScore: finding.score,
        reasons: finding.reasons,
        createdAt: new Date(),
      },
      ctx.deps,
    );
    if (result.status === 'ignored') return;
    if (result.status === 'detected') {
      ctx.logger.info(
        { guildId: message.guildId, detectionId: result.detection.id, level: result.verdict.level },
        'link detection',
      );
      return;
    }
  }
}
