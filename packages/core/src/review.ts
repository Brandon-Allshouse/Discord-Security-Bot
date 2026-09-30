import { safeErrorMessage } from './errors.js';
import { REVERSIBLE_ACTIONS } from './policy.js';
import type { PipelineDeps } from './ports.js';
import type { ActionOutcome, Detection, DetectionStatus } from './types.js';

export const REVIEW_DECISIONS = ['restore', 'false_positive', 'confirm'] as const;
export type ReviewDecision = (typeof REVIEW_DECISIONS)[number];

const STATUS_FOR: Record<ReviewDecision, DetectionStatus> = {
  restore: 'restored',
  false_positive: 'false_positive',
  confirm: 'confirmed',
};

const TERMINAL: ReadonlySet<DetectionStatus> = new Set(['restored', 'false_positive']);

export type ReviewResult =
  | { status: 'not_found' }
  | { status: 'already_resolved'; detection: Detection }
  | { status: 'done'; detection: Detection; reverted: ActionOutcome[] };

/**
 * Applies a moderator's decision. This doesn't check permissions, so call
 * canModerate first.
 *
 * - restore / false_positive: undo every reversible action that succeeded
 * - confirm: keep actions, mark confirmed (feeds the network from M5)
 */
export async function reviewDetection(
  input: {
    guildId: string;
    detectionId: string;
    decision: ReviewDecision;
    actorId: string;
    /** Where the decision was made, for the audit log. */
    via?: 'discord' | 'dashboard';
  },
  deps: Pick<PipelineDeps, 'guilds' | 'detections' | 'audit' | 'executor'>,
): Promise<ReviewResult> {
  const [guild, detection] = await Promise.all([
    deps.guilds.get(input.guildId),
    deps.detections.get(input.guildId, input.detectionId),
  ]);
  if (!guild || !detection) return { status: 'not_found' };
  if (TERMINAL.has(detection.status)) return { status: 'already_resolved', detection };

  const reverted: ActionOutcome[] = [];
  if (input.decision !== 'confirm') {
    for (const taken of detection.actionsTaken) {
      if (!taken.ok || !REVERSIBLE_ACTIONS.has(taken.action)) continue;
      try {
        reverted.push(await deps.executor.revert(taken.action, guild, detection));
      } catch (error) {
        reverted.push({ action: taken.action, ok: false, detail: safeErrorMessage(error) });
      }
    }
  }

  const status = STATUS_FOR[input.decision];
  await deps.detections.setStatus(input.guildId, input.detectionId, status, input.actorId);
  await deps.audit.write({
    guildId: input.guildId,
    actor: input.actorId,
    action: `review.${input.decision}`,
    target: detection.userId,
    details: { detectionId: detection.id, reverted, via: input.via ?? 'discord' },
  });

  return { status: 'done', detection: { ...detection, status }, reverted };
}

/**
 * Who counts as a moderator: anyone with Manage Server, or anyone holding one of the
 * server's mod roles. Everyone else is turned away.
 */
export function canModerate(
  member: { hasManageGuild: boolean; roleIds: readonly string[] },
  modRoleIds: readonly string[],
): boolean {
  if (member.hasManageGuild) return true;
  return member.roleIds.some((roleId) => modRoleIds.includes(roleId));
}
