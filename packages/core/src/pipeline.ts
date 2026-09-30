import { safeErrorMessage } from './errors.js';
import { actionsFor } from './policy.js';
import type { PipelineDeps } from './ports.js';
import { signalSchema, type ActionOutcome, type Detection, type Verdict } from './types.js';
import { decideVerdict } from './verdict.js';

export type PipelineResult =
  | { status: 'ignored'; reason: 'guild_not_registered' }
  | { status: 'clean'; verdict: Verdict }
  | { status: 'detected'; verdict: Verdict; detection: Detection; outcomes: ActionOutcome[] };

/**
 * The one pipeline: Signal -> Verdict -> Action -> Audit. Every detector goes through here.
 * `raw` is validated first, so callers can't skip validation.
 */
export async function processSignal(raw: unknown, deps: PipelineDeps): Promise<PipelineResult> {
  const signal = signalSchema.parse(raw);

  const guild = await deps.guilds.get(signal.guildId);
  if (!guild) return { status: 'ignored', reason: 'guild_not_registered' };

  const [allowlisted, blocklisted] = await Promise.all([
    deps.indicators.isAllowlisted(signal.guildId, signal),
    deps.indicators.isBlocklisted(signal),
  ]);
  const verdict = decideVerdict(signal, { allowlisted, blocklisted });
  if (verdict.level === 'clean') return { status: 'clean', verdict };

  const detection = await deps.detections.create({ signal, verdict });
  await deps.audit.write({
    guildId: guild.id,
    actor: 'bot',
    action: 'detection.created',
    target: signal.userId,
    details: {
      detectionId: detection.id,
      kind: signal.kind,
      level: verdict.level,
      score: verdict.score,
      mode: guild.mode,
    },
  });

  const outcomes: ActionOutcome[] = [];
  for (const action of actionsFor(guild.mode, signal.kind, verdict.level)) {
    let outcome: ActionOutcome;
    try {
      outcome = await deps.executor.execute(action, { guild, detection, previous: outcomes });
    } catch (error) {
      // One failed action must not stop the rest (especially the alert).
      outcome = { action, ok: false, detail: safeErrorMessage(error) };
    }
    outcomes.push(outcome);
    await deps.audit.write({
      guildId: guild.id,
      actor: 'bot',
      action: `action.${action}`,
      target: signal.userId,
      details: { detectionId: detection.id, ok: outcome.ok, detail: outcome.detail ?? null },
    });
  }

  await deps.detections.recordOutcomes(guild.id, detection.id, outcomes);
  return { status: 'detected', verdict, detection: { ...detection, actionsTaken: outcomes }, outcomes };
}
