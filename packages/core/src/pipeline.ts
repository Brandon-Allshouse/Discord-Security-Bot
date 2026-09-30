import { safeErrorMessage } from './errors.js';
import type { IntelSummary } from './intel/types.js';
import { actionsFor } from './policy.js';
import type { PipelineDeps } from './ports.js';
import {
  signalSchema,
  type ActionKind,
  type ActionOutcome,
  type Detection,
  type GuildSettings,
  type Signal,
  type Verdict,
  type VerdictLevel,
} from './types.js';
import { decideVerdict, isWorse } from './verdict.js';

export type PipelineResult =
  | { status: 'ignored'; reason: 'guild_not_registered' }
  /** `needsIntel`: nothing is known about the subject yet, so it's worth an intel lookup. */
  | { status: 'clean'; verdict: Verdict; needsIntel: boolean }
  | { status: 'detected'; verdict: Verdict; detection: Detection; outcomes: ActionOutcome[]; needsIntel: boolean };

export type ReevaluationResult =
  | { status: 'ignored'; reason: 'guild_not_registered' | 'no_message' }
  | { status: 'unchanged'; verdict: Verdict }
  | { status: 'detected'; verdict: Verdict; detection: Detection; outcomes: ActionOutcome[] }
  | { status: 'escalated'; verdict: Verdict; detection: Detection; outcomes: ActionOutcome[] };

/**
 * The one pipeline: Signal -> Verdict -> Action -> Audit. Every detector goes through here.
 * `raw` is validated first, so callers can't skip validation.
 */
export async function processSignal(raw: unknown, deps: PipelineDeps): Promise<PipelineResult> {
  const signal = signalSchema.parse(raw);

  const guild = await deps.guilds.get(signal.guildId);
  if (!guild) return { status: 'ignored', reason: 'guild_not_registered' };

  const { verdict, needsIntel } = await judge(signal, deps);
  if (verdict.level === 'clean') return { status: 'clean', verdict, needsIntel };

  const { detection, outcomes } = await detect(signal, verdict, guild, deps);
  return { status: 'detected', verdict, detection, outcomes, needsIntel };
}

/**
 * Runs a signal through the pipeline again once intel about it has arrived.
 * - No detection yet for this message and subject: behaves like processSignal.
 * - An open detection whose verdict just got worse: escalates it, runs the actions the new
 *   verdict adds, and posts a fresh alert.
 * - Anything else (same verdict, or mods already handled it): does nothing.
 */
export async function reevaluateSignal(raw: unknown, deps: PipelineDeps): Promise<ReevaluationResult> {
  const signal = signalSchema.parse(raw);
  if (!signal.messageId) return { status: 'ignored', reason: 'no_message' };

  const guild = await deps.guilds.get(signal.guildId);
  if (!guild) return { status: 'ignored', reason: 'guild_not_registered' };

  const [{ verdict }, existing] = await Promise.all([
    judge(signal, deps),
    deps.detections.findForMessage(guild.id, signal.messageId, signal.subject),
  ]);

  if (!existing) {
    if (verdict.level === 'clean') return { status: 'unchanged', verdict };
    const { detection, outcomes } = await detect(signal, verdict, guild, deps);
    return { status: 'detected', verdict, detection, outcomes };
  }

  // Mods have already decided, or the new verdict isn't worse: leave it alone.
  if (existing.status !== 'open' || !isWorse(verdict.level, existing.verdict.level)) {
    return { status: 'unchanged', verdict };
  }

  await deps.detections.updateVerdict(guild.id, existing.id, verdict);
  await deps.audit.write({
    guildId: guild.id,
    actor: 'bot',
    action: 'detection.escalated',
    target: signal.userId,
    details: {
      detectionId: existing.id,
      from: existing.verdict.level,
      to: verdict.level,
      score: verdict.score,
      sources: verdict.sources,
      mode: guild.mode,
    },
  });

  // Only what the new verdict adds, plus a fresh alert so mods see the new verdict.
  const already = new Set(actionsFor(guild.mode, signal.kind, existing.verdict.level));
  const actions = actionsFor(guild.mode, signal.kind, verdict.level).filter((a) => a === 'alert' || !already.has(a));
  const detection: Detection = { ...existing, verdict };
  const outcomes = await runActions(actions, guild, detection, deps, existing.verdict.level);
  const actionsTaken = [...existing.actionsTaken, ...outcomes];
  await deps.detections.recordOutcomes(guild.id, existing.id, actionsTaken);
  return { status: 'escalated', verdict, detection: { ...detection, actionsTaken }, outcomes };
}

async function judge(signal: Signal, deps: PipelineDeps): Promise<{ verdict: Verdict; needsIntel: boolean }> {
  const [allowlisted, blocklisted, intel] = await Promise.all([
    deps.indicators.isAllowlisted(signal.guildId, signal),
    deps.indicators.isBlocklisted(signal),
    cachedIntel(signal, deps),
  ]);
  const verdict = decideVerdict(signal, { allowlisted, blocklisted, intel });
  const needsIntel = deps.intel !== undefined && !allowlisted && !blocklisted && intel === null;
  return { verdict, needsIntel };
}

/** Intel is an extra, never a dependency: if the cache can't be read, judge on local information. */
async function cachedIntel(signal: Signal, deps: PipelineDeps): Promise<IntelSummary | null> {
  if (!deps.intel) return null;
  try {
    return await deps.intel.summaryFor(signal);
  } catch {
    return null;
  }
}

async function detect(signal: Signal, verdict: Verdict, guild: GuildSettings, deps: PipelineDeps) {
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

  const outcomes = await runActions(actionsFor(guild.mode, signal.kind, verdict.level), guild, detection, deps);
  await deps.detections.recordOutcomes(guild.id, detection.id, outcomes);
  return { detection: { ...detection, actionsTaken: outcomes }, outcomes };
}

async function runActions(
  actions: readonly ActionKind[],
  guild: GuildSettings,
  detection: Detection,
  deps: PipelineDeps,
  escalatedFrom?: VerdictLevel,
): Promise<ActionOutcome[]> {
  const outcomes: ActionOutcome[] = [];
  for (const action of actions) {
    let outcome: ActionOutcome;
    try {
      outcome = await deps.executor.execute(action, {
        guild,
        detection,
        previous: outcomes,
        ...(escalatedFrom ? { escalatedFrom } : {}),
      });
    } catch (error) {
      // One failed action must not stop the rest (especially the alert).
      outcome = { action, ok: false, detail: safeErrorMessage(error) };
    }
    outcomes.push(outcome);
    await deps.audit.write({
      guildId: guild.id,
      actor: 'bot',
      action: `action.${action}`,
      target: detection.userId,
      details: { detectionId: detection.id, ok: outcome.ok, detail: outcome.detail ?? null },
    });
  }
  return outcomes;
}
