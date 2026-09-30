import type { IntelSummary } from './intel/types.js';
import type { ActionKind, ActionOutcome, Detection, DetectionStatus, GuildSettings, Signal, Verdict, VerdictLevel } from './types.js';

/** Interfaces the pipeline depends on. Implemented by @equinox/db and the bot. */

export interface GuildRepository {
  get(guildId: string): Promise<GuildSettings | null>;
}

export interface IndicatorLookup {
  isAllowlisted(guildId: string, signal: Signal): Promise<boolean>;
  isBlocklisted(signal: Signal): Promise<boolean>;
}

/** Cached threat intel. Only reads caches; lookups that take time happen in the intel worker. */
export interface IntelLookup {
  summaryFor(signal: Signal): Promise<IntelSummary | null>;
}

export interface NewDetection {
  signal: Signal;
  verdict: Verdict;
}

export interface DetectionRepository {
  create(input: NewDetection): Promise<Detection>;
  recordOutcomes(guildId: string, detectionId: string, outcomes: ActionOutcome[]): Promise<void>;
  /** Looked up by guild too, so a detection ID from another server finds nothing. */
  get(guildId: string, detectionId: string): Promise<Detection | null>;
  setStatus(guildId: string, detectionId: string, status: DetectionStatus, actorId: string): Promise<void>;
  /** The detection for one subject in one message, if there is one. */
  findForMessage(guildId: string, messageId: string, subject: string): Promise<Detection | null>;
  /** Replaces the verdict after late intel made it worse. */
  updateVerdict(guildId: string, detectionId: string, verdict: Verdict): Promise<void>;
}

export interface AuditEntry {
  guildId: string;
  /** 'bot' or a Discord user ID. */
  actor: string;
  action: string;
  target: string | null;
  details: Record<string, unknown>;
}

export interface AuditLog {
  write(entry: AuditEntry): Promise<void>;
}

export interface ActionContext {
  guild: GuildSettings;
  detection: Detection;
  /** Outcomes of actions already taken for this detection, for the alert. */
  previous: readonly ActionOutcome[];
  /** Set when late threat intel made an existing detection worse: the verdict it had before. */
  escalatedFrom?: VerdictLevel;
}

export interface ActionExecutor {
  execute(action: ActionKind, context: ActionContext): Promise<ActionOutcome>;
  revert(action: ActionKind, guild: GuildSettings, detection: Detection): Promise<ActionOutcome>;
}

export interface PipelineDeps {
  guilds: GuildRepository;
  indicators: IndicatorLookup;
  detections: DetectionRepository;
  audit: AuditLog;
  executor: ActionExecutor;
  /** Optional: without it (or when it fails), verdicts use local information only. */
  intel?: IntelLookup;
}
