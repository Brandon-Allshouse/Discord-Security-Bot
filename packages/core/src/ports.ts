import type { ActionKind, ActionOutcome, Detection, DetectionStatus, GuildSettings, Signal, Verdict } from './types.js';

/** Interfaces the pipeline depends on. Implemented by @equinox/db and the bot. */

export interface GuildRepository {
  get(guildId: string): Promise<GuildSettings | null>;
}

export interface IndicatorLookup {
  isAllowlisted(guildId: string, signal: Signal): Promise<boolean>;
  isBlocklisted(signal: Signal): Promise<boolean>;
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
}
