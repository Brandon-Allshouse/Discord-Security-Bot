import { z } from 'zod';

export const SIGNAL_KINDS = ['url', 'file', 'message_fingerprint', 'member_join', 'report'] as const;
export type SignalKind = (typeof SIGNAL_KINDS)[number];

export const VERDICT_LEVELS = ['clean', 'suspicious', 'malicious'] as const;
export type VerdictLevel = (typeof VERDICT_LEVELS)[number];

export const GUILD_MODES = ['alert_only', 'protect', 'strict'] as const;
export type GuildMode = (typeof GUILD_MODES)[number];

export const ACTION_KINDS = ['none', 'alert', 'delete', 'quarantine', 'timeout', 'kick', 'ban'] as const;
export type ActionKind = (typeof ACTION_KINDS)[number];

export const DETECTION_STATUSES = ['open', 'confirmed', 'false_positive', 'restored'] as const;
export type DetectionStatus = (typeof DETECTION_STATUSES)[number];

export const snowflakeSchema = z.string().regex(/^\d{17,20}$/);

/**
 * What every detector produces. The pipeline validates it on the way in, so a buggy
 * detector can't push junk into verdicts, actions or the database.
 */
export const signalSchema = z.object({
  id: z.uuid(),
  kind: z.enum(SIGNAL_KINDS),
  guildId: snowflakeSchema,
  userId: snowflakeSchema,
  channelId: snowflakeSchema.optional(),
  messageId: snowflakeSchema.optional(),
  /** Normalized URL, sha256, fingerprint, etc. */
  subject: z.string().min(1).max(2048),
  /** 0..1 from local detectors. */
  heuristicScore: z.number().min(0).max(1),
  /** Human-readable, shown to mods. */
  reasons: z.array(z.string().min(1).max(200)).max(10),
  createdAt: z.date(),
});

export type Signal = z.infer<typeof signalSchema>;

export interface Verdict {
  level: VerdictLevel;
  /** 0..1 */
  score: number;
  /** e.g. 'blocklist', 'heuristic', 'virustotal', 'network:7-guilds' */
  sources: string[];
  reasons: string[];
}

export interface GuildSettings {
  id: string;
  mode: GuildMode;
  alertChannelId: string | null;
  quarantineRoleId: string | null;
  modRoleIds: string[];
}

export interface ActionOutcome {
  action: ActionKind;
  ok: boolean;
  /** Safe, human-readable detail. Never raw error objects or stack traces. */
  detail?: string;
  /** For alerts: the message that was posted, so it can be updated when the detection is resolved elsewhere. */
  ref?: { channelId: string; messageId: string };
}

export interface Detection {
  id: string;
  guildId: string;
  userId: string;
  channelId: string | null;
  messageId: string | null;
  signalKind: SignalKind;
  subject: string;
  verdict: Verdict;
  actionsTaken: ActionOutcome[];
  status: DetectionStatus;
  createdAt: Date;
}
