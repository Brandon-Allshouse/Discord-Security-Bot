import { createHmac, timingSafeEqual } from 'node:crypto';
import { z } from 'zod';
import { REVIEW_DECISIONS } from './review.js';
import { snowflakeSchema } from './types.js';

/**
 * How the dashboard asks the bot to do things that need Discord permissions (reviewing a
 * detection, setup, a test alert). The dashboard never holds the bot token:
 *
 * 1. The bot publishes a snapshot of each server (channel and role names, what it's allowed
 *    to do) so the dashboard can show forms.
 * 2. The dashboard signs a request and queues it for the shard that serves the server.
 * 3. The bot checks the signature and its age, re-validates everything, carries it out with
 *    its own permissions, audits it under the user's ID, and answers with a result code.
 *
 * Only the dashboard decides *who* may ask (Manage Server, checked at login). The signature
 * is what lets the bot trust that the request really came from the dashboard.
 */

/** Written by the bot manager: how many shards are running. */
export const BOT_SHARD_COUNT_KEY = 'equinox:bot:shards';
export const guildSnapshotKey = (guildId: string) => `equinox:guild:${guildId}:snapshot`;
export const GUILD_SNAPSHOT_TTL_SECONDS = 15 * 60;

/** One queue per shard, so a request reaches the process that is connected to that server. */
export const dashboardActionQueue = (shardId: number) => `dashboard-actions-${shardId}`;

/** Discord's own sharding formula: which shard serves a server. */
export function shardForGuild(guildId: string, shardCount: number): number {
  if (!Number.isInteger(shardCount) || shardCount < 1) throw new Error('invalid shard count');
  return Number((BigInt(guildId) >> 22n) % BigInt(shardCount));
}

export const guildSnapshotSchema = z.object({
  channels: z
    .array(z.object({ id: snowflakeSchema, name: z.string().max(100), canPostAlerts: z.boolean() }))
    .max(500),
  roles: z
    .array(
      z.object({
        id: snowflakeSchema,
        name: z.string().max(100),
        /** Can be the mod role: not @everyone and not managed by an integration. */
        canBeModRole: z.boolean(),
        /** Can be the quarantine role: the bot can hand it out (below the bot's own role). */
        canBeQuarantineRole: z.boolean(),
      }),
    )
    .max(250),
  missingPermissions: z.array(z.string().max(50)).max(20),
  updatedAt: z.iso.datetime(),
});
export type GuildSnapshot = z.infer<typeof guildSnapshotSchema>;

const actorFields = { guildId: snowflakeSchema, actorId: snowflakeSchema };

export const dashboardActionSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('review'), ...actorFields, detectionId: z.uuid(), decision: z.enum(REVIEW_DECISIONS) }),
  z.object({
    type: z.literal('setup'),
    ...actorFields,
    alertChannelId: snowflakeSchema,
    modRoleId: snowflakeSchema.nullable(),
    quarantineRoleId: snowflakeSchema.nullable(),
  }),
  z.object({ type: z.literal('test'), ...actorFields }),
]);
export type DashboardAction = z.infer<typeof dashboardActionSchema>;

export const DASHBOARD_RESULT_CODES = [
  'reviewed',
  'already_resolved',
  'not_found',
  'setup_saved',
  'setup_bad_channel',
  'setup_bad_mod_role',
  'setup_bad_quarantine_role',
  'test_sent',
  'test_not_detected',
  'guild_unavailable',
  'rejected',
] as const;
export type DashboardResultCode = (typeof DASHBOARD_RESULT_CODES)[number];
export const dashboardResultSchema = z.object({ code: z.enum(DASHBOARD_RESULT_CODES) });
export type DashboardResult = z.infer<typeof dashboardResultSchema>;

/** Requests older than this are refused, so a captured request can't be replayed later. */
export const ACTION_MAX_AGE_MS = 2 * 60 * 1000;

export const signedActionSchema = z.object({
  action: z.unknown(),
  issuedAt: z.number().int(),
  signature: z.string().regex(/^[0-9a-f]{64}$/),
});
export type SignedAction = z.infer<typeof signedActionSchema>;

function mac(key: string, action: DashboardAction, issuedAt: number): string {
  // Fixed field order, so both sides sign exactly the same bytes.
  return createHmac('sha256', Buffer.from(key, 'hex')).update(`${issuedAt}.${JSON.stringify(action)}`).digest('hex');
}

export function signAction(key: string, action: DashboardAction, now = Date.now()): SignedAction {
  // Parsed first, so the signed bytes are in schema order, exactly as the bot will re-serialize them.
  const parsed = dashboardActionSchema.parse(action);
  return { action: parsed, issuedAt: now, signature: mac(key, parsed, now) };
}

/**
 * Checks a request from the dashboard: well-formed, recent, and signed with the shared key.
 * Returns the action, or null for anything that doesn't check out.
 */
export function verifyAction(key: string, raw: unknown, now = Date.now()): DashboardAction | null {
  const envelope = signedActionSchema.safeParse(raw);
  if (!envelope.success) return null;
  const { issuedAt, signature } = envelope.data;
  if (Math.abs(now - issuedAt) > ACTION_MAX_AGE_MS) return null;
  const action = dashboardActionSchema.safeParse(envelope.data.action);
  if (!action.success) return null;
  // Re-serialize the parsed action: the signature must cover exactly what will be acted on.
  const expected = Buffer.from(mac(key, action.data, issuedAt), 'hex');
  const given = Buffer.from(signature, 'hex');
  return expected.length === given.length && timingSafeEqual(expected, given) ? action.data : null;
}
