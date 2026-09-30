import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { z } from 'zod';
import { DASHBOARD_RESULT_CODES, guildSnapshotSchema } from './dashboard-contract.js';
import { intelStatusSchema, intelSummarySchema } from './intel/contract.js';
import { ACTION_KINDS, DETECTION_STATUSES, GUILD_MODES, SIGNAL_KINDS, snowflakeSchema, VERDICT_LEVELS } from './types.js';

/**
 * The contract between the dashboard (frontend) and the API (backend).
 *
 * The dashboard holds no database or Redis credentials and no Discord secrets. Everything it
 * shows or changes goes through the API, and every request is signed:
 *
 *   HMAC-SHA256(API_SIGNING_KEY, timestamp \n nonce \n METHOD \n path \n session \n sha256(body))
 *
 * The API refuses a request that isn't signed, is more than 60 seconds off, or reuses a nonce,
 * so requests can't be forged, altered (including swapping the session) or replayed.
 */

export const API_HEADERS = {
  timestamp: 'x-equinox-timestamp',
  nonce: 'x-equinox-nonce',
  signature: 'x-equinox-signature',
  /** The logged-in user's session ID (from the dashboard's cookie). Covered by the signature. */
  session: 'x-equinox-session',
} as const;

export const API_REQUEST_MAX_AGE_MS = 60_000;
const NONCE = /^[A-Za-z0-9_-]{22,64}$/;
const HEX64 = /^[0-9a-f]{64}$/;

export interface ApiRequestParts {
  method: string;
  /** Path including any query string, exactly as sent. */
  path: string;
  /** Raw request body ('' when there is none). */
  body: string;
  /** Session ID, or '' when there is none. */
  session: string;
}

function canonical(parts: ApiRequestParts, timestamp: number, nonce: string): string {
  const bodyHash = createHash('sha256').update(parts.body).digest('hex');
  return [timestamp, nonce, parts.method.toUpperCase(), parts.path, parts.session, bodyHash].join('\n');
}

function mac(key: string, text: string): string {
  return createHmac('sha256', Buffer.from(key, 'hex')).update(text).digest('hex');
}

/** Headers for a signed request from the dashboard to the API. */
export function signApiRequest(key: string, parts: ApiRequestParts, now = Date.now(), nonce = randomBytes(18).toString('base64url')) {
  const headers: Record<string, string> = {
    [API_HEADERS.timestamp]: String(now),
    [API_HEADERS.nonce]: nonce,
    [API_HEADERS.signature]: mac(key, canonical(parts, now, nonce)),
  };
  if (parts.session) headers[API_HEADERS.session] = parts.session;
  return headers;
}

export type ApiVerification = { ok: true; nonce: string } | { ok: false; problem: 'missing' | 'stale' | 'bad_signature' };

/**
 * Checks a request's signature and age. The caller must also check the nonce hasn't been
 * seen before (the API keeps them in Redis for longer than the allowed age).
 */
export function verifyApiRequest(
  key: string,
  parts: Omit<ApiRequestParts, 'session'>,
  headers: Record<string, string | string[] | undefined>,
  now = Date.now(),
): ApiVerification {
  const one = (name: string) => {
    const value = headers[name];
    return typeof value === 'string' ? value : '';
  };
  const timestamp = Number(one(API_HEADERS.timestamp));
  const nonce = one(API_HEADERS.nonce);
  const signature = one(API_HEADERS.signature);
  if (!Number.isInteger(timestamp) || !NONCE.test(nonce) || !HEX64.test(signature)) return { ok: false, problem: 'missing' };
  if (Math.abs(now - timestamp) > API_REQUEST_MAX_AGE_MS) return { ok: false, problem: 'stale' };
  const expected = Buffer.from(mac(key, canonical({ ...parts, session: one(API_HEADERS.session) }, timestamp, nonce)), 'hex');
  const given = Buffer.from(signature, 'hex');
  return expected.length === given.length && timingSafeEqual(expected, given) ? { ok: true, nonce } : { ok: false, problem: 'bad_signature' };
}

/* ---------- Response shapes. The dashboard validates every response it gets. ---------- */

const isoDate = z.iso.datetime().transform((value) => new Date(value));

export const API_ERRORS = [
  'unauthenticated',
  'csrf',
  'not_found',
  'rate_limited',
  'bad_request',
  'mode',
  'domain',
  'missing',
  'url',
  'discord',
  'unavailable',
  /** The request to the API wasn't validly signed, was too old, or was a replay. */
  'signature',
] as const;
export type ApiErrorCode = (typeof API_ERRORS)[number];
export const apiErrorSchema = z.object({
  error: z.enum(API_ERRORS),
  /** For unexpected failures: the reference in the API's log, so a user's report can be traced. */
  ref: z.string().regex(/^[0-9a-f]{8}$/).optional(),
});

/** What came of a request the API passed on to the bot. */
export const BOT_OUTCOMES = [...DASHBOARD_RESULT_CODES, 'timeout', 'bot_unavailable', 'off'] as const;
export type BotOutcome = (typeof BOT_OUTCOMES)[number];
export const botOutcomeSchema = z.object({ outcome: z.enum(BOT_OUTCOMES) });

export const authorizeUrlSchema = z.object({ url: z.url() });
export const sessionCreatedSchema = z.object({ sessionId: z.string().regex(/^[A-Za-z0-9_-]{43}$/) });

const guildRef = z.object({ id: snowflakeSchema, name: z.string().max(200) });
/** Who is looking at a page: enough for the header and for forms. */
export const viewerSchema = z.object({ username: z.string().max(100), csrf: z.string().min(20).max(100) });
export type Viewer = z.infer<typeof viewerSchema>;
export const meSchema = z.object({
  user: z.object({ id: snowflakeSchema, username: z.string().max(100) }),
  csrf: z.string().min(20).max(100),
  /** Servers the user manages where Equinox is installed. */
  guilds: z.array(guildRef).max(200),
});
export type Me = z.infer<typeof meSchema>;

const actionOutcomeSchema = z.object({
  action: z.enum(ACTION_KINDS),
  ok: z.boolean(),
  detail: z.string().max(500).optional(),
  ref: z.object({ channelId: z.string(), messageId: z.string() }).optional(),
});

export const detectionSchema = z.object({
  id: z.uuid(),
  guildId: snowflakeSchema,
  userId: snowflakeSchema,
  channelId: snowflakeSchema.nullable(),
  messageId: snowflakeSchema.nullable(),
  signalKind: z.enum(SIGNAL_KINDS),
  subject: z.string().max(2048),
  verdict: z.object({
    level: z.enum(VERDICT_LEVELS),
    score: z.number().min(0).max(1),
    sources: z.array(z.string().max(50)).max(20),
    reasons: z.array(z.string().max(300)).max(20),
  }),
  actionsTaken: z.array(actionOutcomeSchema).max(50),
  status: z.enum(DETECTION_STATUSES),
  createdAt: isoDate,
});

export const guildPageSchema = z.object({
  viewer: viewerSchema,
  name: z.string().max(200),
  guild: z.object({
    id: snowflakeSchema,
    mode: z.enum(GUILD_MODES),
    alertChannelId: snowflakeSchema.nullable(),
    quarantineRoleId: snowflakeSchema.nullable(),
    modRoleIds: z.array(snowflakeSchema).max(25),
  }),
  openCount: z.number().int().min(0),
  detections: z.array(detectionSchema).max(100),
  allowlist: z.array(z.object({ value: z.string().max(253), addedBy: z.string().max(20), createdAt: isoDate })).max(500),
  audit: z
    .array(z.object({ actor: z.string().max(20), action: z.string().max(100), target: z.string().max(2048).nullable(), createdAt: isoDate }))
    .max(100),
  intelStatus: intelStatusSchema.nullable(),
  snapshot: guildSnapshotSchema.nullable(),
  botEnabled: z.boolean(),
});
export type GuildPage = z.infer<typeof guildPageSchema>;

export const linkCheckResponseSchema = z.object({
  viewer: viewerSchema,
  name: z.string().max(200),
  result: z.object({
    url: z.string().max(2048),
    level: z.enum(VERDICT_LEVELS),
    score: z.number().min(0).max(1),
    reasons: z.array(z.string().max(300)).max(20),
    allowlisted: z.boolean(),
    blocklisted: z.boolean(),
    knownSafe: z.boolean(),
    intel: intelSummarySchema.nullable(),
    intelState: z.enum(['not_needed', 'checked', 'pending']),
  }),
  queued: z.boolean(),
});
