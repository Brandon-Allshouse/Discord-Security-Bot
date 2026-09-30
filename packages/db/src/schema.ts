import { sql } from 'drizzle-orm';
import {
  boolean,
  index,
  jsonb,
  pgEnum,
  pgTable,
  real,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';
import type { ActionOutcome, Verdict } from '@equinox/core';

export const guildMode = pgEnum('guild_mode', ['alert_only', 'protect', 'strict']);
export const detectionStatus = pgEnum('detection_status', ['open', 'confirmed', 'false_positive', 'restored']);

const createdAt = () => timestamp('created_at', { withTimezone: true }).notNull().defaultNow();

export const guilds = pgTable('guilds', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  joinedAt: timestamp('joined_at', { withTimezone: true }).notNull().defaultNow(),
  leftAt: timestamp('left_at', { withTimezone: true }),
  mode: guildMode('mode').notNull().default('alert_only'),
  alertChannelId: text('alert_channel_id'),
  quarantineRoleId: text('quarantine_role_id'),
  modRoleIds: text('mod_role_ids').array().notNull().default(sql`'{}'::text[]`),
  vtUploadOptIn: boolean('vt_upload_opt_in').notNull().default(false),
  trustScore: real('trust_score').notNull().default(0.5),
  settings: jsonb('settings').$type<Record<string, unknown>>().notNull().default({}),
});

export const detections = pgTable(
  'detections',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    guildId: text('guild_id')
      .notNull()
      .references(() => guilds.id, { onDelete: 'cascade' }),
    userId: text('user_id').notNull(),
    channelId: text('channel_id'),
    messageId: text('message_id'),
    signalKind: text('signal_kind').notNull(),
    subject: text('subject').notNull(),
    indicatorId: uuid('indicator_id'),
    verdict: jsonb('verdict').$type<Verdict>().notNull(),
    actionsTaken: jsonb('actions_taken').$type<ActionOutcome[]>().notNull().default([]),
    status: detectionStatus('status').notNull().default('open'),
    /** Only filled for confirmed detections; cleared by the retention job. */
    evidence: jsonb('evidence').$type<Record<string, unknown>>(),
    incidentId: uuid('incident_id'),
    createdAt: createdAt(),
    revertedAt: timestamp('reverted_at', { withTimezone: true }),
    revertedBy: text('reverted_by'),
    /** Retention: 90 days (see Privacy in the README). */
    expiresAt: timestamp('expires_at', { withTimezone: true })
      .notNull()
      .default(sql`now() + interval '90 days'`),
  },
  (table) => [
    index('detections_guild_created_idx').on(table.guildId, table.createdAt),
    index('detections_expires_idx').on(table.expiresAt),
  ],
);

/**
 * Append-only. UPDATE and DELETE are rejected by a trigger (migration 0001),
 * so not even the app itself can rewrite history.
 */
export const auditLog = pgTable(
  'audit_log',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    guildId: text('guild_id').notNull(),
    actor: text('actor').notNull(),
    action: text('action').notNull(),
    target: text('target'),
    details: jsonb('details').$type<Record<string, unknown>>().notNull().default({}),
    createdAt: createdAt(),
  },
  (table) => [index('audit_log_guild_created_idx').on(table.guildId, table.createdAt)],
);

export const guildAllowlist = pgTable(
  'guild_allowlist',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    guildId: text('guild_id')
      .notNull()
      .references(() => guilds.id, { onDelete: 'cascade' }),
    type: text('type').notNull(),
    value: text('value').notNull(),
    addedBy: text('added_by').notNull(),
    createdAt: createdAt(),
  },
  (table) => [uniqueIndex('guild_allowlist_unique').on(table.guildId, table.type, table.value)],
);

/**
 * Network-wide cache of threat-intel answers (spec §4). No guild_id: it holds indicators only,
 * never who saw them. Tenant roles get no access; only the intel worker reads and writes it.
 */
export const providerResults = pgTable(
  'provider_results',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    provider: text('provider').notNull(),
    kind: text('kind').notNull(),
    subject: text('subject').notNull(),
    verdictLevel: text('verdict_level').notNull(),
    weight: real('weight').notNull().default(0),
    reasons: text('reasons').array().notNull().default(sql`'{}'::text[]`),
    details: jsonb('details').$type<Record<string, unknown>>().notNull().default({}),
    fetchedAt: timestamp('fetched_at', { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  },
  (table) => [
    uniqueIndex('provider_results_unique').on(table.provider, table.kind, table.subject),
    index('provider_results_expires_idx').on(table.expiresAt),
  ],
);
