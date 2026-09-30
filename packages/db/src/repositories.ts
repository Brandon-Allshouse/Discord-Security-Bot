import { and, desc, eq, inArray, isNull, lt, sql } from 'drizzle-orm';
import type {
  ActionOutcome,
  AuditEntry,
  AuditLog,
  Detection,
  DetectionRepository,
  DetectionStatus,
  GuildMode,
  GuildRepository,
  GuildSettings,
  NewDetection,
  SignalKind,
} from '@equinox/core';
import type { Database } from './client.js';
import { auditLog, detections, guildAllowlist, guilds } from './schema.js';
import { asTenant } from './tenant.js';

type GuildRow = typeof guilds.$inferSelect;
type DetectionRow = typeof detections.$inferSelect;

function toGuildSettings(row: GuildRow): GuildSettings {
  return {
    id: row.id,
    mode: row.mode,
    alertChannelId: row.alertChannelId,
    quarantineRoleId: row.quarantineRoleId,
    modRoleIds: row.modRoleIds,
  };
}

function toDetection(row: DetectionRow): Detection {
  return {
    id: row.id,
    guildId: row.guildId,
    userId: row.userId,
    channelId: row.channelId,
    messageId: row.messageId,
    signalKind: row.signalKind as SignalKind,
    subject: row.subject,
    verdict: row.verdict,
    actionsTaken: row.actionsTaken,
    status: row.status,
    createdAt: row.createdAt,
  };
}

/*
 * Every method that touches tenant data runs through asTenant(), so Postgres row-level
 * security enforces the tenant boundary. The explicit guild filters stay as a second layer.
 * All queries go through Drizzle's query builder, so values are always parameterized.
 */

/** Tenant settings. A tenant is created when the sensor joins a server. */
export class GuildStore implements GuildRepository {
  constructor(private readonly db: Database) {}

  async get(guildId: string): Promise<GuildSettings | null> {
    return asTenant(this.db, guildId, async (tx) => {
      const [row] = await tx
        .select()
        .from(guilds)
        .where(and(eq(guilds.id, guildId), isNull(guilds.leftAt)));
      return row ? toGuildSettings(row) : null;
    });
  }

  /** On join: create the tenant in alert_only, or re-activate it without touching its settings. */
  async register(input: { id: string; name: string }): Promise<GuildSettings> {
    return asTenant(this.db, input.id, async (tx) => {
      const [row] = await tx
        .insert(guilds)
        .values({ id: input.id, name: input.name })
        .onConflictDoUpdate({ target: guilds.id, set: { name: input.name, leftAt: null } })
        .returning();
      if (!row) throw new Error('guild upsert returned no row');
      return toGuildSettings(row);
    });
  }

  async markLeft(guildId: string): Promise<void> {
    await asTenant(this.db, guildId, (tx) =>
      tx.update(guilds).set({ leftAt: new Date() }).where(eq(guilds.id, guildId)),
    );
  }

  async setMode(guildId: string, mode: GuildMode): Promise<void> {
    await asTenant(this.db, guildId, (tx) => tx.update(guilds).set({ mode }).where(eq(guilds.id, guildId)));
  }

  async configure(
    guildId: string,
    settings: Partial<Pick<GuildSettings, 'alertChannelId' | 'quarantineRoleId' | 'modRoleIds'>>,
  ): Promise<void> {
    if (Object.keys(settings).length === 0) return;
    await asTenant(this.db, guildId, (tx) => tx.update(guilds).set(settings).where(eq(guilds.id, guildId)));
  }
}

export class DetectionStore implements DetectionRepository {
  constructor(private readonly db: Database) {}

  async create({ signal, verdict }: NewDetection): Promise<Detection> {
    return asTenant(this.db, signal.guildId, async (tx) => {
      const [row] = await tx
        .insert(detections)
        .values({
          guildId: signal.guildId,
          userId: signal.userId,
          channelId: signal.channelId ?? null,
          messageId: signal.messageId ?? null,
          signalKind: signal.kind,
          subject: signal.subject,
          verdict,
        })
        .returning();
      if (!row) throw new Error('detection insert returned no row');
      return toDetection(row);
    });
  }

  async recordOutcomes(guildId: string, detectionId: string, outcomes: ActionOutcome[]): Promise<void> {
    await asTenant(this.db, guildId, (tx) =>
      tx
        .update(detections)
        .set({ actionsTaken: outcomes })
        .where(and(eq(detections.id, detectionId), eq(detections.guildId, guildId))),
    );
  }

  async get(guildId: string, detectionId: string): Promise<Detection | null> {
    return asTenant(this.db, guildId, async (tx) => {
      const [row] = await tx
        .select()
        .from(detections)
        .where(and(eq(detections.id, detectionId), eq(detections.guildId, guildId)));
      return row ? toDetection(row) : null;
    });
  }

  async setStatus(guildId: string, detectionId: string, status: DetectionStatus, actorId: string): Promise<void> {
    const reverting = status === 'restored' || status === 'false_positive';
    await asTenant(this.db, guildId, (tx) =>
      tx
        .update(detections)
        .set({ status, ...(reverting ? { revertedAt: new Date(), revertedBy: actorId } : {}) })
        .where(and(eq(detections.id, detectionId), eq(detections.guildId, guildId))),
    );
  }

  async countOpen(guildId: string): Promise<number> {
    return asTenant(this.db, guildId, async (tx) => {
      const [row] = await tx
        .select({ count: sql<number>`count(*)::int` })
        .from(detections)
        .where(and(eq(detections.guildId, guildId), eq(detections.status, 'open')));
      return row?.count ?? 0;
    });
  }
}

export class AuditStore implements AuditLog {
  constructor(private readonly db: Database) {}

  async write(entry: AuditEntry): Promise<void> {
    await asTenant(this.db, entry.guildId, (tx) => tx.insert(auditLog).values(entry));
  }

  async recent(guildId: string, limit = 20) {
    return asTenant(this.db, guildId, (tx) =>
      tx
        .select()
        .from(auditLog)
        .where(eq(auditLog.guildId, guildId))
        .orderBy(desc(auditLog.createdAt))
        .limit(Math.max(1, Math.min(limit, 100))),
    );
  }
}

export class AllowlistStore {
  constructor(private readonly db: Database) {}

  async has(guildId: string, type: string, value: string): Promise<boolean> {
    return this.hasAny(guildId, type, [value]);
  }

  async hasAny(guildId: string, type: string, values: string[]): Promise<boolean> {
    if (values.length === 0) return false;
    return asTenant(this.db, guildId, async (tx) => {
      const [row] = await tx
        .select({ id: guildAllowlist.id })
        .from(guildAllowlist)
        .where(
          and(eq(guildAllowlist.guildId, guildId), eq(guildAllowlist.type, type), inArray(guildAllowlist.value, values)),
        )
        .limit(1);
      return row !== undefined;
    });
  }

  async add(input: { guildId: string; type: string; value: string; addedBy: string }): Promise<void> {
    await asTenant(this.db, input.guildId, (tx) => tx.insert(guildAllowlist).values(input).onConflictDoNothing());
  }

  async remove(guildId: string, type: string, value: string): Promise<boolean> {
    return asTenant(this.db, guildId, async (tx) => {
      const rows = await tx
        .delete(guildAllowlist)
        .where(and(eq(guildAllowlist.guildId, guildId), eq(guildAllowlist.type, type), eq(guildAllowlist.value, value)))
        .returning({ id: guildAllowlist.id });
      return rows.length > 0;
    });
  }

  async list(guildId: string) {
    return asTenant(this.db, guildId, (tx) =>
      tx.select().from(guildAllowlist).where(eq(guildAllowlist.guildId, guildId)).limit(500),
    );
  }
}

/**
 * Cross-tenant maintenance jobs. Runs as the owning role, outside RLS, so keep it small:
 * nothing here may return tenant data to a caller.
 */
export class SystemStore {
  constructor(private readonly db: Database) {}

  /** Retention: removes detections past their expiry in every tenant. Returns how many were deleted. */
  async deleteExpiredDetections(now = new Date()): Promise<number> {
    const rows = await this.db.delete(detections).where(lt(detections.expiresAt, now)).returning({ id: detections.id });
    return rows.length;
  }
}

export function createStores(db: Database) {
  return {
    guilds: new GuildStore(db),
    detections: new DetectionStore(db),
    audit: new AuditStore(db),
    allowlist: new AllowlistStore(db),
  };
}

export type Stores = ReturnType<typeof createStores>;
