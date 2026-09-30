import { PostgreSqlContainer, type StartedPostgreSqlContainer } from '@testcontainers/postgresql';
import { processSignal, reviewDetection, type ActionExecutor, type Verdict } from '@equinox/core';
import { makeSignal } from '@equinox/core/testing';
import { sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createDb, runMigrations, type DbHandle } from './client.js';
import { createStores, SystemStore, type Stores } from './repositories.js';
import { auditLog, detections, guildAllowlist, guilds } from './schema.js';
import { asTenant } from './tenant.js';

let container: StartedPostgreSqlContainer;
let handle: DbHandle;
let stores: Stores;

const TENANT_A = '100000000000000001';
const TENANT_B = '100000000000000002';
const MOD = '500000000000000001';
const verdict: Verdict = { level: 'suspicious', score: 0.6, sources: ['heuristic'], reasons: [] };

const executor: ActionExecutor = {
  execute: (action) => Promise.resolve({ action, ok: true }),
  revert: (action) => Promise.resolve({ action, ok: true }),
};

beforeAll(async () => {
  container = await new PostgreSqlContainer('postgres:16-alpine').start();
  await runMigrations(container.getConnectionUri());
  handle = createDb(container.getConnectionUri(), { max: 2 });
  stores = createStores(handle.db);
  await stores.guilds.register({ id: TENANT_A, name: 'A' });
  await stores.guilds.register({ id: TENANT_B, name: 'B' });
}, 120_000);

afterAll(async () => {
  await handle?.close();
  await container?.stop();
});

describe('migrations', () => {
  it('are idempotent', async () => {
    await expect(runMigrations(container.getConnectionUri())).resolves.toBeUndefined();
  });
});

describe('guild store', () => {
  it('registers new tenants in alert_only', async () => {
    expect(await stores.guilds.get(TENANT_A)).toMatchObject({ id: TENANT_A, mode: 'alert_only', modRoleIds: [] });
  });

  it('keeps settings when a server re-joins, and hides servers that left', async () => {
    await stores.guilds.setMode(TENANT_A, 'protect');
    await stores.guilds.markLeft(TENANT_A);
    expect(await stores.guilds.get(TENANT_A)).toBeNull();
    await stores.guilds.register({ id: TENANT_A, name: 'A' });
    expect((await stores.guilds.get(TENANT_A))?.mode).toBe('protect');
    await stores.guilds.setMode(TENANT_A, 'alert_only');
  });

  it('stores configuration', async () => {
    await stores.guilds.configure(TENANT_B, { alertChannelId: '300000000000000009', modRoleIds: ['600000000000000001'] });
    expect(await stores.guilds.get(TENANT_B)).toMatchObject({
      alertChannelId: '300000000000000009',
      modRoleIds: ['600000000000000001'],
    });
  });

  it('rejects malformed tenant IDs before touching the database', async () => {
    await expect(stores.guilds.get("1' OR '1'='1")).rejects.toThrow(/invalid tenant id/);
  });
});

describe('pipeline against Postgres', () => {
  it('stores a detection, its outcomes, the review and the audit trail', async () => {
    const deps = {
      guilds: stores.guilds,
      detections: stores.detections,
      audit: stores.audit,
      executor,
      indicators: { isAllowlisted: () => Promise.resolve(false), isBlocklisted: () => Promise.resolve(false) },
    };
    const result = await processSignal(makeSignal({ guildId: TENANT_A }), deps);
    if (result.status !== 'detected') throw new Error('expected detection');

    const stored = await stores.detections.get(TENANT_A, result.detection.id);
    expect(stored?.actionsTaken).toEqual([{ action: 'alert', ok: true }]);
    expect(await stores.detections.countOpen(TENANT_A)).toBeGreaterThanOrEqual(1);

    await reviewDetection(
      { guildId: TENANT_A, detectionId: result.detection.id, decision: 'false_positive', actorId: MOD },
      deps,
    );
    const [row] = await handle.db.select().from(detections).where(sql`${detections.id} = ${result.detection.id}`);
    expect(row).toMatchObject({ status: 'false_positive', revertedBy: MOD });
    expect(row?.revertedAt).toBeInstanceOf(Date);

    const actions = (await stores.audit.recent(TENANT_A)).map((r) => r.action);
    expect(actions).toEqual(expect.arrayContaining(['detection.created', 'action.alert', 'review.false_positive']));
  });

  it('confirm does not set reverted fields', async () => {
    const detection = await stores.detections.create({ signal: makeSignal({ guildId: TENANT_A }), verdict });
    await stores.detections.setStatus(TENANT_A, detection.id, 'confirmed', MOD);
    const [row] = await handle.db.select().from(detections).where(sql`${detections.id} = ${detection.id}`);
    expect(row).toMatchObject({ status: 'confirmed', revertedAt: null, revertedBy: null });
  });
});

describe('tenant isolation (row-level security)', () => {
  let detectionA: string;
  let detectionB: string;

  beforeAll(async () => {
    detectionA = (await stores.detections.create({ signal: makeSignal({ guildId: TENANT_A }), verdict })).id;
    detectionB = (await stores.detections.create({ signal: makeSignal({ guildId: TENANT_B }), verdict })).id;
    await stores.allowlist.add({ guildId: TENANT_B, type: 'domain', value: 'b-only.example', addedBy: MOD });
  });

  it('a query with no tenant filter only sees its own tenant', async () => {
    const rows = await asTenant(handle.db, TENANT_A, (tx) => tx.select().from(detections));
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.every((r) => r.guildId === TENANT_A)).toBe(true);
    expect(rows.some((r) => r.id === detectionB)).toBe(false);

    const tenantsVisible = await asTenant(handle.db, TENANT_A, (tx) => tx.select().from(guilds));
    expect(tenantsVisible.map((g) => g.id)).toEqual([TENANT_A]);

    const allowlistVisible = await asTenant(handle.db, TENANT_A, (tx) => tx.select().from(guildAllowlist));
    expect(allowlistVisible.some((r) => r.value === 'b-only.example')).toBe(false);

    const auditVisible = await asTenant(handle.db, TENANT_A, (tx) => tx.select().from(auditLog));
    expect(auditVisible.every((r) => r.guildId === TENANT_A)).toBe(true);
  });

  it('cannot read another tenant’s detection by ID', async () => {
    expect(await stores.detections.get(TENANT_A, detectionB)).toBeNull();
    const rows = await asTenant(handle.db, TENANT_A, (tx) =>
      tx.select().from(detections).where(sql`${detections.id} = ${detectionB}`),
    );
    expect(rows).toEqual([]);
  });

  it('cannot write rows into another tenant', async () => {
    await expect(
      asTenant(handle.db, TENANT_A, (tx) =>
        tx.insert(guildAllowlist).values({ guildId: TENANT_B, type: 'domain', value: 'x.example', addedBy: MOD }),
      ),
    ).rejects.toThrow();
    await expect(
      asTenant(handle.db, TENANT_A, (tx) =>
        tx.insert(auditLog).values({ guildId: TENANT_B, actor: 'bot', action: 'forged', details: {} }),
      ),
    ).rejects.toThrow();
  });

  it('cannot update or delete another tenant’s rows', async () => {
    const updated = await asTenant(handle.db, TENANT_A, (tx) =>
      tx.update(detections).set({ status: 'restored' }).returning({ id: detections.id }),
    );
    expect(updated.some((r) => r.id === detectionB)).toBe(false);
    expect(updated.some((r) => r.id === detectionA)).toBe(true);

    const deleted = await asTenant(handle.db, TENANT_A, (tx) =>
      tx.delete(guildAllowlist).returning({ value: guildAllowlist.value }),
    );
    expect(deleted.some((r) => r.value === 'b-only.example')).toBe(false);
    expect(await stores.allowlist.has(TENANT_B, 'domain', 'b-only.example')).toBe(true);
  });

  it('sees nothing when no tenant is set', async () => {
    const rows = await handle.db.transaction(async (tx) => {
      await tx.execute(sql`set local role equinox_tenant`);
      return tx.select().from(detections);
    });
    expect(rows).toEqual([]);
  });

  it('tenant role cannot delete detections or alter the audit log', async () => {
    await expect(asTenant(handle.db, TENANT_A, (tx) => tx.delete(detections))).rejects.toThrow();
    await expect(asTenant(handle.db, TENANT_A, (tx) => tx.execute(sql`UPDATE audit_log SET action = 'x'`))).rejects.toThrow();
  });

  it('does not leak the tenant or role to the next query on a pooled connection', async () => {
    await asTenant(handle.db, TENANT_A, (tx) => tx.select().from(guilds));
    const result = await handle.db.execute<{ tenant: string | null; role: string }>(
      sql`select current_setting('equinox.tenant_id', true) as tenant, current_user as role`,
    );
    const [row] = [...result];
    expect(row?.tenant ?? '').toBe('');
    expect(row?.role).not.toBe('equinox_tenant');
  });
});

describe('retention (system job)', () => {
  it('deletes only expired detections, across tenants', async () => {
    const system = new SystemStore(handle.db);
    const fresh = await stores.detections.create({ signal: makeSignal({ guildId: TENANT_B }), verdict });
    expect(await system.deleteExpiredDetections(new Date())).toBe(0);
    const inFuture = new Date(Date.now() + 91 * 24 * 60 * 60 * 1000);
    expect(await system.deleteExpiredDetections(inFuture)).toBeGreaterThanOrEqual(1);
    expect(await stores.detections.get(TENANT_B, fresh.id)).toBeNull();
  });
});

describe('audit log', () => {
  it('is append-only even for the owning role: updates, deletes and truncates are rejected', async () => {
    await stores.audit.write({ guildId: TENANT_A, actor: 'bot', action: 'test', target: null, details: {} });
    await expect(handle.db.execute(sql`UPDATE audit_log SET action = 'tampered'`)).rejects.toThrow();
    await expect(handle.db.execute(sql`DELETE FROM audit_log`)).rejects.toThrow();
    await expect(handle.db.execute(sql`TRUNCATE audit_log`)).rejects.toThrow();
    const rows = await stores.audit.recent(TENANT_A, 100);
    expect(rows.some((row) => row.action === 'tampered')).toBe(false);
  });

  it('caps page size', async () => {
    expect((await stores.audit.recent(TENANT_A, 10_000)).length).toBeLessThanOrEqual(100);
  });
});

describe('allowlist store', () => {
  it('adds idempotently, checks and removes per tenant', async () => {
    const entry = { guildId: TENANT_A, type: 'domain', value: 'example.com', addedBy: MOD };
    await stores.allowlist.add(entry);
    await stores.allowlist.add(entry);
    expect(await stores.allowlist.has(TENANT_A, 'domain', 'example.com')).toBe(true);
    expect(await stores.allowlist.hasAny(TENANT_A, 'domain', ['a.example.com', 'example.com'])).toBe(true);
    expect(await stores.allowlist.hasAny(TENANT_A, 'domain', [])).toBe(false);
    expect(await stores.allowlist.has(TENANT_B, 'domain', 'example.com')).toBe(false);
    expect((await stores.allowlist.list(TENANT_A)).map((r) => r.value)).toContain('example.com');
    expect(await stores.allowlist.remove(TENANT_A, 'domain', 'example.com')).toBe(true);
    expect(await stores.allowlist.remove(TENANT_A, 'domain', 'example.com')).toBe(false);
  });
});
