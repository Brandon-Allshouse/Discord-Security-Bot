import { sql } from 'drizzle-orm';
import type { Database } from './client.js';

/**
 * A tenant is one Discord server (guild). Its ID is the guild's snowflake.
 *
 * Tenant isolation is enforced by Postgres, not just by WHERE clauses:
 * every tenant query runs in a transaction that
 *   1. sets `equinox.tenant_id` to the tenant, and
 *   2. switches to the `equinox_tenant` role, which is subject to row-level security.
 * RLS policies (migration 0002) only expose rows whose guild_id matches the setting.
 * If a query forgets its tenant filter, it gets nothing from other tenants instead of leaking them.
 */
export type TenantTx = Parameters<Parameters<Database['transaction']>[0]>[0];

const TENANT_ID = /^\d{17,20}$/;

export function assertTenantId(tenantId: string): void {
  if (!TENANT_ID.test(tenantId)) throw new Error('invalid tenant id');
}

export async function asTenant<T>(db: Database, tenantId: string, fn: (tx: TenantTx) => Promise<T>): Promise<T> {
  assertTenantId(tenantId);
  return db.transaction(async (tx) => {
    // set_config(..., true) and SET LOCAL both end with the transaction, so nothing leaks
    // to the next query that reuses this pooled connection.
    await tx.execute(sql`select set_config('equinox.tenant_id', ${tenantId}, true)`);
    await tx.execute(sql`set local role equinox_tenant`);
    return fn(tx);
  });
}
