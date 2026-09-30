-- Tenant isolation: one tenant per Discord server (guild).
-- Tenant queries run as equinox_tenant with equinox.tenant_id set (see src/tenant.ts).
-- Rows from other tenants are invisible and can't be written, even if the app forgets a filter.
-- System jobs (retention, network-wide indicators) run as the owning role, outside RLS.

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'equinox_tenant') THEN
    CREATE ROLE equinox_tenant NOLOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT;
  END IF;
END
$$;
--> statement-breakpoint
-- Let the application's login role switch into the tenant role.
GRANT equinox_tenant TO CURRENT_USER;
--> statement-breakpoint
GRANT USAGE ON SCHEMA public TO equinox_tenant;
--> statement-breakpoint
GRANT SELECT, INSERT, UPDATE ON guilds TO equinox_tenant;
--> statement-breakpoint
GRANT SELECT, INSERT, UPDATE ON detections TO equinox_tenant;
--> statement-breakpoint
GRANT SELECT, INSERT, DELETE ON guild_allowlist TO equinox_tenant;
--> statement-breakpoint
-- Append-only at the privilege level too (the trigger from 0001 is the second layer).
GRANT SELECT, INSERT ON audit_log TO equinox_tenant;
--> statement-breakpoint
ALTER TABLE guilds ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE detections ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE guild_allowlist ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
-- current_setting(..., true) returns NULL when unset, and NULL never matches: no tenant, no rows.
CREATE POLICY tenant_isolation ON guilds TO equinox_tenant
  USING (id = current_setting('equinox.tenant_id', true))
  WITH CHECK (id = current_setting('equinox.tenant_id', true));
--> statement-breakpoint
CREATE POLICY tenant_isolation ON detections TO equinox_tenant
  USING (guild_id = current_setting('equinox.tenant_id', true))
  WITH CHECK (guild_id = current_setting('equinox.tenant_id', true));
--> statement-breakpoint
CREATE POLICY tenant_isolation ON guild_allowlist TO equinox_tenant
  USING (guild_id = current_setting('equinox.tenant_id', true))
  WITH CHECK (guild_id = current_setting('equinox.tenant_id', true));
--> statement-breakpoint
CREATE POLICY tenant_isolation ON audit_log TO equinox_tenant
  USING (guild_id = current_setting('equinox.tenant_id', true))
  WITH CHECK (guild_id = current_setting('equinox.tenant_id', true));
