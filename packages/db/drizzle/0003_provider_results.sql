CREATE TABLE "provider_results" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"provider" text NOT NULL,
	"kind" text NOT NULL,
	"subject" text NOT NULL,
	"verdict_level" text NOT NULL,
	"weight" real DEFAULT 0 NOT NULL,
	"reasons" text[] DEFAULT '{}'::text[] NOT NULL,
	"details" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"fetched_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX "provider_results_unique" ON "provider_results" USING btree ("provider","kind","subject");--> statement-breakpoint
CREATE INDEX "provider_results_expires_idx" ON "provider_results" USING btree ("expires_at");--> statement-breakpoint
-- Network-wide intel cache: tenants get no grants on it, and RLS with no policy is a second layer.
ALTER TABLE "provider_results" ENABLE ROW LEVEL SECURITY;
