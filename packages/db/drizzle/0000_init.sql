CREATE TYPE "public"."detection_status" AS ENUM('open', 'confirmed', 'false_positive', 'restored');--> statement-breakpoint
CREATE TYPE "public"."guild_mode" AS ENUM('alert_only', 'protect', 'strict');--> statement-breakpoint
CREATE TABLE "audit_log" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"guild_id" text NOT NULL,
	"actor" text NOT NULL,
	"action" text NOT NULL,
	"target" text,
	"details" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "detections" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"guild_id" text NOT NULL,
	"user_id" text NOT NULL,
	"channel_id" text,
	"message_id" text,
	"signal_kind" text NOT NULL,
	"subject" text NOT NULL,
	"indicator_id" uuid,
	"verdict" jsonb NOT NULL,
	"actions_taken" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"status" "detection_status" DEFAULT 'open' NOT NULL,
	"evidence" jsonb,
	"incident_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"reverted_at" timestamp with time zone,
	"reverted_by" text,
	"expires_at" timestamp with time zone DEFAULT now() + interval '90 days' NOT NULL
);
--> statement-breakpoint
CREATE TABLE "guild_allowlist" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"guild_id" text NOT NULL,
	"type" text NOT NULL,
	"value" text NOT NULL,
	"added_by" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "guilds" (
	"id" text PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"joined_at" timestamp with time zone DEFAULT now() NOT NULL,
	"left_at" timestamp with time zone,
	"mode" "guild_mode" DEFAULT 'alert_only' NOT NULL,
	"alert_channel_id" text,
	"quarantine_role_id" text,
	"mod_role_ids" text[] DEFAULT '{}'::text[] NOT NULL,
	"vt_upload_opt_in" boolean DEFAULT false NOT NULL,
	"trust_score" real DEFAULT 0.5 NOT NULL,
	"settings" jsonb DEFAULT '{}'::jsonb NOT NULL
);
--> statement-breakpoint
ALTER TABLE "detections" ADD CONSTRAINT "detections_guild_id_guilds_id_fk" FOREIGN KEY ("guild_id") REFERENCES "public"."guilds"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "guild_allowlist" ADD CONSTRAINT "guild_allowlist_guild_id_guilds_id_fk" FOREIGN KEY ("guild_id") REFERENCES "public"."guilds"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "audit_log_guild_created_idx" ON "audit_log" USING btree ("guild_id","created_at");--> statement-breakpoint
CREATE INDEX "detections_guild_created_idx" ON "detections" USING btree ("guild_id","created_at");--> statement-breakpoint
CREATE INDEX "detections_expires_idx" ON "detections" USING btree ("expires_at");--> statement-breakpoint
CREATE UNIQUE INDEX "guild_allowlist_unique" ON "guild_allowlist" USING btree ("guild_id","type","value");