CREATE TABLE "dependency_fixes" (
	"id" uuid PRIMARY KEY NOT NULL,
	"project_id" uuid NOT NULL,
	"family" text NOT NULL,
	"package_name" text NOT NULL,
	"state" text NOT NULL,
	"refresh" boolean DEFAULT false NOT NULL,
	"origin" text NOT NULL,
	"requested_by" uuid,
	"generation" smallint DEFAULT 1 NOT NULL,
	"lease_token_hash" text,
	"lease_until" timestamp with time zone,
	"base_sha" text,
	"head_sha" text,
	"branch" text NOT NULL,
	"mr_number" integer,
	"mr_url" text,
	"installed_version" text,
	"target_version" text,
	"targets" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"vulnerability_ids" text[] DEFAULT '{}'::text[] NOT NULL,
	"declined_target" text,
	"failure" jsonb,
	"prepared" jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "dependency_fixes_family_check" CHECK (family IN ('js','go','maven','python')),
	CONSTRAINT "dependency_fixes_state_check" CHECK (state IN ('requested','preparing','committing','open','failed','no_fix','merged','fixed','declined','taken_over','cancelled')),
	CONSTRAINT "dependency_fixes_origin_check" CHECK (origin IN ('manual','auto')),
	CONSTRAINT "dependency_fixes_generation_check" CHECK (generation >= 1),
	CONSTRAINT "dependency_fixes_lease_check" CHECK (state <> 'preparing' OR (lease_token_hash IS NOT NULL AND lease_until IS NOT NULL)),
	CONSTRAINT "dependency_fixes_committing_check" CHECK (state <> 'committing' OR prepared IS NOT NULL),
	CONSTRAINT "dependency_fixes_open_check" CHECK (state <> 'open' OR (mr_number IS NOT NULL AND head_sha IS NOT NULL))
);
--> statement-breakpoint
CREATE TABLE "project_fix_settings" (
	"project_id" uuid PRIMARY KEY NOT NULL,
	"enabled" boolean DEFAULT false NOT NULL,
	"auto_min_severity" text,
	"auto_exploited" boolean DEFAULT false NOT NULL,
	"auto_since" timestamp with time zone,
	"max_open" smallint DEFAULT 5 NOT NULL,
	"last_claim_at" timestamp with time zone,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "project_fix_settings_auto_severity_check" CHECK (auto_min_severity IS NULL OR auto_min_severity IN ('critical','high','medium','low')),
	CONSTRAINT "project_fix_settings_auto_since_check" CHECK ((auto_min_severity IS NULL AND NOT auto_exploited) OR auto_since IS NOT NULL),
	CONSTRAINT "project_fix_settings_max_open_check" CHECK (max_open BETWEEN 1 AND 20)
);
--> statement-breakpoint
ALTER TABLE "scm_connections" ADD COLUMN "fix_mrs_allowed" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "dependency_fixes" ADD CONSTRAINT "dependency_fixes_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dependency_fixes" ADD CONSTRAINT "dependency_fixes_requested_by_users_id_fk" FOREIGN KEY ("requested_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "project_fix_settings" ADD CONSTRAINT "project_fix_settings_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "dependency_fixes_package_uq" ON "dependency_fixes" USING btree ("project_id","family","package_name");--> statement-breakpoint
CREATE INDEX "dependency_fixes_lease_idx" ON "dependency_fixes" USING btree ("state","lease_until");--> statement-breakpoint
CREATE INDEX "dependency_fixes_requested_by_idx" ON "dependency_fixes" USING btree ("requested_by") WHERE requested_by IS NOT NULL;