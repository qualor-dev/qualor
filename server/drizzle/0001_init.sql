CREATE TABLE "analyses" (
	"id" uuid PRIMARY KEY NOT NULL,
	"project_id" uuid NOT NULL,
	"branch_id" uuid,
	"revision" text,
	"baseline_revision" text,
	"baseline_status" text,
	"version_label" text,
	"analysis_date" timestamp with time zone,
	"status" text DEFAULT 'queued' NOT NULL,
	"error" jsonb,
	"scanner_version" text,
	"engines" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"warnings" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"gate_status" text,
	"gate_result" jsonb,
	"uploaded_by_token_id" uuid,
	"queued_at" timestamp with time zone DEFAULT now() NOT NULL,
	"started_at" timestamp with time zone,
	"finished_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "analyses_status_check" CHECK (status IN ('queued','processing','succeeded','failed')),
	CONSTRAINT "analyses_baseline_status_check" CHECK (baseline_status IN ('ok','unavailable','first_analysis')),
	CONSTRAINT "analyses_gate_status_check" CHECK (gate_status IN ('passed','failed','error','none')),
	CONSTRAINT "analyses_revision_format" CHECK (revision ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'),
	CONSTRAINT "analyses_baseline_revision_format" CHECK (baseline_revision ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'),
	CONSTRAINT "analyses_succeeded_is_complete" CHECK (status <> 'succeeded' OR (branch_id IS NOT NULL AND revision IS NOT NULL
        AND analysis_date IS NOT NULL AND baseline_status IS NOT NULL
        AND scanner_version IS NOT NULL))
);
--> statement-breakpoint
CREATE TABLE "analysis_reports" (
	"analysis_id" uuid PRIMARY KEY NOT NULL,
	"body" "bytea" NOT NULL,
	"size_bytes" integer NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "api_tokens" (
	"id" uuid PRIMARY KEY NOT NULL,
	"kind" text NOT NULL,
	"user_id" uuid,
	"project_id" uuid,
	"name" text NOT NULL,
	"prefix" text NOT NULL,
	"secret_hash" "bytea" NOT NULL,
	"scopes" text[] NOT NULL,
	"expires_at" timestamp with time zone,
	"last_used_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "api_tokens_kind_check" CHECK ((kind = 'personal' AND user_id IS NOT NULL AND project_id IS NULL)
        OR (kind = 'project' AND project_id IS NOT NULL AND user_id IS NULL
            AND scopes = ARRAY['analysis:write']::text[]))
);
--> statement-breakpoint
CREATE TABLE "branch_files" (
	"branch_id" uuid NOT NULL,
	"path" text NOT NULL,
	"language" text NOT NULL,
	"kind" text NOT NULL,
	"sha256" text NOT NULL,
	"metrics" jsonb,
	"coverage" jsonb,
	"new_lines" jsonb,
	"duplications" jsonb,
	"analysis_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "branch_files_branch_id_path_pk" PRIMARY KEY("branch_id","path"),
	CONSTRAINT "branch_files_kind_check" CHECK (kind IN ('main','test'))
);
--> statement-breakpoint
CREATE TABLE "branches" (
	"id" uuid PRIMARY KEY NOT NULL,
	"project_id" uuid NOT NULL,
	"kind" text NOT NULL,
	"name" text NOT NULL,
	"is_main" boolean DEFAULT false NOT NULL,
	"mr_source_branch" text,
	"mr_target_branch" text,
	"mr_title" text,
	"mr_url" text,
	"last_analysis_id" uuid,
	"last_analyzed_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "branches_kind_check" CHECK (kind IN ('branch','merge_request')),
	CONSTRAINT "branches_main_is_branch" CHECK (NOT is_main OR kind = 'branch')
);
--> statement-breakpoint
CREATE TABLE "gate_conditions" (
	"id" uuid PRIMARY KEY NOT NULL,
	"gate_id" uuid NOT NULL,
	"metric_key" text NOT NULL,
	"operator" text NOT NULL,
	"threshold" double precision NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "gate_conditions_operator_check" CHECK (operator IN ('gt','lt'))
);
--> statement-breakpoint
CREATE TABLE "instance_settings" (
	"key" text PRIMARY KEY NOT NULL,
	"value" jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "issue_changes" (
	"id" uuid PRIMARY KEY NOT NULL,
	"issue_id" uuid NOT NULL,
	"user_id" uuid,
	"analysis_id" uuid,
	"field" text NOT NULL,
	"old_value" text,
	"new_value" text,
	"comment" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "issue_changes_field_check" CHECK (field IN ('status','severity','comment')),
	CONSTRAINT "issue_changes_comment_length" CHECK (char_length(comment) <= 2000)
);
--> statement-breakpoint
CREATE TABLE "issues" (
	"id" uuid PRIMARY KEY NOT NULL,
	"project_id" uuid NOT NULL,
	"branch_id" uuid NOT NULL,
	"rule_id" uuid NOT NULL,
	"fingerprint" char(32) NOT NULL,
	"line_hash" text NOT NULL,
	"context_hash" text NOT NULL,
	"path" text,
	"start_line" integer,
	"start_column" integer,
	"end_line" integer,
	"end_column" integer,
	"message" text NOT NULL,
	"severity" text NOT NULL,
	"severity_rank" smallint GENERATED ALWAYS AS (CASE severity WHEN 'blocker' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END) STORED NOT NULL,
	"severity_overridden" boolean DEFAULT false NOT NULL,
	"quality" text NOT NULL,
	"kind" text NOT NULL,
	"status" text DEFAULT 'open' NOT NULL,
	"in_new_code" boolean DEFAULT false NOT NULL,
	"duplicate_of_issue_id" uuid,
	"snippet" jsonb,
	"secondary_locations" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"first_seen_analysis_id" uuid,
	"first_seen_at" timestamp with time zone NOT NULL,
	"last_seen_analysis_id" uuid,
	"resolved_at" timestamp with time zone,
	"resolved_by" uuid,
	"closed_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "issues_status_check" CHECK (status IN ('open','resolved','wont_fix','false_positive','closed')),
	CONSTRAINT "issues_severity_check" CHECK (severity IN ('blocker','high','medium','low','info')),
	CONSTRAINT "issues_quality_check" CHECK (quality IN ('security','reliability','maintainability')),
	CONSTRAINT "issues_kind_check" CHECK (kind IN ('issue','hotspot'))
);
--> statement-breakpoint
CREATE TABLE "jobs" (
	"id" uuid PRIMARY KEY NOT NULL,
	"queue" text NOT NULL,
	"concurrency_key" text,
	"payload" jsonb NOT NULL,
	"status" text DEFAULT 'queued' NOT NULL,
	"run_at" timestamp with time zone DEFAULT now() NOT NULL,
	"attempts" integer DEFAULT 0 NOT NULL,
	"max_attempts" integer DEFAULT 5 NOT NULL,
	"locked_by" text,
	"locked_until" timestamp with time zone,
	"last_error" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "jobs_status_check" CHECK (status IN ('queued','running','succeeded','failed','dead'))
);
--> statement-breakpoint
CREATE TABLE "measures" (
	"analysis_id" uuid NOT NULL,
	"metric_key" text NOT NULL,
	"scope" text NOT NULL,
	"value" double precision,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "measures_analysis_id_metric_key_scope_pk" PRIMARY KEY("analysis_id","metric_key","scope"),
	CONSTRAINT "measures_scope_check" CHECK (scope IN ('overall','new'))
);
--> statement-breakpoint
CREATE TABLE "memberships" (
	"organization_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"role" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "memberships_organization_id_user_id_pk" PRIMARY KEY("organization_id","user_id"),
	CONSTRAINT "memberships_role_check" CHECK (role IN ('admin','member'))
);
--> statement-breakpoint
CREATE TABLE "organizations" (
	"id" uuid PRIMARY KEY NOT NULL,
	"key" text NOT NULL,
	"name" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "organizations_key_unique" UNIQUE("key"),
	CONSTRAINT "organizations_key_format" CHECK (key ~ '^[a-z0-9][a-z0-9-]{1,63}$')
);
--> statement-breakpoint
CREATE TABLE "profile_rules" (
	"profile_id" uuid NOT NULL,
	"rule_id" uuid NOT NULL,
	"active" boolean NOT NULL,
	"severity_override" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "profile_rules_profile_id_rule_id_pk" PRIMARY KEY("profile_id","rule_id"),
	CONSTRAINT "profile_rules_severity_check" CHECK (severity_override IN ('blocker','high','medium','low','info'))
);
--> statement-breakpoint
CREATE TABLE "project_profiles" (
	"project_id" uuid NOT NULL,
	"language" text NOT NULL,
	"profile_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "project_profiles_project_id_language_pk" PRIMARY KEY("project_id","language")
);
--> statement-breakpoint
CREATE TABLE "projects" (
	"id" uuid PRIMARY KEY NOT NULL,
	"organization_id" uuid NOT NULL,
	"key" text NOT NULL,
	"name" text NOT NULL,
	"main_branch_name" text DEFAULT 'main' NOT NULL,
	"quality_gate_id" uuid,
	"new_code_definition" jsonb,
	"scm_connection_id" uuid,
	"scm_project_ref" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "projects_key_unique" UNIQUE("key"),
	CONSTRAINT "projects_key_format" CHECK (key ~ '^[A-Za-z0-9._/:-]{1,255}$')
);
--> statement-breakpoint
CREATE TABLE "quality_gates" (
	"id" uuid PRIMARY KEY NOT NULL,
	"organization_id" uuid NOT NULL,
	"name" text NOT NULL,
	"is_default" boolean DEFAULT false NOT NULL,
	"is_builtin" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "quality_profiles" (
	"id" uuid PRIMARY KEY NOT NULL,
	"organization_id" uuid NOT NULL,
	"name" text NOT NULL,
	"language" text NOT NULL,
	"parent_id" uuid,
	"is_default" boolean DEFAULT false NOT NULL,
	"is_builtin" boolean DEFAULT false NOT NULL,
	"unknown_rules" text DEFAULT 'activate' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "quality_profiles_unknown_rules_check" CHECK (unknown_rules IN ('activate','ignore'))
);
--> statement-breakpoint
CREATE TABLE "rules" (
	"id" uuid PRIMARY KEY NOT NULL,
	"key" text NOT NULL,
	"engine_id" text NOT NULL,
	"engine_rule_id" text NOT NULL,
	"name" text NOT NULL,
	"description_md" text,
	"help_uri" text,
	"languages" text[] DEFAULT '{}'::text[] NOT NULL,
	"default_severity" text NOT NULL,
	"quality" text NOT NULL,
	"kind" text NOT NULL,
	"tags" text[] DEFAULT '{}'::text[] NOT NULL,
	"cwe" integer[] DEFAULT '{}'::integer[] NOT NULL,
	"status" text DEFAULT 'ready' NOT NULL,
	"origin" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "rules_key_unique" UNIQUE("key"),
	CONSTRAINT "rules_default_severity_check" CHECK (default_severity IN ('blocker','high','medium','low','info')),
	CONSTRAINT "rules_quality_check" CHECK (quality IN ('security','reliability','maintainability')),
	CONSTRAINT "rules_kind_check" CHECK (kind IN ('issue','hotspot')),
	CONSTRAINT "rules_status_check" CHECK (status IN ('ready','deprecated','removed')),
	CONSTRAINT "rules_origin_check" CHECK (origin IN ('builtin','reported'))
);
--> statement-breakpoint
CREATE TABLE "scm_connections" (
	"id" uuid PRIMARY KEY NOT NULL,
	"organization_id" uuid NOT NULL,
	"provider" text NOT NULL,
	"base_url" text NOT NULL,
	"token_enc" jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "scm_connections_provider_check" CHECK (provider IN ('gitlab','github'))
);
--> statement-breakpoint
CREATE TABLE "sessions" (
	"id" "bytea" PRIMARY KEY NOT NULL,
	"user_id" uuid NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"last_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"ip" text,
	"user_agent" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" uuid PRIMARY KEY NOT NULL,
	"username" "citext" NOT NULL,
	"email" "citext",
	"display_name" text,
	"password_hash" text,
	"password_change_required" boolean DEFAULT false NOT NULL,
	"is_instance_admin" boolean DEFAULT false NOT NULL,
	"active" boolean DEFAULT true NOT NULL,
	"last_login_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "users_username_unique" UNIQUE("username"),
	CONSTRAINT "users_email_unique" UNIQUE("email")
);
--> statement-breakpoint
CREATE TABLE "webhook_deliveries" (
	"id" uuid PRIMARY KEY NOT NULL,
	"subscription_id" uuid NOT NULL,
	"event" text NOT NULL,
	"payload" jsonb NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"attempts" integer DEFAULT 0 NOT NULL,
	"response_code" integer,
	"response_excerpt" text,
	"next_attempt_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "webhook_deliveries_status_check" CHECK (status IN ('pending','succeeded','failed')),
	CONSTRAINT "webhook_deliveries_excerpt_length" CHECK (octet_length(response_excerpt) <= 1024)
);
--> statement-breakpoint
CREATE TABLE "webhook_subscriptions" (
	"id" uuid PRIMARY KEY NOT NULL,
	"organization_id" uuid NOT NULL,
	"project_id" uuid,
	"url" text NOT NULL,
	"secret_enc" jsonb NOT NULL,
	"events" text[] NOT NULL,
	"active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "analyses" ADD CONSTRAINT "analyses_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "analyses" ADD CONSTRAINT "analyses_branch_id_branches_id_fk" FOREIGN KEY ("branch_id") REFERENCES "public"."branches"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "analyses" ADD CONSTRAINT "analyses_uploaded_by_token_id_api_tokens_id_fk" FOREIGN KEY ("uploaded_by_token_id") REFERENCES "public"."api_tokens"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "analysis_reports" ADD CONSTRAINT "analysis_reports_analysis_id_analyses_id_fk" FOREIGN KEY ("analysis_id") REFERENCES "public"."analyses"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "api_tokens" ADD CONSTRAINT "api_tokens_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "api_tokens" ADD CONSTRAINT "api_tokens_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "api_tokens" ADD CONSTRAINT "api_tokens_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "branch_files" ADD CONSTRAINT "branch_files_branch_id_branches_id_fk" FOREIGN KEY ("branch_id") REFERENCES "public"."branches"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "branch_files" ADD CONSTRAINT "branch_files_analysis_id_analyses_id_fk" FOREIGN KEY ("analysis_id") REFERENCES "public"."analyses"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "branches" ADD CONSTRAINT "branches_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "branches" ADD CONSTRAINT "branches_last_analysis_id_analyses_id_fk" FOREIGN KEY ("last_analysis_id") REFERENCES "public"."analyses"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "gate_conditions" ADD CONSTRAINT "gate_conditions_gate_id_quality_gates_id_fk" FOREIGN KEY ("gate_id") REFERENCES "public"."quality_gates"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "issue_changes" ADD CONSTRAINT "issue_changes_issue_id_issues_id_fk" FOREIGN KEY ("issue_id") REFERENCES "public"."issues"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "issue_changes" ADD CONSTRAINT "issue_changes_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "issue_changes" ADD CONSTRAINT "issue_changes_analysis_id_analyses_id_fk" FOREIGN KEY ("analysis_id") REFERENCES "public"."analyses"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "issues" ADD CONSTRAINT "issues_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "issues" ADD CONSTRAINT "issues_branch_id_branches_id_fk" FOREIGN KEY ("branch_id") REFERENCES "public"."branches"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "issues" ADD CONSTRAINT "issues_rule_id_rules_id_fk" FOREIGN KEY ("rule_id") REFERENCES "public"."rules"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "issues" ADD CONSTRAINT "issues_duplicate_of_issue_id_issues_id_fk" FOREIGN KEY ("duplicate_of_issue_id") REFERENCES "public"."issues"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "issues" ADD CONSTRAINT "issues_first_seen_analysis_id_analyses_id_fk" FOREIGN KEY ("first_seen_analysis_id") REFERENCES "public"."analyses"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "issues" ADD CONSTRAINT "issues_last_seen_analysis_id_analyses_id_fk" FOREIGN KEY ("last_seen_analysis_id") REFERENCES "public"."analyses"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "issues" ADD CONSTRAINT "issues_resolved_by_users_id_fk" FOREIGN KEY ("resolved_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "measures" ADD CONSTRAINT "measures_analysis_id_analyses_id_fk" FOREIGN KEY ("analysis_id") REFERENCES "public"."analyses"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "memberships" ADD CONSTRAINT "memberships_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "memberships" ADD CONSTRAINT "memberships_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "profile_rules" ADD CONSTRAINT "profile_rules_profile_id_quality_profiles_id_fk" FOREIGN KEY ("profile_id") REFERENCES "public"."quality_profiles"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "profile_rules" ADD CONSTRAINT "profile_rules_rule_id_rules_id_fk" FOREIGN KEY ("rule_id") REFERENCES "public"."rules"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "project_profiles" ADD CONSTRAINT "project_profiles_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "project_profiles" ADD CONSTRAINT "project_profiles_profile_id_quality_profiles_id_fk" FOREIGN KEY ("profile_id") REFERENCES "public"."quality_profiles"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "projects" ADD CONSTRAINT "projects_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "projects" ADD CONSTRAINT "projects_quality_gate_id_quality_gates_id_fk" FOREIGN KEY ("quality_gate_id") REFERENCES "public"."quality_gates"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "projects" ADD CONSTRAINT "projects_scm_connection_id_scm_connections_id_fk" FOREIGN KEY ("scm_connection_id") REFERENCES "public"."scm_connections"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "quality_gates" ADD CONSTRAINT "quality_gates_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "quality_profiles" ADD CONSTRAINT "quality_profiles_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "quality_profiles" ADD CONSTRAINT "quality_profiles_parent_id_quality_profiles_id_fk" FOREIGN KEY ("parent_id") REFERENCES "public"."quality_profiles"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scm_connections" ADD CONSTRAINT "scm_connections_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "webhook_deliveries" ADD CONSTRAINT "webhook_deliveries_subscription_id_webhook_subscriptions_id_fk" FOREIGN KEY ("subscription_id") REFERENCES "public"."webhook_subscriptions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "webhook_subscriptions" ADD CONSTRAINT "webhook_subscriptions_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "webhook_subscriptions" ADD CONSTRAINT "webhook_subscriptions_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "analyses_branch_idx" ON "analyses" USING btree ("branch_id","id");--> statement-breakpoint
CREATE INDEX "analyses_project_idx" ON "analyses" USING btree ("project_id","id");--> statement-breakpoint
CREATE INDEX "analyses_uploaded_by_token_idx" ON "analyses" USING btree ("uploaded_by_token_id") WHERE uploaded_by_token_id IS NOT NULL;--> statement-breakpoint
CREATE INDEX "api_tokens_prefix_idx" ON "api_tokens" USING btree ("prefix");--> statement-breakpoint
CREATE INDEX "api_tokens_user_idx" ON "api_tokens" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "api_tokens_project_idx" ON "api_tokens" USING btree ("project_id");--> statement-breakpoint
CREATE INDEX "api_tokens_created_by_idx" ON "api_tokens" USING btree ("created_by") WHERE created_by IS NOT NULL;--> statement-breakpoint
CREATE INDEX "branch_files_analysis_idx" ON "branch_files" USING btree ("analysis_id");--> statement-breakpoint
CREATE UNIQUE INDEX "branches_project_kind_name" ON "branches" USING btree ("project_id","kind","name");--> statement-breakpoint
CREATE INDEX "branches_last_analysis_idx" ON "branches" USING btree ("last_analysis_id") WHERE last_analysis_id IS NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "branches_one_main" ON "branches" USING btree ("project_id") WHERE is_main;--> statement-breakpoint
CREATE UNIQUE INDEX "gate_conditions_gate_metric" ON "gate_conditions" USING btree ("gate_id","metric_key");--> statement-breakpoint
CREATE INDEX "issue_changes_issue_idx" ON "issue_changes" USING btree ("issue_id","id");--> statement-breakpoint
CREATE INDEX "issue_changes_user_idx" ON "issue_changes" USING btree ("user_id") WHERE user_id IS NOT NULL;--> statement-breakpoint
CREATE INDEX "issue_changes_analysis_idx" ON "issue_changes" USING btree ("analysis_id") WHERE analysis_id IS NOT NULL;--> statement-breakpoint
CREATE INDEX "issues_default_list_idx" ON "issues" USING btree ("branch_id","status","severity_rank","id");--> statement-breakpoint
CREATE INDEX "issues_rule_idx" ON "issues" USING btree ("branch_id","rule_id","status");--> statement-breakpoint
CREATE INDEX "issues_path_idx" ON "issues" USING btree ("branch_id","path","start_line");--> statement-breakpoint
CREATE INDEX "issues_fingerprint_idx" ON "issues" USING btree ("branch_id","fingerprint");--> statement-breakpoint
CREATE INDEX "issues_new_code_idx" ON "issues" USING btree ("branch_id","in_new_code") WHERE status = 'open';--> statement-breakpoint
CREATE INDEX "issues_message_trgm_idx" ON "issues" USING gin (message gin_trgm_ops);--> statement-breakpoint
CREATE INDEX "issues_project_idx" ON "issues" USING btree ("project_id");--> statement-breakpoint
CREATE INDEX "issues_rule_id_idx" ON "issues" USING btree ("rule_id");--> statement-breakpoint
CREATE INDEX "issues_duplicate_of_idx" ON "issues" USING btree ("duplicate_of_issue_id") WHERE duplicate_of_issue_id IS NOT NULL;--> statement-breakpoint
CREATE INDEX "issues_first_seen_analysis_idx" ON "issues" USING btree ("first_seen_analysis_id") WHERE first_seen_analysis_id IS NOT NULL;--> statement-breakpoint
CREATE INDEX "issues_last_seen_analysis_idx" ON "issues" USING btree ("last_seen_analysis_id") WHERE last_seen_analysis_id IS NOT NULL;--> statement-breakpoint
CREATE INDEX "issues_resolved_by_idx" ON "issues" USING btree ("resolved_by") WHERE resolved_by IS NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "jobs_one_running_per_key" ON "jobs" USING btree ("concurrency_key") WHERE status = 'running';--> statement-breakpoint
CREATE INDEX "jobs_dequeue_idx" ON "jobs" USING btree ("queue","run_at","id") WHERE status = 'queued';--> statement-breakpoint
CREATE INDEX "jobs_key_queued_idx" ON "jobs" USING btree ("concurrency_key","id") WHERE status = 'queued';--> statement-breakpoint
CREATE INDEX "jobs_lease_idx" ON "jobs" USING btree ("locked_until") WHERE status = 'running';--> statement-breakpoint
CREATE INDEX "memberships_user_idx" ON "memberships" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "profile_rules_rule_idx" ON "profile_rules" USING btree ("rule_id");--> statement-breakpoint
CREATE INDEX "project_profiles_profile_idx" ON "project_profiles" USING btree ("profile_id");--> statement-breakpoint
CREATE INDEX "projects_organization_idx" ON "projects" USING btree ("organization_id");--> statement-breakpoint
CREATE INDEX "projects_quality_gate_idx" ON "projects" USING btree ("quality_gate_id") WHERE quality_gate_id IS NOT NULL;--> statement-breakpoint
CREATE INDEX "projects_scm_connection_idx" ON "projects" USING btree ("scm_connection_id") WHERE scm_connection_id IS NOT NULL;--> statement-breakpoint
CREATE INDEX "quality_gates_organization_idx" ON "quality_gates" USING btree ("organization_id");--> statement-breakpoint
CREATE UNIQUE INDEX "quality_gates_one_default" ON "quality_gates" USING btree ("organization_id") WHERE is_default;--> statement-breakpoint
CREATE UNIQUE INDEX "quality_profiles_org_language_name" ON "quality_profiles" USING btree ("organization_id","language","name");--> statement-breakpoint
CREATE INDEX "quality_profiles_parent_idx" ON "quality_profiles" USING btree ("parent_id") WHERE parent_id IS NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "quality_profiles_one_default" ON "quality_profiles" USING btree ("organization_id","language") WHERE is_default;--> statement-breakpoint
CREATE INDEX "scm_connections_organization_idx" ON "scm_connections" USING btree ("organization_id");--> statement-breakpoint
CREATE INDEX "sessions_user_idx" ON "sessions" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "webhook_deliveries_due_idx" ON "webhook_deliveries" USING btree ("status","next_attempt_at");--> statement-breakpoint
CREATE INDEX "webhook_deliveries_subscription_idx" ON "webhook_deliveries" USING btree ("subscription_id","id");--> statement-breakpoint
CREATE INDEX "webhook_subscriptions_organization_idx" ON "webhook_subscriptions" USING btree ("organization_id");--> statement-breakpoint
CREATE INDEX "webhook_subscriptions_project_idx" ON "webhook_subscriptions" USING btree ("project_id") WHERE project_id IS NOT NULL;