CREATE TABLE "llm_requests" (
	"id" uuid PRIMARY KEY NOT NULL,
	"organization_id" uuid NOT NULL,
	"project_id" uuid NOT NULL,
	"issue_id" uuid,
	"user_id" uuid,
	"feature" text NOT NULL,
	"cache_key" char(64) NOT NULL,
	"provider" text NOT NULL,
	"provider_host" text NOT NULL,
	"model" text NOT NULL,
	"prompt_version" text NOT NULL,
	"status" text DEFAULT 'queued' NOT NULL,
	"error_code" text,
	"attempts" smallint DEFAULT 0 NOT NULL,
	"input_sha256" char(64) NOT NULL,
	"input_bytes" integer NOT NULL,
	"fields" text[] NOT NULL,
	"redactions" integer DEFAULT 0 NOT NULL,
	"input_tokens" integer,
	"output_tokens" integer,
	"cost_micro_usd" bigint,
	"duration_ms" integer,
	"result" jsonb,
	"prompt" jsonb,
	"post" jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"finished_at" timestamp with time zone,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "llm_requests_feature_check" CHECK (feature IN ('explain','triage','fix')),
	CONSTRAINT "llm_requests_status_check" CHECK (status IN ('queued','running','succeeded','failed')),
	CONSTRAINT "llm_requests_result_check" CHECK (result IS NULL OR status = 'succeeded'),
	CONSTRAINT "llm_requests_result_size" CHECK (result IS NULL OR octet_length(result::text) <= 16384),
	CONSTRAINT "llm_requests_prompt_size" CHECK (prompt IS NULL OR octet_length(prompt::text) <= 65536)
);
--> statement-breakpoint
ALTER TABLE "llm_requests" ADD CONSTRAINT "llm_requests_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "llm_requests" ADD CONSTRAINT "llm_requests_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "llm_requests" ADD CONSTRAINT "llm_requests_issue_id_issues_id_fk" FOREIGN KEY ("issue_id") REFERENCES "public"."issues"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "llm_requests" ADD CONSTRAINT "llm_requests_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "llm_requests_organization_idx" ON "llm_requests" USING btree ("organization_id","created_at");--> statement-breakpoint
CREATE INDEX "llm_requests_cache_idx" ON "llm_requests" USING btree ("organization_id","feature","cache_key","created_at" DESC NULLS LAST) WHERE status = 'succeeded';--> statement-breakpoint
CREATE INDEX "llm_requests_issue_idx" ON "llm_requests" USING btree ("issue_id","feature","created_at" DESC NULLS LAST) WHERE issue_id IS NOT NULL;--> statement-breakpoint
CREATE INDEX "llm_requests_project_idx" ON "llm_requests" USING btree ("project_id");--> statement-breakpoint
CREATE INDEX "llm_requests_user_idx" ON "llm_requests" USING btree ("user_id") WHERE user_id IS NOT NULL;