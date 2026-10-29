CREATE TABLE "repository_setup_items" (
	"run_id" uuid NOT NULL,
	"position" integer NOT NULL,
	"repository_ref" text NOT NULL,
	"repository_name" text NOT NULL,
	"project_outcome" text DEFAULT 'pending' NOT NULL,
	"project_id" uuid,
	"ci_outcome" text DEFAULT 'pending' NOT NULL,
	"ci_url" text,
	"ci_reason" text,
	"snippet" text,
	"token_enc" jsonb,
	"error_code" text,
	"error_message" text,
	CONSTRAINT "repository_setup_items_run_id_position_pk" PRIMARY KEY("run_id","position"),
	CONSTRAINT "repository_setup_items_project_outcome_check" CHECK (project_outcome IN ('pending','created','adopted','failed')),
	CONSTRAINT "repository_setup_items_ci_outcome_check" CHECK (ci_outcome IN ('pending','merge_request','snippet','already','skipped','failed'))
);
--> statement-breakpoint
CREATE TABLE "repository_setup_runs" (
	"id" uuid PRIMARY KEY NOT NULL,
	"organization_id" uuid NOT NULL,
	"connection_id" uuid,
	"created_by" uuid,
	"ci_setup" boolean DEFAULT false NOT NULL,
	"status" text DEFAULT 'queued' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"finished_at" timestamp with time zone,
	CONSTRAINT "repository_setup_runs_status_check" CHECK (status IN ('queued','running','done'))
);
--> statement-breakpoint
CREATE TABLE "setup_checklist_closures" (
	"user_id" uuid NOT NULL,
	"organization_id" uuid NOT NULL,
	"closed_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "setup_checklist_closures_user_id_organization_id_pk" PRIMARY KEY("user_id","organization_id")
);
--> statement-breakpoint
ALTER TABLE "scm_connections" ADD COLUMN "ci_setup_allowed" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "repository_setup_items" ADD CONSTRAINT "repository_setup_items_run_id_repository_setup_runs_id_fk" FOREIGN KEY ("run_id") REFERENCES "public"."repository_setup_runs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "repository_setup_items" ADD CONSTRAINT "repository_setup_items_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "repository_setup_runs" ADD CONSTRAINT "repository_setup_runs_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "repository_setup_runs" ADD CONSTRAINT "repository_setup_runs_connection_id_scm_connections_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."scm_connections"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "repository_setup_runs" ADD CONSTRAINT "repository_setup_runs_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "setup_checklist_closures" ADD CONSTRAINT "setup_checklist_closures_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "setup_checklist_closures" ADD CONSTRAINT "setup_checklist_closures_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "repository_setup_items_project_idx" ON "repository_setup_items" USING btree ("project_id") WHERE project_id IS NOT NULL;--> statement-breakpoint
CREATE INDEX "repository_setup_runs_organization_idx" ON "repository_setup_runs" USING btree ("organization_id");--> statement-breakpoint
CREATE INDEX "repository_setup_runs_connection_idx" ON "repository_setup_runs" USING btree ("connection_id") WHERE connection_id IS NOT NULL;--> statement-breakpoint
CREATE INDEX "repository_setup_runs_created_by_idx" ON "repository_setup_runs" USING btree ("created_by") WHERE created_by IS NOT NULL;--> statement-breakpoint
CREATE INDEX "setup_checklist_closures_organization_idx" ON "setup_checklist_closures" USING btree ("organization_id");