CREATE TABLE "jira_connections" (
	"id" uuid PRIMARY KEY NOT NULL,
	"organization_id" uuid NOT NULL,
	"deployment" text NOT NULL,
	"site_url" text NOT NULL,
	"api_url" text,
	"email" text,
	"token_enc" jsonb NOT NULL,
	"problem" jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "jira_connections_deployment_check" CHECK (deployment IN ('cloud','data_center')),
	CONSTRAINT "jira_connections_api_url_check" CHECK (api_url IS NULL OR deployment = 'cloud'),
	CONSTRAINT "jira_connections_email_check" CHECK ((deployment = 'cloud') = (email IS NOT NULL))
);
--> statement-breakpoint
CREATE TABLE "jira_links" (
	"id" uuid PRIMARY KEY NOT NULL,
	"project_id" uuid NOT NULL,
	"connection_id" uuid NOT NULL,
	"kind" text NOT NULL,
	"issue_id" uuid,
	"package_name" text,
	"vulnerability_id" text,
	"state" text NOT NULL,
	"origin" text NOT NULL,
	"generation" smallint DEFAULT 1 NOT NULL,
	"attempted_at" timestamp with time zone,
	"failure" jsonb,
	"jira_issue_id" text,
	"jira_key" text,
	"status_name" text,
	"status_category" text,
	"status_checked_at" timestamp with time zone,
	"missed_passes" smallint DEFAULT 0 NOT NULL,
	"reported_fixed_at" timestamp with time zone,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "jira_links_kind_check" CHECK (kind IN ('issue','vulnerability')),
	CONSTRAINT "jira_links_target_check" CHECK ((kind = 'issue' AND issue_id IS NOT NULL AND package_name IS NULL AND vulnerability_id IS NULL) OR (kind = 'vulnerability' AND issue_id IS NULL AND package_name IS NOT NULL AND vulnerability_id IS NOT NULL)),
	CONSTRAINT "jira_links_state_check" CHECK (state IN ('pending','created','failed','missing','dismissed')),
	CONSTRAINT "jira_links_origin_check" CHECK (origin IN ('manual','auto')),
	CONSTRAINT "jira_links_jira_check" CHECK (state NOT IN ('created','missing') OR (jira_issue_id IS NOT NULL AND jira_key IS NOT NULL)),
	CONSTRAINT "jira_links_status_category_check" CHECK (status_category IS NULL OR status_category IN ('new','indeterminate','done'))
);
--> statement-breakpoint
CREATE TABLE "project_jira_settings" (
	"project_id" uuid PRIMARY KEY NOT NULL,
	"connection_id" uuid NOT NULL,
	"jira_project_id" text NOT NULL,
	"jira_project_key" text NOT NULL,
	"jira_project_name" text NOT NULL,
	"issue_type_id" text NOT NULL,
	"issue_type_name" text NOT NULL,
	"labels" text[] DEFAULT '{}'::text[] NOT NULL,
	"priorities" jsonb,
	"labels_available" boolean NOT NULL,
	"priority_available" boolean NOT NULL,
	"auto_min_severity" text,
	"auto_exploited" boolean DEFAULT false NOT NULL,
	"auto_since" timestamp with time zone,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "project_jira_settings_labels_check" CHECK (cardinality(labels) <= 10),
	CONSTRAINT "project_jira_settings_auto_severity_check" CHECK (auto_min_severity IS NULL OR auto_min_severity IN ('critical','high','medium','low')),
	CONSTRAINT "project_jira_settings_auto_since_check" CHECK ((auto_min_severity IS NULL AND NOT auto_exploited) OR auto_since IS NOT NULL)
);
--> statement-breakpoint
ALTER TABLE "jira_connections" ADD CONSTRAINT "jira_connections_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "jira_links" ADD CONSTRAINT "jira_links_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "jira_links" ADD CONSTRAINT "jira_links_connection_id_jira_connections_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."jira_connections"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "jira_links" ADD CONSTRAINT "jira_links_issue_id_issues_id_fk" FOREIGN KEY ("issue_id") REFERENCES "public"."issues"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "jira_links" ADD CONSTRAINT "jira_links_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "project_jira_settings" ADD CONSTRAINT "project_jira_settings_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "project_jira_settings" ADD CONSTRAINT "project_jira_settings_connection_id_jira_connections_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."jira_connections"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "jira_connections_organization_uq" ON "jira_connections" USING btree ("organization_id");--> statement-breakpoint
CREATE UNIQUE INDEX "jira_links_issue_uq" ON "jira_links" USING btree ("issue_id");--> statement-breakpoint
CREATE UNIQUE INDEX "jira_links_vulnerability_uq" ON "jira_links" USING btree ("project_id","package_name","vulnerability_id") WHERE kind = 'vulnerability';--> statement-breakpoint
CREATE INDEX "jira_links_pass_idx" ON "jira_links" USING btree ("connection_id","state","status_checked_at" NULLS FIRST);--> statement-breakpoint
CREATE INDEX "jira_links_project_idx" ON "jira_links" USING btree ("project_id");--> statement-breakpoint
CREATE INDEX "jira_links_created_by_idx" ON "jira_links" USING btree ("created_by") WHERE created_by IS NOT NULL;--> statement-breakpoint
CREATE INDEX "project_jira_settings_connection_idx" ON "project_jira_settings" USING btree ("connection_id");