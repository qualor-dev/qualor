CREATE TABLE "boards_links" (
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
	"work_item_id" integer,
	"state_name" text,
	"state_category" text,
	"state_checked_at" timestamp with time zone,
	"missed_passes" smallint DEFAULT 0 NOT NULL,
	"reported_fixed_at" timestamp with time zone,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "boards_links_kind_check" CHECK (kind IN ('issue','vulnerability')),
	CONSTRAINT "boards_links_target_check" CHECK ((kind = 'issue' AND issue_id IS NOT NULL AND package_name IS NULL AND vulnerability_id IS NULL) OR (kind = 'vulnerability' AND issue_id IS NULL AND package_name IS NOT NULL AND vulnerability_id IS NOT NULL)),
	CONSTRAINT "boards_links_state_check" CHECK (state IN ('pending','created','failed','missing','dismissed')),
	CONSTRAINT "boards_links_origin_check" CHECK (origin IN ('manual','auto')),
	CONSTRAINT "boards_links_work_item_check" CHECK (state NOT IN ('created','missing') OR work_item_id IS NOT NULL),
	CONSTRAINT "boards_links_state_category_check" CHECK (state_category IS NULL OR state_category IN ('proposed','inprogress','resolved','completed','removed'))
);
--> statement-breakpoint
CREATE TABLE "project_boards_settings" (
	"project_id" uuid PRIMARY KEY NOT NULL,
	"connection_id" uuid NOT NULL,
	"azure_project_id" text NOT NULL,
	"azure_project_name" text NOT NULL,
	"work_item_type_ref" text NOT NULL,
	"work_item_type_name" text NOT NULL,
	"area_path" text,
	"iteration_path" text,
	"tags" text[] DEFAULT '{}'::text[] NOT NULL,
	"auto_min_severity" text,
	"auto_exploited" boolean DEFAULT false NOT NULL,
	"auto_since" timestamp with time zone,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "project_boards_settings_azure_project_check" CHECK (azure_project_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
	CONSTRAINT "project_boards_settings_tags_check" CHECK (cardinality(tags) <= 10),
	CONSTRAINT "project_boards_settings_auto_severity_check" CHECK (auto_min_severity IS NULL OR auto_min_severity IN ('critical','high','medium','low')),
	CONSTRAINT "project_boards_settings_auto_since_check" CHECK ((auto_min_severity IS NULL AND NOT auto_exploited) OR auto_since IS NOT NULL)
);
--> statement-breakpoint
ALTER TABLE "boards_links" ADD CONSTRAINT "boards_links_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "boards_links" ADD CONSTRAINT "boards_links_connection_id_scm_connections_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."scm_connections"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "boards_links" ADD CONSTRAINT "boards_links_issue_id_issues_id_fk" FOREIGN KEY ("issue_id") REFERENCES "public"."issues"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "boards_links" ADD CONSTRAINT "boards_links_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "project_boards_settings" ADD CONSTRAINT "project_boards_settings_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "project_boards_settings" ADD CONSTRAINT "project_boards_settings_connection_id_scm_connections_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."scm_connections"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "boards_links_issue_uq" ON "boards_links" USING btree ("issue_id");--> statement-breakpoint
CREATE UNIQUE INDEX "boards_links_vulnerability_uq" ON "boards_links" USING btree ("project_id","package_name","vulnerability_id") WHERE kind = 'vulnerability';--> statement-breakpoint
CREATE INDEX "boards_links_pass_idx" ON "boards_links" USING btree ("connection_id","state","state_checked_at" NULLS FIRST);--> statement-breakpoint
CREATE INDEX "boards_links_project_idx" ON "boards_links" USING btree ("project_id");--> statement-breakpoint
CREATE INDEX "boards_links_created_by_idx" ON "boards_links" USING btree ("created_by") WHERE created_by IS NOT NULL;--> statement-breakpoint
CREATE INDEX "project_boards_settings_connection_idx" ON "project_boards_settings" USING btree ("connection_id");