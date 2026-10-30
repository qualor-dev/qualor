CREATE TABLE "project_versions" (
	"id" uuid PRIMARY KEY NOT NULL,
	"project_id" uuid NOT NULL,
	"label" text NOT NULL,
	"source" text NOT NULL,
	"tag" text,
	"analysis_id" uuid,
	"analyzed_at" timestamp with time zone NOT NULL,
	"tracking" text DEFAULT 'auto' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "project_versions_label_check" CHECK (char_length(label) BETWEEN 1 AND 100),
	CONSTRAINT "project_versions_source_check" CHECK (source IN ('tag','label')),
	CONSTRAINT "project_versions_tracking_check" CHECK (tracking IN ('auto','pinned','unsupported'))
);
--> statement-breakpoint
CREATE TABLE "project_vulnerability_settings" (
	"project_id" uuid PRIMARY KEY NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"branch_patterns" text[] DEFAULT '{}'::text[] NOT NULL,
	"version_rule" text DEFAULT 'lines' NOT NULL,
	"version_lines" integer DEFAULT 5 NOT NULL,
	"label_versions" boolean DEFAULT false NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "project_vulnerability_settings_rule_check" CHECK (version_rule IN ('lines','all','none')),
	CONSTRAINT "project_vulnerability_settings_lines_check" CHECK (version_lines BETWEEN 1 AND 20)
);
--> statement-breakpoint
CREATE TABLE "version_dependencies" (
	"version_id" uuid NOT NULL,
	"path" text NOT NULL,
	"ecosystem" text NOT NULL,
	"name" text NOT NULL,
	"version" text NOT NULL,
	"licenses" text[] NOT NULL,
	"direct" boolean,
	"line" integer,
	"analysis_id" uuid NOT NULL,
	CONSTRAINT "version_dependencies_version_id_path_ecosystem_name_version_pk" PRIMARY KEY("version_id","path","ecosystem","name","version")
);
--> statement-breakpoint
ALTER TABLE "analyses" DROP CONSTRAINT "analyses_succeeded_is_complete";--> statement-breakpoint
ALTER TABLE "analyses" ADD COLUMN "version_id" uuid;--> statement-breakpoint
ALTER TABLE "analyses" ADD COLUMN "dependency_ignores" jsonb;--> statement-breakpoint
ALTER TABLE "project_versions" ADD CONSTRAINT "project_versions_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "project_versions" ADD CONSTRAINT "project_versions_analysis_id_analyses_id_fk" FOREIGN KEY ("analysis_id") REFERENCES "public"."analyses"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "project_vulnerability_settings" ADD CONSTRAINT "project_vulnerability_settings_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "version_dependencies" ADD CONSTRAINT "version_dependencies_version_id_project_versions_id_fk" FOREIGN KEY ("version_id") REFERENCES "public"."project_versions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "version_dependencies" ADD CONSTRAINT "version_dependencies_analysis_id_analyses_id_fk" FOREIGN KEY ("analysis_id") REFERENCES "public"."analyses"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "project_versions_project_label" ON "project_versions" USING btree ("project_id","label");--> statement-breakpoint
CREATE INDEX "project_versions_project_analyzed_idx" ON "project_versions" USING btree ("project_id","analyzed_at" DESC NULLS LAST);--> statement-breakpoint
CREATE INDEX "project_versions_analysis_idx" ON "project_versions" USING btree ("analysis_id") WHERE analysis_id IS NOT NULL;--> statement-breakpoint
CREATE INDEX "version_dependencies_licenses" ON "version_dependencies" USING gin ("licenses");--> statement-breakpoint
CREATE INDEX "version_dependencies_analysis_idx" ON "version_dependencies" USING btree ("analysis_id");--> statement-breakpoint
ALTER TABLE "analyses" ADD CONSTRAINT "analyses_version_id_project_versions_id_fk" FOREIGN KEY ("version_id") REFERENCES "public"."project_versions"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "analyses_version_idx" ON "analyses" USING btree ("version_id","id") WHERE version_id IS NOT NULL;--> statement-breakpoint
ALTER TABLE "analyses" ADD CONSTRAINT "analyses_one_target" CHECK (branch_id IS NULL OR version_id IS NULL);--> statement-breakpoint
ALTER TABLE "analyses" ADD CONSTRAINT "analyses_succeeded_is_complete" CHECK (status <> 'succeeded' OR ((branch_id IS NOT NULL OR version_id IS NOT NULL)
        AND revision IS NOT NULL AND analysis_date IS NOT NULL AND baseline_status IS NOT NULL
        AND scanner_version IS NOT NULL));