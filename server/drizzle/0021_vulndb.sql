CREATE TABLE "matched_packages" (
	"purl" text PRIMARY KEY NOT NULL,
	"dataset_digest" text NOT NULL,
	"matched_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "target_vulnerabilities" (
	"id" uuid PRIMARY KEY NOT NULL,
	"project_id" uuid NOT NULL,
	"branch_id" uuid,
	"version_id" uuid,
	"ecosystem" text NOT NULL,
	"package_name" text NOT NULL,
	"package_version" text NOT NULL,
	"purl" text NOT NULL,
	"vulnerability_id" text NOT NULL,
	"ignored" boolean DEFAULT false NOT NULL,
	"first_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "target_vulnerabilities_one_target" CHECK ((branch_id IS NULL) <> (version_id IS NULL))
);
--> statement-breakpoint
CREATE TABLE "vulndb_chunks" (
	"dataset_id" uuid NOT NULL,
	"seq" integer NOT NULL,
	"data" "bytea" NOT NULL,
	CONSTRAINT "vulndb_chunks_dataset_id_seq_pk" PRIMARY KEY("dataset_id","seq")
);
--> statement-breakpoint
CREATE TABLE "vulndb_datasets" (
	"id" uuid PRIMARY KEY NOT NULL,
	"kind" text NOT NULL,
	"digest" text NOT NULL,
	"size_bytes" bigint NOT NULL,
	"built_at" timestamp with time zone,
	"source" text NOT NULL,
	"status" text NOT NULL,
	"chunk_count" integer DEFAULT 0 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "vulndb_datasets_kind_check" CHECK (kind IN ('trivy')),
	CONSTRAINT "vulndb_datasets_digest_check" CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "vulndb_datasets_source_check" CHECK (source IN ('official','mirror','upload')),
	CONSTRAINT "vulndb_datasets_status_check" CHECK (status IN ('incomplete','ready'))
);
--> statement-breakpoint
CREATE TABLE "vulnerability_matches" (
	"purl" text NOT NULL,
	"vulnerability_id" text NOT NULL,
	"severity" text NOT NULL,
	"title" text,
	"fixed_version" text,
	"primary_url" text,
	"published_at" timestamp with time zone,
	CONSTRAINT "vulnerability_matches_purl_vulnerability_id_pk" PRIMARY KEY("purl","vulnerability_id"),
	CONSTRAINT "vulnerability_matches_severity_check" CHECK (severity IN ('critical','high','medium','low','unknown'))
);
--> statement-breakpoint
ALTER TABLE "project_versions" ADD COLUMN "has_inventory" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "target_vulnerabilities" ADD CONSTRAINT "target_vulnerabilities_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "target_vulnerabilities" ADD CONSTRAINT "target_vulnerabilities_branch_id_branches_id_fk" FOREIGN KEY ("branch_id") REFERENCES "public"."branches"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "target_vulnerabilities" ADD CONSTRAINT "target_vulnerabilities_version_id_project_versions_id_fk" FOREIGN KEY ("version_id") REFERENCES "public"."project_versions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vulndb_chunks" ADD CONSTRAINT "vulndb_chunks_dataset_id_vulndb_datasets_id_fk" FOREIGN KEY ("dataset_id") REFERENCES "public"."vulndb_datasets"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "target_vulnerabilities_branch_uq" ON "target_vulnerabilities" USING btree ("branch_id","purl","vulnerability_id") WHERE branch_id IS NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "target_vulnerabilities_version_uq" ON "target_vulnerabilities" USING btree ("version_id","purl","vulnerability_id") WHERE version_id IS NOT NULL;--> statement-breakpoint
CREATE INDEX "target_vulnerabilities_project_idx" ON "target_vulnerabilities" USING btree ("project_id");--> statement-breakpoint
CREATE INDEX "vulndb_datasets_kind_created_idx" ON "vulndb_datasets" USING btree ("kind","created_at" DESC NULLS LAST);--> statement-breakpoint
UPDATE "project_versions" SET "has_inventory" = true WHERE EXISTS (SELECT 1 FROM "version_dependencies" WHERE "version_dependencies"."version_id" = "project_versions"."id");
