ALTER TABLE "compliance_reports" ADD COLUMN "version_id" uuid;--> statement-breakpoint
ALTER TABLE "compliance_reports" ADD COLUMN "sbom" "bytea";--> statement-breakpoint
ALTER TABLE "compliance_reports" ADD COLUMN "sbom_sha256" char(64);--> statement-breakpoint
ALTER TABLE "compliance_reports" ADD CONSTRAINT "compliance_reports_version_id_project_versions_id_fk" FOREIGN KEY ("version_id") REFERENCES "public"."project_versions"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "compliance_reports_version_idx" ON "compliance_reports" USING btree ("version_id") WHERE version_id IS NOT NULL;--> statement-breakpoint
ALTER TABLE "compliance_reports" ADD CONSTRAINT "compliance_reports_target_check" CHECK (branch_id IS NULL OR version_id IS NULL);--> statement-breakpoint
ALTER TABLE "compliance_reports" ADD CONSTRAINT "compliance_reports_sbom_sha256_format" CHECK (sbom_sha256 IS NULL OR sbom_sha256 ~ '^[0-9a-f]{64}$');--> statement-breakpoint
ALTER TABLE "compliance_reports" ADD CONSTRAINT "compliance_reports_sbom_check" CHECK ((sbom IS NULL) = (sbom_sha256 IS NULL));