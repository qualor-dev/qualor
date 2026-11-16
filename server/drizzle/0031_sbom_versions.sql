ALTER TABLE "project_versions" DROP CONSTRAINT "project_versions_source_check";--> statement-breakpoint
ALTER TABLE "project_versions" ADD COLUMN "os_family" text;--> statement-breakpoint
ALTER TABLE "project_versions" ADD COLUMN "os_version" text;--> statement-breakpoint
ALTER TABLE "project_versions" ADD COLUMN "sbom_format" text;--> statement-breakpoint
ALTER TABLE "project_versions" ADD COLUMN "sbom_subject" text;--> statement-breakpoint
ALTER TABLE "version_dependencies" ADD COLUMN "source_name" text;--> statement-breakpoint
ALTER TABLE "version_dependencies" ADD COLUMN "source_version" text;--> statement-breakpoint
CREATE INDEX "branch_dependencies_name_trgm_idx" ON "branch_dependencies" USING gin (name gin_trgm_ops);--> statement-breakpoint
CREATE INDEX "version_dependencies_name_trgm_idx" ON "version_dependencies" USING gin (name gin_trgm_ops);--> statement-breakpoint
ALTER TABLE "project_versions" ADD CONSTRAINT "project_versions_os_check" CHECK ((os_family IS NULL) = (os_version IS NULL) AND (os_family IS NULL OR (char_length(os_family) <= 64 AND char_length(os_version) <= 64)));--> statement-breakpoint
ALTER TABLE "project_versions" ADD CONSTRAINT "project_versions_sbom_check" CHECK ((sbom_format IS NULL OR char_length(sbom_format) <= 32) AND (sbom_subject IS NULL OR char_length(sbom_subject) <= 512));--> statement-breakpoint
ALTER TABLE "project_versions" ADD CONSTRAINT "project_versions_source_check" CHECK (source IN ('tag','label','sbom'));--> statement-breakpoint
ALTER TABLE "version_dependencies" ADD CONSTRAINT "version_dependencies_source_check" CHECK ((source_name IS NULL OR char_length(source_name) <= 512) AND (source_version IS NULL OR char_length(source_version) <= 256));