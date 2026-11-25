ALTER TABLE "projects" ADD COLUMN "cleanup_branches_days" integer;--> statement-breakpoint
ALTER TABLE "projects" ADD COLUMN "cleanup_merge_requests_days" integer;--> statement-breakpoint
ALTER TABLE "projects" ADD COLUMN "cleanup_keep_branches" text[] DEFAULT '{}'::text[] NOT NULL;--> statement-breakpoint
ALTER TABLE "projects" ADD CONSTRAINT "projects_cleanup_branches_days_check" CHECK (cleanup_branches_days IS NULL OR (cleanup_branches_days BETWEEN 0 AND 3650));--> statement-breakpoint
ALTER TABLE "projects" ADD CONSTRAINT "projects_cleanup_merge_requests_days_check" CHECK (cleanup_merge_requests_days IS NULL OR (cleanup_merge_requests_days BETWEEN 0 AND 3650));--> statement-breakpoint
ALTER TABLE "projects" ADD CONSTRAINT "projects_cleanup_keep_branches_check" CHECK (cardinality(cleanup_keep_branches) <= 20);