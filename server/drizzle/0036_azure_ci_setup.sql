ALTER TABLE "repository_setup_items" ADD COLUMN "azure_pipeline_id" integer;--> statement-breakpoint
ALTER TABLE "repository_setup_items" ADD COLUMN "azure_queue" text;--> statement-breakpoint
ALTER TABLE "repository_setup_items" ADD COLUMN "azure_policy" text;--> statement-breakpoint
ALTER TABLE "repository_setup_items" ADD COLUMN "azure_policy_error" text;--> statement-breakpoint
ALTER TABLE "repository_setup_runs" ADD COLUMN "azure_pool" text;--> statement-breakpoint
ALTER TABLE "repository_setup_items" ADD CONSTRAINT "repository_setup_items_azure_queue_check" CHECK (azure_queue IS NULL OR azure_queue IN ('authorized','open','manual'));--> statement-breakpoint
ALTER TABLE "repository_setup_items" ADD CONSTRAINT "repository_setup_items_azure_policy_check" CHECK (azure_policy IS NULL OR azure_policy IN ('pending','on','manual','failed'));