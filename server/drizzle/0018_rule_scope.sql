ALTER TABLE "profile_rules" ADD COLUMN "scope_override" text;--> statement-breakpoint
ALTER TABLE "rules" ADD COLUMN "scope" text DEFAULT 'all' NOT NULL;--> statement-breakpoint
ALTER TABLE "profile_rules" ADD CONSTRAINT "profile_rules_scope_check" CHECK (scope_override IN ('main','test','all'));--> statement-breakpoint
ALTER TABLE "rules" ADD CONSTRAINT "rules_scope_check" CHECK (scope IN ('main','test','all'));