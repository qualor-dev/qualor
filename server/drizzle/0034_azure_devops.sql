ALTER TABLE "review_replies" DROP CONSTRAINT "review_replies_provider_check";--> statement-breakpoint
ALTER TABLE "scm_connections" DROP CONSTRAINT "scm_connections_provider_check";--> statement-breakpoint
ALTER TABLE "scm_connections" DROP CONSTRAINT "scm_connections_github_app_check";--> statement-breakpoint
ALTER TABLE "scm_connections" ADD COLUMN "azure_auth" text;--> statement-breakpoint
ALTER TABLE "scm_connections" ADD COLUMN "azure_tenant_id" text;--> statement-breakpoint
ALTER TABLE "scm_connections" ADD COLUMN "azure_client_id" text;--> statement-breakpoint
ALTER TABLE "review_replies" ADD CONSTRAINT "review_replies_provider_check" CHECK (provider IN ('gitlab','github','azure'));--> statement-breakpoint
ALTER TABLE "scm_connections" ADD CONSTRAINT "scm_connections_azure_auth_check" CHECK ((provider = 'azure') = (azure_auth IS NOT NULL) AND (azure_auth IS NULL OR azure_auth IN ('pat','service_principal_secret','service_principal_certificate')));--> statement-breakpoint
ALTER TABLE "scm_connections" ADD CONSTRAINT "scm_connections_azure_principal_check" CHECK (COALESCE(azure_auth IN ('service_principal_secret','service_principal_certificate'), false) = (azure_tenant_id IS NOT NULL AND azure_client_id IS NOT NULL) AND (azure_tenant_id IS NULL) = (azure_client_id IS NULL) AND (azure_tenant_id IS NULL OR azure_tenant_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') AND (azure_client_id IS NULL OR azure_client_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'));--> statement-breakpoint
ALTER TABLE "scm_connections" ADD CONSTRAINT "scm_connections_provider_check" CHECK (provider IN ('gitlab','github','azure'));--> statement-breakpoint
ALTER TABLE "scm_connections" ADD CONSTRAINT "scm_connections_github_app_check" CHECK ((provider = 'gitlab' AND app_id IS NULL) OR (provider = 'github' AND app_id IS NOT NULL AND app_id ~ '^[0-9]{1,20}$') OR (provider = 'azure' AND app_id IS NULL));