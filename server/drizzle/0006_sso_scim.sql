CREATE TABLE "identities" (
	"id" uuid PRIMARY KEY NOT NULL,
	"connection_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"subject" text,
	"linked_by" text NOT NULL,
	"scim_user_name" "citext",
	"scim_external_id" text,
	"scim_name" jsonb,
	"last_sign_in_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "identities_subject_length" CHECK (subject IS NULL OR char_length(subject) BETWEEN 1 AND 255),
	CONSTRAINT "identities_subject_or_scim_check" CHECK (subject IS NOT NULL OR scim_user_name IS NOT NULL),
	CONSTRAINT "identities_linked_by_check" CHECK (linked_by IN ('jit','verified_email','user','scim','scim_match'))
);
--> statement-breakpoint
CREATE TABLE "scim_group_members" (
	"group_id" uuid NOT NULL,
	"identity_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "scim_group_members_group_id_identity_id_pk" PRIMARY KEY("group_id","identity_id")
);
--> statement-breakpoint
CREATE TABLE "scim_groups" (
	"id" uuid PRIMARY KEY NOT NULL,
	"connection_id" uuid NOT NULL,
	"display_name" text NOT NULL,
	"external_id" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "scim_tokens" (
	"id" uuid PRIMARY KEY NOT NULL,
	"connection_id" uuid NOT NULL,
	"name" text NOT NULL,
	"prefix" text NOT NULL,
	"secret_hash" "bytea" NOT NULL,
	"expires_at" timestamp with time zone,
	"last_used_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "sso_connections" (
	"id" uuid PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"protocol" text NOT NULL,
	"enabled" boolean DEFAULT false NOT NULL,
	"config" jsonb NOT NULL,
	"secret_enc" jsonb,
	"sp_key_enc" jsonb,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "sso_connections_protocol_check" CHECK (protocol IN ('oidc','saml')),
	CONSTRAINT "sso_connections_secret_check" CHECK ((protocol = 'oidc' AND sp_key_enc IS NULL) OR (protocol = 'saml' AND secret_enc IS NULL)),
	CONSTRAINT "sso_connections_config_size" CHECK (octet_length(config::text) <= 65536)
);
--> statement-breakpoint
CREATE TABLE "sso_group_mappings" (
	"id" uuid PRIMARY KEY NOT NULL,
	"connection_id" uuid NOT NULL,
	"group_value" text NOT NULL,
	"organization_id" uuid NOT NULL,
	"project_id" uuid,
	"role" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "sso_group_mappings_unique" UNIQUE NULLS NOT DISTINCT("connection_id","group_value","organization_id","project_id"),
	CONSTRAINT "sso_group_mappings_group_length" CHECK (char_length(group_value) BETWEEN 1 AND 255),
	CONSTRAINT "sso_group_mappings_role_check" CHECK (role IN ('admin','project_admin','member','viewer')),
	CONSTRAINT "sso_group_mappings_project_role_check" CHECK (project_id IS NULL OR role IN ('project_admin','member','viewer'))
);
--> statement-breakpoint
CREATE TABLE "sso_states" (
	"key" text PRIMARY KEY NOT NULL,
	"kind" text NOT NULL,
	"connection_id" uuid NOT NULL,
	"payload" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "sso_states_kind_check" CHECK (kind IN ('oidc','saml-request','saml-assertion','finish')),
	CONSTRAINT "sso_states_payload_size" CHECK (octet_length(payload::text) <= 16384)
);
--> statement-breakpoint
ALTER TABLE "memberships" ADD COLUMN "managed_by_connection_id" uuid;--> statement-breakpoint
ALTER TABLE "project_memberships" ADD COLUMN "managed_by_connection_id" uuid;--> statement-breakpoint
ALTER TABLE "identities" ADD CONSTRAINT "identities_connection_id_sso_connections_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."sso_connections"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identities" ADD CONSTRAINT "identities_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scim_group_members" ADD CONSTRAINT "scim_group_members_group_id_scim_groups_id_fk" FOREIGN KEY ("group_id") REFERENCES "public"."scim_groups"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scim_group_members" ADD CONSTRAINT "scim_group_members_identity_id_identities_id_fk" FOREIGN KEY ("identity_id") REFERENCES "public"."identities"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scim_groups" ADD CONSTRAINT "scim_groups_connection_id_sso_connections_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."sso_connections"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scim_tokens" ADD CONSTRAINT "scim_tokens_connection_id_sso_connections_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."sso_connections"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scim_tokens" ADD CONSTRAINT "scim_tokens_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sso_connections" ADD CONSTRAINT "sso_connections_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sso_group_mappings" ADD CONSTRAINT "sso_group_mappings_connection_id_sso_connections_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."sso_connections"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sso_group_mappings" ADD CONSTRAINT "sso_group_mappings_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sso_group_mappings" ADD CONSTRAINT "sso_group_mappings_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sso_states" ADD CONSTRAINT "sso_states_connection_id_sso_connections_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."sso_connections"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "identities_connection_subject_key" ON "identities" USING btree ("connection_id","subject") WHERE subject IS NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "identities_connection_user_key" ON "identities" USING btree ("connection_id","user_id");--> statement-breakpoint
CREATE UNIQUE INDEX "identities_connection_scim_user_name_key" ON "identities" USING btree ("connection_id","scim_user_name") WHERE scim_user_name IS NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "identities_connection_scim_external_id_key" ON "identities" USING btree ("connection_id","scim_external_id") WHERE scim_external_id IS NOT NULL;--> statement-breakpoint
CREATE INDEX "identities_user_idx" ON "identities" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "scim_group_members_identity_idx" ON "scim_group_members" USING btree ("identity_id");--> statement-breakpoint
CREATE UNIQUE INDEX "scim_groups_display_name_key" ON "scim_groups" USING btree ("connection_id",lower("display_name"));--> statement-breakpoint
CREATE UNIQUE INDEX "scim_groups_external_id_key" ON "scim_groups" USING btree ("connection_id","external_id") WHERE external_id IS NOT NULL;--> statement-breakpoint
CREATE INDEX "scim_tokens_prefix_idx" ON "scim_tokens" USING btree ("prefix");--> statement-breakpoint
CREATE INDEX "scim_tokens_connection_idx" ON "scim_tokens" USING btree ("connection_id");--> statement-breakpoint
CREATE INDEX "scim_tokens_created_by_idx" ON "scim_tokens" USING btree ("created_by") WHERE created_by IS NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "sso_connections_name_key" ON "sso_connections" USING btree (lower("name"));--> statement-breakpoint
CREATE INDEX "sso_connections_created_by_idx" ON "sso_connections" USING btree ("created_by") WHERE created_by IS NOT NULL;--> statement-breakpoint
CREATE INDEX "sso_group_mappings_organization_idx" ON "sso_group_mappings" USING btree ("organization_id");--> statement-breakpoint
CREATE INDEX "sso_group_mappings_project_idx" ON "sso_group_mappings" USING btree ("project_id") WHERE project_id IS NOT NULL;--> statement-breakpoint
CREATE INDEX "sso_states_expires_idx" ON "sso_states" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "sso_states_connection_idx" ON "sso_states" USING btree ("connection_id");--> statement-breakpoint
ALTER TABLE "memberships" ADD CONSTRAINT "memberships_managed_by_connection_id_sso_connections_id_fk" FOREIGN KEY ("managed_by_connection_id") REFERENCES "public"."sso_connections"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "project_memberships" ADD CONSTRAINT "project_memberships_managed_by_connection_id_sso_connections_id_fk" FOREIGN KEY ("managed_by_connection_id") REFERENCES "public"."sso_connections"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "memberships_managed_by_idx" ON "memberships" USING btree ("managed_by_connection_id") WHERE managed_by_connection_id IS NOT NULL;--> statement-breakpoint
CREATE INDEX "project_memberships_managed_by_idx" ON "project_memberships" USING btree ("managed_by_connection_id") WHERE managed_by_connection_id IS NOT NULL;