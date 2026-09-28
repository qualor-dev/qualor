CREATE TABLE "audit_events" (
	"id" uuid PRIMARY KEY NOT NULL,
	"seq" bigint NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	"action" text NOT NULL,
	"outcome" text NOT NULL,
	"actor_type" text NOT NULL,
	"actor_user_id" uuid,
	"actor_username" text,
	"actor_token_id" uuid,
	"organization_id" uuid,
	"organization_key" text,
	"project_id" uuid,
	"project_key" text,
	"target_type" text,
	"target_id" text,
	"target_label" text,
	"ip" text,
	"user_agent" text,
	"details" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"prev_hash" char(64) NOT NULL,
	"hash" char(64) NOT NULL,
	CONSTRAINT "audit_events_action_check" CHECK (action ~ '^[a-z][a-z_]*(\.[a-z][a-z_]*)+$'),
	CONSTRAINT "audit_events_outcome_check" CHECK (outcome IN ('success','failure')),
	CONSTRAINT "audit_events_actor_type_check" CHECK (actor_type IN ('user','system','anonymous')),
	CONSTRAINT "audit_events_target_label_length" CHECK (char_length(target_label) <= 255),
	CONSTRAINT "audit_events_user_agent_length" CHECK (char_length(user_agent) <= 256),
	CONSTRAINT "audit_events_details_size" CHECK (octet_length(details::text) <= 8192),
	CONSTRAINT "audit_events_hash_format" CHECK (hash ~ '^[0-9a-f]{64}$'),
	CONSTRAINT "audit_events_prev_hash_format" CHECK (prev_hash ~ '^[0-9a-f]{64}$')
);
--> statement-breakpoint
CREATE TABLE "project_memberships" (
	"project_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"role" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "project_memberships_project_id_user_id_pk" PRIMARY KEY("project_id","user_id"),
	CONSTRAINT "project_memberships_role_check" CHECK (role IN ('project_admin','member','viewer'))
);
--> statement-breakpoint
ALTER TABLE "memberships" DROP CONSTRAINT "memberships_role_check";--> statement-breakpoint
ALTER TABLE "project_memberships" ADD CONSTRAINT "project_memberships_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "project_memberships" ADD CONSTRAINT "project_memberships_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "audit_events_seq_key" ON "audit_events" USING btree ("seq");--> statement-breakpoint
CREATE INDEX "audit_events_created_idx" ON "audit_events" USING btree ("created_at");--> statement-breakpoint
CREATE INDEX "audit_events_organization_idx" ON "audit_events" USING btree ("organization_id","seq") WHERE organization_id IS NOT NULL;--> statement-breakpoint
CREATE INDEX "audit_events_project_idx" ON "audit_events" USING btree ("project_id","seq") WHERE project_id IS NOT NULL;--> statement-breakpoint
CREATE INDEX "audit_events_actor_idx" ON "audit_events" USING btree ("actor_user_id","seq") WHERE actor_user_id IS NOT NULL;--> statement-breakpoint
CREATE INDEX "audit_events_action_idx" ON "audit_events" USING btree ("action","seq");--> statement-breakpoint
CREATE INDEX "project_memberships_user_idx" ON "project_memberships" USING btree ("user_id");--> statement-breakpoint
ALTER TABLE "memberships" ADD CONSTRAINT "memberships_role_check" CHECK (role IN ('admin','project_admin','member','viewer'));
--> statement-breakpoint
CREATE FUNCTION audit_events_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  -- rbac-audit.md §7.3: only a retention run, which sets qualor.audit_prune to the id of
  -- its own transaction, may delete (a value left in the session never matches a later one);
  -- nothing may update or truncate.
  IF TG_OP = 'DELETE' AND current_setting('qualor.audit_prune', true) = txid_current()::text THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'audit_events rows are immutable (%)', TG_OP USING ERRCODE = '55000';
END
$$;
--> statement-breakpoint
CREATE TRIGGER audit_events_guard BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION audit_events_guard();
--> statement-breakpoint
CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION audit_events_guard();
--> statement-breakpoint
-- ALWAYS: the guards fire under session_replication_role = replica too (§7.3).
ALTER TABLE audit_events ENABLE ALWAYS TRIGGER audit_events_guard;
--> statement-breakpoint
ALTER TABLE audit_events ENABLE ALWAYS TRIGGER audit_events_no_truncate;
