import type { LlmFeature, RuleScope } from '@qualor/shared';
import { sql } from 'drizzle-orm';
import {
  type AnyPgColumn,
  bigint,
  boolean,
  char,
  check,
  customType,
  doublePrecision,
  index,
  integer,
  jsonb,
  pgTable,
  primaryKey,
  smallint,
  text,
  timestamp,
  unique,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';
import { uuidv7 } from './ids';

export const TOKEN_SCOPES = ['read', 'write', 'admin', 'analysis:write'] as const;
export type TokenScope = (typeof TOKEN_SCOPES)[number];
/** rbac-audit.md §3.2, §6.1: `admin` is the org admin, `member` the maintainer; every edition. */
export const ORGANIZATION_ROLES = ['admin', 'project_admin', 'member', 'viewer'] as const;
export type OrganizationRole = (typeof ORGANIZATION_ROLES)[number];
/** A role on one project (rbac-audit.md §3.2); `admin` is organisation-level only. */
export const PROJECT_ROLES = ['project_admin', 'member', 'viewer'] as const;
export type ProjectRole = (typeof PROJECT_ROLES)[number];
export type AnalysisStatus = 'queued' | 'processing' | 'succeeded' | 'failed';
export type GateStatus = 'passed' | 'failed' | 'error' | 'none';
export type BaselineStatus = 'ok' | 'unavailable' | 'first_analysis';
export type BranchKind = 'branch' | 'merge_request';
export type JobStatus = 'queued' | 'running' | 'succeeded' | 'failed' | 'dead';
export interface FieldIssue {
  path: string;
  message: string;
}
export interface AnalysisError {
  code: string;
  message: string;
  errors?: FieldIssue[];
}
export interface AnalysisEngine {
  id: string;
  kind: 'builtin' | 'external';
  version: string | null;
  status: 'ok' | 'failed' | 'skipped' | 'timeout';
  reason: string | null;
  durationMs: number;
  /** The vulnerability database a dependency scanner used (report-format.md §5, plan 2B). */
  database?: { name: string; updatedAt: string };
}
export interface AnalysisWarning {
  code: string;
  message: string;
  count?: number;
}
/** AES-256-GCM envelope for `*_enc` columns (data-model.md §2); the helper arrives with webhooks. */
export interface EncryptedValue {
  v: 1;
  iv: string;
  ct: string;
  tag: string;
}
export type NewCodeDefinition =
  | { type: 'days'; value: number }
  | { type: 'previous_version' }
  | { type: 'analysis'; analysisId: string };

const citext = customType<{ data: string }>({ dataType: () => 'citext' });
const bytea = customType<{ data: Buffer; driverData: Buffer }>({ dataType: () => 'bytea' });

const id = () =>
  uuid('id')
    .primaryKey()
    .$defaultFn(() => uuidv7());
const at = (name: string) => timestamp(name, { withTimezone: true });
const createdAt = () => at('created_at').notNull().defaultNow();
const updatedAt = () =>
  at('updated_at')
    .notNull()
    .defaultNow()
    // The database clock, like the defaultNow() above, so updated_at >= created_at always holds.
    .$onUpdate(() => sql`now()`);
const emptyJsonArray = sql`'[]'::jsonb`;
const emptyTextArray = sql`'{}'::text[]`;

// ─── 4.1 Identity and access ────────────────────────────────────────────────

export const organizations = pgTable(
  'organizations',
  {
    id: id(),
    key: text('key').notNull().unique(),
    name: text('name').notNull(),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  () => [check('organizations_key_format', sql`key ~ '^[a-z0-9][a-z0-9-]{1,63}$'`)],
);

export const users = pgTable('users', {
  id: id(),
  username: citext('username').notNull().unique(),
  email: citext('email').unique(),
  displayName: text('display_name'),
  passwordHash: text('password_hash'),
  passwordChangeRequired: boolean('password_change_required').notNull().default(false),
  isInstanceAdmin: boolean('is_instance_admin').notNull().default(false),
  active: boolean('active').notNull().default(true),
  lastLoginAt: at('last_login_at'),
  createdAt: createdAt(),
  updatedAt: updatedAt(),
});

export const memberships = pgTable(
  'memberships',
  {
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    role: text('role').notNull().$type<OrganizationRole>(),
    /** Set while group sync owns this row (sso-scim.md §9.3); a deleted connection leaves it manual. */
    managedByConnectionId: uuid('managed_by_connection_id').references(() => ssoConnections.id, {
      onDelete: 'set null',
    }),
    createdAt: createdAt(),
  },
  (t) => [
    primaryKey({ columns: [t.organizationId, t.userId] }),
    index('memberships_user_idx').on(t.userId),
    index('memberships_managed_by_idx')
      .on(t.managedByConnectionId)
      .where(sql`managed_by_connection_id IS NOT NULL`),
    check('memberships_role_check', sql`role IN ('admin','project_admin','member','viewer')`),
  ],
);

export const scmConnections = pgTable(
  'scm_connections',
  {
    id: id(),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    provider: text('provider').notNull().$type<'gitlab' | 'github'>(),
    baseUrl: text('base_url').notNull(),
    tokenEnc: jsonb('token_enc').notNull().$type<EncryptedValue>(),
    /** github.md §2.5 (D1, migration 0003): the GitHub App id, plain text; NULL for GitLab. */
    appId: text('app_id'),
    /**
     * The secret an SCM webhook is checked against (github.md §2.5), AES-256-GCM with AAD
     * `scm_connections.webhook_secret_enc`; NULL when unset. Either provider may hold one: GitHub's
     * for its App's webhook, and since migration 0017 GitLab's for the note webhook.
     */
    webhookSecretEnc: jsonb('webhook_secret_enc').$type<EncryptedValue>(),
    /** Onboarding (migration 0019): whether Qualor may open CI-setup merge requests; GitLab only. */
    ciSetupAllowed: boolean('ci_setup_allowed').notNull().default(false),
    createdAt: createdAt(),
  },
  (t) => [
    index('scm_connections_organization_idx').on(t.organizationId),
    check('scm_connections_provider_check', sql`provider IN ('gitlab','github')`),
    // A NULL app_id would make the regex test NULL, which a CHECK lets through: hence IS NOT NULL.
    check(
      'scm_connections_github_app_check',
      sql`(provider = 'gitlab' AND app_id IS NULL) OR (provider = 'github' AND app_id IS NOT NULL AND app_id ~ '^[0-9]{1,20}$')`,
    ),
  ],
);

// ─── Onboarding (migration 0019) ────────────────────────────────────────────

export const SETUP_RUN_STATUSES = ['queued', 'running', 'done'] as const;
export type SetupRunStatus = (typeof SETUP_RUN_STATUSES)[number];
export const SETUP_PROJECT_OUTCOMES = ['pending', 'created', 'adopted', 'failed'] as const;
export type SetupProjectOutcome = (typeof SETUP_PROJECT_OUTCOMES)[number];
export const SETUP_CI_OUTCOMES = [
  'pending',
  'merge_request',
  'snippet',
  'already',
  'skipped',
  'failed',
] as const;
export type SetupCiOutcome = (typeof SETUP_CI_OUTCOMES)[number];

/** One bulk "create projects from a connection's repositories" run, worked in the background. */
export const repositorySetupRuns = pgTable(
  'repository_setup_runs',
  {
    id: id(),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    connectionId: uuid('connection_id').references(() => scmConnections.id, {
      onDelete: 'set null',
    }),
    createdBy: uuid('created_by').references(() => users.id, { onDelete: 'set null' }),
    /** Whether the run also opens a CI-setup merge request per repository. */
    ciSetup: boolean('ci_setup').notNull().default(false),
    status: text('status').notNull().default('queued').$type<SetupRunStatus>(),
    createdAt: createdAt(),
    finishedAt: at('finished_at'),
  },
  (t) => [
    index('repository_setup_runs_organization_idx').on(t.organizationId),
    index('repository_setup_runs_connection_idx')
      .on(t.connectionId)
      .where(sql`connection_id IS NOT NULL`),
    index('repository_setup_runs_created_by_idx')
      .on(t.createdBy)
      .where(sql`created_by IS NOT NULL`),
    check('repository_setup_runs_status_check', sql`status IN ('queued','running','done')`),
  ],
);

/** One repository of a run, with what became of its project and its CI setup. */
export const repositorySetupItems = pgTable(
  'repository_setup_items',
  {
    runId: uuid('run_id')
      .notNull()
      .references(() => repositorySetupRuns.id, { onDelete: 'cascade' }),
    position: integer('position').notNull(),
    repositoryRef: text('repository_ref').notNull(),
    repositoryName: text('repository_name').notNull(),
    projectOutcome: text('project_outcome')
      .notNull()
      .default('pending')
      .$type<SetupProjectOutcome>(),
    projectId: uuid('project_id').references(() => projects.id, { onDelete: 'set null' }),
    ciOutcome: text('ci_outcome').notNull().default('pending').$type<SetupCiOutcome>(),
    ciUrl: text('ci_url'),
    ciReason: text('ci_reason'),
    snippet: text('snippet'),
    /** The new project's analysis token, until it is revealed once; cleared afterwards. */
    tokenEnc: jsonb('token_enc').$type<EncryptedValue>(),
    errorCode: text('error_code'),
    errorMessage: text('error_message'),
  },
  (t) => [
    primaryKey({ columns: [t.runId, t.position] }),
    index('repository_setup_items_project_idx')
      .on(t.projectId)
      .where(sql`project_id IS NOT NULL`),
    check(
      'repository_setup_items_project_outcome_check',
      sql`project_outcome IN ('pending','created','adopted','failed')`,
    ),
    check(
      'repository_setup_items_ci_outcome_check',
      sql`ci_outcome IN ('pending','merge_request','snippet','already','skipped','failed')`,
    ),
  ],
);

/** A user closed the setup checklist of an organisation. */
export const setupChecklistClosures = pgTable(
  'setup_checklist_closures',
  {
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    closedAt: timestamp('closed_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    primaryKey({ columns: [t.userId, t.organizationId] }),
    index('setup_checklist_closures_organization_idx').on(t.organizationId),
  ],
);

// ─── 4.4 Gates (projects reference them) ────────────────────────────────────

export const qualityGates = pgTable(
  'quality_gates',
  {
    id: id(),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    isDefault: boolean('is_default').notNull().default(false),
    isBuiltin: boolean('is_builtin').notNull().default(false),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [
    index('quality_gates_organization_idx').on(t.organizationId),
    uniqueIndex('quality_gates_one_default')
      .on(t.organizationId)
      .where(sql`is_default`),
  ],
);

export const gateConditions = pgTable(
  'gate_conditions',
  {
    id: id(),
    gateId: uuid('gate_id')
      .notNull()
      .references(() => qualityGates.id, { onDelete: 'cascade' }),
    metricKey: text('metric_key').notNull(),
    operator: text('operator').notNull().$type<'gt' | 'lt'>(),
    threshold: doublePrecision('threshold').notNull(),
    createdAt: createdAt(),
  },
  (t) => [
    uniqueIndex('gate_conditions_gate_metric').on(t.gateId, t.metricKey),
    check('gate_conditions_operator_check', sql`operator IN ('gt','lt')`),
  ],
);

// ─── 4.2 Projects and branches ──────────────────────────────────────────────

export const projects = pgTable(
  'projects',
  {
    id: id(),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    key: text('key').notNull().unique(),
    name: text('name').notNull(),
    mainBranchName: text('main_branch_name').notNull().default('main'),
    qualityGateId: uuid('quality_gate_id').references(() => qualityGates.id, {
      onDelete: 'set null',
    }),
    newCodeDefinition: jsonb('new_code_definition').$type<NewCodeDefinition>(),
    scmConnectionId: uuid('scm_connection_id').references(() => scmConnections.id, {
      onDelete: 'set null',
    }),
    scmProjectRef: text('scm_project_ref'),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [
    index('projects_organization_idx').on(t.organizationId),
    index('projects_quality_gate_idx')
      .on(t.qualityGateId)
      .where(sql`quality_gate_id IS NOT NULL`),
    index('projects_scm_connection_idx')
      .on(t.scmConnectionId)
      .where(sql`scm_connection_id IS NOT NULL`),
    check('projects_key_format', sql`key ~ '^[A-Za-z0-9._/:-]{1,255}$'`),
  ],
);

/** rbac-audit.md §7.2: a role on one project, added to the organisation role. */
export const projectMemberships = pgTable(
  'project_memberships',
  {
    projectId: uuid('project_id')
      .notNull()
      .references(() => projects.id, { onDelete: 'cascade' }),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    role: text('role').notNull().$type<ProjectRole>(),
    /** Set while group sync owns this row (sso-scim.md §9.3); a deleted connection leaves it manual. */
    managedByConnectionId: uuid('managed_by_connection_id').references(() => ssoConnections.id, {
      onDelete: 'set null',
    }),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [
    primaryKey({ columns: [t.projectId, t.userId] }),
    index('project_memberships_user_idx').on(t.userId),
    index('project_memberships_managed_by_idx')
      .on(t.managedByConnectionId)
      .where(sql`managed_by_connection_id IS NOT NULL`),
    check('project_memberships_role_check', sql`role IN ('project_admin','member','viewer')`),
  ],
);

export const apiTokens = pgTable(
  'api_tokens',
  {
    id: id(),
    kind: text('kind').notNull().$type<'personal' | 'project'>(),
    userId: uuid('user_id').references(() => users.id, { onDelete: 'cascade' }),
    projectId: uuid('project_id').references(() => projects.id, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    prefix: text('prefix').notNull(),
    secretHash: bytea('secret_hash').notNull(),
    scopes: text('scopes').array().notNull().$type<TokenScope[]>(),
    expiresAt: at('expires_at'),
    lastUsedAt: at('last_used_at'),
    revokedAt: at('revoked_at'),
    createdBy: uuid('created_by').references(() => users.id, { onDelete: 'set null' }),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [
    index('api_tokens_prefix_idx').on(t.prefix),
    index('api_tokens_user_idx').on(t.userId),
    index('api_tokens_project_idx').on(t.projectId),
    index('api_tokens_created_by_idx')
      .on(t.createdBy)
      .where(sql`created_by IS NOT NULL`),
    check(
      'api_tokens_kind_check',
      sql`(kind = 'personal' AND user_id IS NOT NULL AND project_id IS NULL)
        OR (kind = 'project' AND project_id IS NOT NULL AND user_id IS NULL
            AND scopes = ARRAY['analysis:write']::text[])`,
    ),
  ],
);

export const sessions = pgTable(
  'sessions',
  {
    id: bytea('id').primaryKey(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    expiresAt: at('expires_at').notNull(),
    lastSeenAt: at('last_seen_at').notNull().defaultNow(),
    ip: text('ip'),
    userAgent: text('user_agent'),
    createdAt: createdAt(),
  },
  (t) => [index('sessions_user_idx').on(t.userId)],
);

export const branches = pgTable(
  'branches',
  {
    id: id(),
    projectId: uuid('project_id')
      .notNull()
      .references(() => projects.id, { onDelete: 'cascade' }),
    kind: text('kind').notNull().$type<BranchKind>(),
    name: text('name').notNull(),
    isMain: boolean('is_main').notNull().default(false),
    mrSourceBranch: text('mr_source_branch'),
    mrTargetBranch: text('mr_target_branch'),
    mrTitle: text('mr_title'),
    mrUrl: text('mr_url'),
    lastAnalysisId: uuid('last_analysis_id').references((): AnyPgColumn => analyses.id, {
      onDelete: 'set null',
    }),
    lastAnalyzedAt: at('last_analyzed_at'),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [
    uniqueIndex('branches_project_kind_name').on(t.projectId, t.kind, t.name),
    index('branches_last_analysis_idx')
      .on(t.lastAnalysisId)
      .where(sql`last_analysis_id IS NOT NULL`),
    uniqueIndex('branches_one_main')
      .on(t.projectId)
      .where(sql`is_main`),
    check('branches_kind_check', sql`kind IN ('branch','merge_request')`),
    check('branches_main_is_branch', sql`NOT is_main OR kind = 'branch'`),
  ],
);

// ─── 4.3 Analyses and measures ──────────────────────────────────────────────

export const analyses = pgTable(
  'analyses',
  {
    id: id(),
    projectId: uuid('project_id')
      .notNull()
      .references(() => projects.id, { onDelete: 'cascade' }),
    // Filled by the processing job (ruling R4).
    branchId: uuid('branch_id').references(() => branches.id, { onDelete: 'cascade' }),
    revision: text('revision'),
    baselineRevision: text('baseline_revision'),
    baselineStatus: text('baseline_status').$type<BaselineStatus>(),
    versionLabel: text('version_label'),
    analysisDate: at('analysis_date'),
    status: text('status').notNull().default('queued').$type<AnalysisStatus>(),
    error: jsonb('error').$type<AnalysisError>(),
    scannerVersion: text('scanner_version'),
    engines: jsonb('engines').notNull().default(emptyJsonArray).$type<AnalysisEngine[]>(),
    warnings: jsonb('warnings').notNull().default(emptyJsonArray).$type<AnalysisWarning[]>(),
    gateStatus: text('gate_status').$type<GateStatus>(),
    gateResult: jsonb('gate_result').$type<unknown>(),
    // scm.md §7: the report's SCM context, written at ingestion; NULL for older rows.
    // Read through scm/context.ts, which validates it (anything else counts as NULL).
    scmContext: jsonb('scm_context').$type<unknown>(),
    uploadedByTokenId: uuid('uploaded_by_token_id').references(() => apiTokens.id, {
      onDelete: 'set null',
    }),
    queuedAt: at('queued_at').notNull().defaultNow(),
    startedAt: at('started_at'),
    finishedAt: at('finished_at'),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [
    index('analyses_branch_idx').on(t.branchId, t.id),
    index('analyses_project_idx').on(t.projectId, t.id),
    index('analyses_uploaded_by_token_idx')
      .on(t.uploadedByTokenId)
      .where(sql`uploaded_by_token_id IS NOT NULL`),
    check('analyses_status_check', sql`status IN ('queued','processing','succeeded','failed')`),
    check(
      'analyses_baseline_status_check',
      sql`baseline_status IN ('ok','unavailable','first_analysis')`,
    ),
    check('analyses_gate_status_check', sql`gate_status IN ('passed','failed','error','none')`),
    check('analyses_revision_format', sql`revision ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'`),
    check(
      'analyses_baseline_revision_format',
      sql`baseline_revision ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'`,
    ),
    check(
      'analyses_succeeded_is_complete',
      sql`status <> 'succeeded' OR (branch_id IS NOT NULL AND revision IS NOT NULL
        AND analysis_date IS NOT NULL AND baseline_status IS NOT NULL
        AND scanner_version IS NOT NULL)`,
    ),
  ],
);

export const analysisReports = pgTable('analysis_reports', {
  analysisId: uuid('analysis_id')
    .primaryKey()
    .references(() => analyses.id, { onDelete: 'cascade' }),
  body: bytea('body').notNull(),
  sizeBytes: integer('size_bytes').notNull(),
  createdAt: createdAt(),
});

export const measures = pgTable(
  'measures',
  {
    analysisId: uuid('analysis_id')
      .notNull()
      .references(() => analyses.id, { onDelete: 'cascade' }),
    metricKey: text('metric_key').notNull(),
    scope: text('scope').notNull().$type<'overall' | 'new'>(),
    value: doublePrecision('value'),
    createdAt: createdAt(),
  },
  (t) => [
    primaryKey({ columns: [t.analysisId, t.metricKey, t.scope] }),
    check('measures_scope_check', sql`scope IN ('overall','new')`),
  ],
);

export const branchFiles = pgTable(
  'branch_files',
  {
    branchId: uuid('branch_id')
      .notNull()
      .references(() => branches.id, { onDelete: 'cascade' }),
    path: text('path').notNull(),
    language: text('language').notNull(),
    kind: text('kind').notNull().$type<'main' | 'test'>(),
    sha256: text('sha256').notNull(),
    metrics: jsonb('metrics').$type<Record<string, number>>(),
    coverage: jsonb('coverage').$type<unknown>(),
    newLines: jsonb('new_lines').$type<unknown>(),
    duplications: jsonb('duplications').$type<unknown>(),
    analysisId: uuid('analysis_id')
      .notNull()
      .references(() => analyses.id, { onDelete: 'cascade' }),
    createdAt: createdAt(),
  },
  (t) => [
    primaryKey({ columns: [t.branchId, t.path] }),
    index('branch_files_analysis_idx').on(t.analysisId),
    check('branch_files_kind_check', sql`kind IN ('main','test')`),
  ],
);

/**
 * The dependency inventory of a branch's latest analysis that carried one (report `dependencies`),
 * replaced in the ingestion transaction next to `branch_files`. `licenses` holds the licence
 * strings as the scanner normalised them; `{}` means unknown.
 */
export const branchDependencies = pgTable(
  'branch_dependencies',
  {
    branchId: uuid('branch_id')
      .notNull()
      .references(() => branches.id, { onDelete: 'cascade' }),
    path: text('path').notNull(),
    ecosystem: text('ecosystem').notNull(),
    name: text('name').notNull(),
    version: text('version').notNull(),
    licenses: text('licenses').array().notNull(),
    direct: boolean('direct'),
    line: integer('line'),
    analysisId: uuid('analysis_id')
      .notNull()
      .references(() => analyses.id, { onDelete: 'cascade' }),
  },
  (t) => [
    primaryKey({ columns: [t.branchId, t.path, t.ecosystem, t.name, t.version] }),
    index('branch_dependencies_licenses').using('gin', t.licenses),
    // Supporting index for the analyses foreign key (cascades).
    index('branch_dependencies_analysis_idx').on(t.analysisId),
  ],
);

// ─── 4.4 Rules and profiles ─────────────────────────────────────────────────

export const rules = pgTable(
  'rules',
  {
    id: id(),
    key: text('key').notNull().unique(),
    engineId: text('engine_id').notNull(),
    engineRuleId: text('engine_rule_id').notNull(),
    name: text('name').notNull(),
    descriptionMd: text('description_md'),
    helpUri: text('help_uri'),
    languages: text('languages').array().notNull().default(emptyTextArray),
    defaultSeverity: text('default_severity').notNull(),
    quality: text('quality').notNull(),
    kind: text('kind').notNull().$type<'issue' | 'hotspot'>(),
    tags: text('tags').array().notNull().default(emptyTextArray),
    cwe: integer('cwe')
      .array()
      .notNull()
      .default(sql`'{}'::integer[]`),
    /** The code the rule reports on (0.13): main code, test code or all of it. */
    scope: text('scope').notNull().default('all').$type<RuleScope>(),
    status: text('status').notNull().default('ready').$type<'ready' | 'deprecated' | 'removed'>(),
    origin: text('origin').notNull().$type<'builtin' | 'reported'>(),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  () => [
    check(
      'rules_default_severity_check',
      sql`default_severity IN ('blocker','high','medium','low','info')`,
    ),
    check(
      'rules_quality_check',
      sql`quality IN ('security','reliability','maintainability','licensing')`,
    ),
    check('rules_kind_check', sql`kind IN ('issue','hotspot')`),
    check('rules_scope_check', sql`scope IN ('main','test','all')`),
    check('rules_status_check', sql`status IN ('ready','deprecated','removed')`),
    check('rules_origin_check', sql`origin IN ('builtin','reported')`),
  ],
);

export const qualityProfiles = pgTable(
  'quality_profiles',
  {
    id: id(),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    language: text('language').notNull(),
    parentId: uuid('parent_id').references((): AnyPgColumn => qualityProfiles.id, {
      onDelete: 'restrict',
    }),
    isDefault: boolean('is_default').notNull().default(false),
    isBuiltin: boolean('is_builtin').notNull().default(false),
    unknownRules: text('unknown_rules')
      .notNull()
      .default('activate')
      .$type<'activate' | 'ignore'>(),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [
    uniqueIndex('quality_profiles_org_language_name').on(t.organizationId, t.language, t.name),
    index('quality_profiles_parent_idx')
      .on(t.parentId)
      .where(sql`parent_id IS NOT NULL`),
    uniqueIndex('quality_profiles_one_default')
      .on(t.organizationId, t.language)
      .where(sql`is_default`),
    check('quality_profiles_unknown_rules_check', sql`unknown_rules IN ('activate','ignore')`),
  ],
);

export const profileRules = pgTable(
  'profile_rules',
  {
    profileId: uuid('profile_id')
      .notNull()
      .references(() => qualityProfiles.id, { onDelete: 'cascade' }),
    ruleId: uuid('rule_id')
      .notNull()
      .references(() => rules.id, { onDelete: 'cascade' }),
    active: boolean('active').notNull(),
    severityOverride: text('severity_override'),
    /** The rule's scope in this profile and its children (0.13); null: none set here. */
    scopeOverride: text('scope_override').$type<RuleScope>(),
    createdAt: createdAt(),
  },
  (t) => [
    primaryKey({ columns: [t.profileId, t.ruleId] }),
    index('profile_rules_rule_idx').on(t.ruleId),
    check(
      'profile_rules_severity_check',
      sql`severity_override IN ('blocker','high','medium','low','info')`,
    ),
    check('profile_rules_scope_check', sql`scope_override IN ('main','test','all')`),
  ],
);

export const projectProfiles = pgTable(
  'project_profiles',
  {
    projectId: uuid('project_id')
      .notNull()
      .references(() => projects.id, { onDelete: 'cascade' }),
    language: text('language').notNull(),
    profileId: uuid('profile_id')
      .notNull()
      .references(() => qualityProfiles.id, { onDelete: 'cascade' }),
    createdAt: createdAt(),
  },
  (t) => [
    primaryKey({ columns: [t.projectId, t.language] }),
    index('project_profiles_profile_idx').on(t.profileId),
  ],
);

// ─── 4.5 Issues ─────────────────────────────────────────────────────────────

export const issues = pgTable(
  'issues',
  {
    id: id(),
    projectId: uuid('project_id')
      .notNull()
      .references(() => projects.id, { onDelete: 'cascade' }),
    branchId: uuid('branch_id')
      .notNull()
      .references(() => branches.id, { onDelete: 'cascade' }),
    ruleId: uuid('rule_id')
      .notNull()
      .references(() => rules.id, { onDelete: 'restrict' }),
    fingerprint: char('fingerprint', { length: 32 }).notNull(),
    lineHash: text('line_hash').notNull(),
    contextHash: text('context_hash').notNull(),
    path: text('path'),
    startLine: integer('start_line'),
    startColumn: integer('start_column'),
    endLine: integer('end_line'),
    endColumn: integer('end_column'),
    message: text('message').notNull(),
    severity: text('severity').notNull(),
    // Ruling R6: text severities sort alphabetically; lists sort by this rank.
    severityRank: smallint('severity_rank')
      .notNull()
      .generatedAlwaysAs(
        sql`CASE severity WHEN 'blocker' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END`,
      ),
    severityOverridden: boolean('severity_overridden').notNull().default(false),
    quality: text('quality').notNull(),
    kind: text('kind').notNull().$type<'issue' | 'hotspot'>(),
    status: text('status').notNull().default('open'),
    inNewCode: boolean('in_new_code').notNull().default(false),
    duplicateOfIssueId: uuid('duplicate_of_issue_id').references((): AnyPgColumn => issues.id, {
      onDelete: 'set null',
    }),
    snippet: jsonb('snippet').$type<unknown>(),
    secondaryLocations: jsonb('secondary_locations').notNull().default(emptyJsonArray),
    // Qualor's C# taint engine only (R-9): 'medium' is shown as "possible"; null for every other
    // analyzer (not set).
    confidence: text('confidence').$type<'high' | 'medium'>(),
    firstSeenAnalysisId: uuid('first_seen_analysis_id').references(() => analyses.id, {
      onDelete: 'set null',
    }),
    firstSeenAt: at('first_seen_at').notNull(),
    lastSeenAnalysisId: uuid('last_seen_analysis_id').references(() => analyses.id, {
      onDelete: 'set null',
    }),
    resolvedAt: at('resolved_at'),
    resolvedBy: uuid('resolved_by').references(() => users.id, { onDelete: 'set null' }),
    closedAt: at('closed_at'),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [
    index('issues_default_list_idx').on(t.branchId, t.status, t.severityRank, t.id),
    index('issues_rule_idx').on(t.branchId, t.ruleId, t.status),
    index('issues_path_idx').on(t.branchId, t.path, t.startLine),
    index('issues_fingerprint_idx').on(t.branchId, t.fingerprint),
    index('issues_new_code_idx')
      .on(t.branchId, t.inNewCode)
      .where(sql`status = 'open'`),
    index('issues_message_trgm_idx').using('gin', sql`message gin_trgm_ops`),
    // Supporting indexes for foreign keys (cascades, SET NULL and RESTRICT checks).
    index('issues_project_idx').on(t.projectId),
    index('issues_rule_id_idx').on(t.ruleId),
    index('issues_duplicate_of_idx')
      .on(t.duplicateOfIssueId)
      .where(sql`duplicate_of_issue_id IS NOT NULL`),
    index('issues_first_seen_analysis_idx')
      .on(t.firstSeenAnalysisId)
      .where(sql`first_seen_analysis_id IS NOT NULL`),
    index('issues_last_seen_analysis_idx')
      .on(t.lastSeenAnalysisId)
      .where(sql`last_seen_analysis_id IS NOT NULL`),
    index('issues_resolved_by_idx')
      .on(t.resolvedBy)
      .where(sql`resolved_by IS NOT NULL`),
    check(
      'issues_status_check',
      sql`status IN ('open','resolved','wont_fix','false_positive','closed')`,
    ),
    check('issues_severity_check', sql`severity IN ('blocker','high','medium','low','info')`),
    check(
      'issues_quality_check',
      sql`quality IN ('security','reliability','maintainability','licensing')`,
    ),
    check('issues_kind_check', sql`kind IN ('issue','hotspot')`),
    check('issues_confidence_check', sql`confidence IN ('high','medium')`),
  ],
);

export const issueChanges = pgTable(
  'issue_changes',
  {
    id: id(),
    issueId: uuid('issue_id')
      .notNull()
      .references(() => issues.id, { onDelete: 'cascade' }),
    userId: uuid('user_id').references(() => users.id, { onDelete: 'set null' }),
    analysisId: uuid('analysis_id').references(() => analyses.id, { onDelete: 'set null' }),
    field: text('field').notNull().$type<'status' | 'severity' | 'comment'>(),
    oldValue: text('old_value'),
    newValue: text('new_value'),
    comment: text('comment'),
    createdAt: createdAt(),
  },
  (t) => [
    index('issue_changes_issue_idx').on(t.issueId, t.id),
    index('issue_changes_user_idx')
      .on(t.userId)
      .where(sql`user_id IS NOT NULL`),
    index('issue_changes_analysis_idx')
      .on(t.analysisId)
      .where(sql`analysis_id IS NOT NULL`),
    check('issue_changes_field_check', sql`field IN ('status','severity','comment')`),
    check('issue_changes_comment_length', sql`char_length(comment) <= 2000`),
  ],
);

// ─── 4.6 Webhooks, jobs, settings ───────────────────────────────────────────

/** 6G: a generic signed webhook, or a Slack / Microsoft Teams incoming webhook. */
export type WebhookKind = 'generic' | 'slack' | 'teams';

export const webhookSubscriptions = pgTable(
  'webhook_subscriptions',
  {
    id: id(),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    projectId: uuid('project_id').references(() => projects.id, { onDelete: 'cascade' }),
    /** 6G spec §3: set at creation, never changed. */
    kind: text('kind').notNull().default('generic').$type<WebhookKind>(),
    /** The URL deliveries go to; for chat kinds its masked form (the real one is `url_enc`). */
    url: text('url').notNull(),
    /** Chat kinds only: the real URL, a secret (AAD `webhook_subscriptions.url_enc`). */
    urlEnc: jsonb('url_enc').$type<EncryptedValue>(),
    /** Generic only: the signing secret. Chat kinds are not signed (6G spec D5). */
    secretEnc: jsonb('secret_enc').$type<EncryptedValue>(),
    events: text('events').array().notNull(),
    active: boolean('active').notNull().default(true),
    /** The IANA zone the weekly digest is due in (Monday 09:00 local). */
    timezone: text('timezone').notNull().default('UTC'),
    /** The local ISO week (`2026-W43`) of the last digest sent or skipped as quiet. */
    digestLastWeek: text('digest_last_week'),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [
    index('webhook_subscriptions_organization_idx').on(t.organizationId),
    index('webhook_subscriptions_project_idx')
      .on(t.projectId)
      .where(sql`project_id IS NOT NULL`),
    check('webhook_subscriptions_kind_check', sql`kind IN ('generic','slack','teams')`),
    check(
      'webhook_subscriptions_secret_by_kind',
      sql`(kind = 'generic') = (secret_enc IS NOT NULL)`,
    ),
    check('webhook_subscriptions_url_enc_by_kind', sql`(kind = 'generic') = (url_enc IS NULL)`),
  ],
);

export const webhookDeliveries = pgTable(
  'webhook_deliveries',
  {
    id: id(),
    subscriptionId: uuid('subscription_id')
      .notNull()
      .references(() => webhookSubscriptions.id, { onDelete: 'cascade' }),
    event: text('event').notNull(),
    payload: jsonb('payload').notNull().$type<unknown>(),
    status: text('status').notNull().default('pending').$type<'pending' | 'succeeded' | 'failed'>(),
    attempts: integer('attempts').notNull().default(0),
    responseCode: integer('response_code'),
    responseExcerpt: text('response_excerpt'),
    nextAttemptAt: at('next_attempt_at'),
    createdAt: createdAt(),
  },
  (t) => [
    index('webhook_deliveries_due_idx').on(t.status, t.nextAttemptAt),
    index('webhook_deliveries_subscription_idx').on(t.subscriptionId, t.id),
    check('webhook_deliveries_status_check', sql`status IN ('pending','succeeded','failed')`),
    check('webhook_deliveries_excerpt_length', sql`octet_length(response_excerpt) <= 1024`),
  ],
);

export const jobs = pgTable(
  'jobs',
  {
    id: id(),
    queue: text('queue').notNull(),
    concurrencyKey: text('concurrency_key'),
    payload: jsonb('payload').notNull().$type<unknown>(),
    status: text('status').notNull().default('queued').$type<JobStatus>(),
    runAt: at('run_at').notNull().defaultNow(),
    attempts: integer('attempts').notNull().default(0),
    maxAttempts: integer('max_attempts').notNull().default(5),
    lockedBy: text('locked_by'),
    lockedUntil: at('locked_until'),
    lastError: text('last_error'),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [
    uniqueIndex('jobs_one_running_per_key')
      .on(t.concurrencyKey)
      .where(sql`status = 'running'`),
    index('jobs_dequeue_idx')
      .on(t.queue, t.runAt, t.id)
      .where(sql`status = 'queued'`),
    index('jobs_key_queued_idx')
      .on(t.concurrencyKey, t.id)
      .where(sql`status = 'queued'`),
    index('jobs_lease_idx')
      .on(t.lockedUntil)
      .where(sql`status = 'running'`),
    check('jobs_status_check', sql`status IN ('queued','running','succeeded','failed','dead')`),
  ],
);

export const instanceSettings = pgTable('instance_settings', {
  key: text('key').primaryKey(),
  value: jsonb('value').notNull().$type<unknown>(),
  createdAt: createdAt(),
  updatedAt: updatedAt(),
});

// ─── 4.7 AI requests (Phase 3B, DM-1) ───────────────────────────────────────

export const LLM_REQUEST_STATUSES = ['queued', 'running', 'succeeded', 'failed'] as const;
export type LlmRequestStatus = (typeof LLM_REQUEST_STATUSES)[number];

/**
 * What a row of `llm_requests` is for: the three single-shot features, `review` (6I-3, migration
 * 0016_review_runs): the provider calls of an AI review run, and `review-reply` (6I-4, migration
 * 0017_review_replies): those of an answer to a reply in a merge request.
 */
export type LlmRequestFeature = LlmFeature | 'review' | 'review-reply';

/** llm.md §8.4: what happened to a fix suggestion's post. */
export interface LlmPost {
  status: 'queued' | 'posted' | 'failed';
  reason?: string;
  url?: string;
  at: string;
}

/** llm.md §10–§11.1 (DM-1): one row per AI request sent: metadata, the validated answer, the post. */
export const llmRequests = pgTable(
  'llm_requests',
  {
    id: id(),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    projectId: uuid('project_id')
      .notNull()
      .references(() => projects.id, { onDelete: 'cascade' }),
    // Closed issues are pruned (§7); the audit row stays.
    issueId: uuid('issue_id').references(() => issues.id, { onDelete: 'set null' }),
    userId: uuid('user_id').references(() => users.id, { onDelete: 'set null' }),
    feature: text('feature').notNull().$type<LlmRequestFeature>(),
    cacheKey: char('cache_key', { length: 64 }).notNull(),
    provider: text('provider').notNull(),
    providerHost: text('provider_host').notNull(),
    model: text('model').notNull(),
    promptVersion: text('prompt_version').notNull(),
    status: text('status').notNull().default('queued').$type<LlmRequestStatus>(),
    errorCode: text('error_code'),
    attempts: smallint('attempts').notNull().default(0),
    inputSha256: char('input_sha256', { length: 64 }).notNull(),
    inputBytes: integer('input_bytes').notNull(),
    fields: text('fields').array().notNull(),
    redactions: integer('redactions').notNull().default(0),
    inputTokens: integer('input_tokens'),
    outputTokens: integer('output_tokens'),
    costMicroUsd: bigint('cost_micro_usd', { mode: 'number' }),
    durationMs: integer('duration_ms'),
    result: jsonb('result').$type<unknown>(),
    prompt: jsonb('prompt').$type<unknown>(),
    post: jsonb('post').$type<LlmPost>(),
    createdAt: createdAt(),
    finishedAt: at('finished_at'),
    updatedAt: updatedAt(),
  },
  (t) => [
    // Quotas and usage (llm.md §12.1); also the organisation FK's index.
    index('llm_requests_organization_idx').on(t.organizationId, t.createdAt),
    // The cache (llm.md §10.2).
    index('llm_requests_cache_idx')
      .on(t.organizationId, t.feature, t.cacheKey, t.createdAt.desc())
      .where(sql`status = 'succeeded'`),
    // The issue view; also the issue FK's index.
    index('llm_requests_issue_idx')
      .on(t.issueId, t.feature, t.createdAt.desc())
      .where(sql`issue_id IS NOT NULL`),
    index('llm_requests_project_idx').on(t.projectId),
    index('llm_requests_user_idx')
      .on(t.userId)
      .where(sql`user_id IS NOT NULL`),
    check(
      'llm_requests_feature_check',
      sql`feature IN ('explain','triage','fix','review','review-reply')`,
    ),
    check('llm_requests_status_check', sql`status IN ('queued','running','succeeded','failed')`),
    check('llm_requests_result_check', sql`result IS NULL OR status = 'succeeded'`),
    check('llm_requests_result_size', sql`result IS NULL OR octet_length(result::text) <= 16384`),
    check('llm_requests_prompt_size', sql`prompt IS NULL OR octet_length(prompt::text) <= 65536`),
  ],
);
export type LlmRequestRow = typeof llmRequests.$inferSelect;

// ─── 4.8 Audit events (Phase 4C) ────────────────────────────────────────────

/**
 * rbac-audit.md §7.3: append-only, hash-chained. No foreign keys on purpose (a cascade would
 * change the chain; events outlive what they name). A trigger (migration 0005) refuses UPDATE,
 * TRUNCATE and a DELETE outside retention.
 */
export const auditEvents = pgTable(
  'audit_events',
  {
    id: id(),
    seq: bigint('seq', { mode: 'number' }).notNull(),
    createdAt: at('created_at').notNull(),
    action: text('action').notNull(),
    outcome: text('outcome').notNull().$type<'success' | 'failure'>(),
    actorType: text('actor_type').notNull().$type<'user' | 'system' | 'anonymous'>(),
    actorUserId: uuid('actor_user_id'),
    actorUsername: text('actor_username'),
    actorTokenId: uuid('actor_token_id'),
    organizationId: uuid('organization_id'),
    organizationKey: text('organization_key'),
    projectId: uuid('project_id'),
    projectKey: text('project_key'),
    targetType: text('target_type'),
    targetId: text('target_id'),
    targetLabel: text('target_label'),
    ip: text('ip'),
    userAgent: text('user_agent'),
    details: jsonb('details').notNull().default({}).$type<Record<string, unknown>>(),
    prevHash: char('prev_hash', { length: 64 }).notNull(),
    hash: char('hash', { length: 64 }).notNull(),
  },
  (t) => [
    uniqueIndex('audit_events_seq_key').on(t.seq),
    index('audit_events_created_idx').on(t.createdAt),
    index('audit_events_organization_idx')
      .on(t.organizationId, t.seq)
      .where(sql`organization_id IS NOT NULL`),
    index('audit_events_project_idx')
      .on(t.projectId, t.seq)
      .where(sql`project_id IS NOT NULL`),
    index('audit_events_actor_idx')
      .on(t.actorUserId, t.seq)
      .where(sql`actor_user_id IS NOT NULL`),
    index('audit_events_action_idx').on(t.action, t.seq),
    check('audit_events_action_check', sql`action ~ '^[a-z][a-z_]*(\\.[a-z][a-z_]*)+$'`),
    check('audit_events_outcome_check', sql`outcome IN ('success','failure')`),
    check('audit_events_actor_type_check', sql`actor_type IN ('user','system','anonymous')`),
    check('audit_events_target_label_length', sql`char_length(target_label) <= 255`),
    check('audit_events_user_agent_length', sql`char_length(user_agent) <= 256`),
    check('audit_events_details_size', sql`octet_length(details::text) <= 8192`),
    check('audit_events_hash_format', sql`hash ~ '^[0-9a-f]{64}$'`),
    check('audit_events_prev_hash_format', sql`prev_hash ~ '^[0-9a-f]{64}$'`),
  ],
);
export type AuditEventRow = typeof auditEvents.$inferSelect;

// ─── 4E-1 Compliance reports (feature compliance-export; empty without a licence) ───────────

export type ComplianceReportScope = 'project' | 'organization';
export type ComplianceReportStatus = 'pending' | 'ready' | 'failed';
export interface ComplianceStandardRef {
  id: string;
  version: string;
  sourceSha256: string;
}

const NIL_UUID = sql`'00000000-0000-0000-0000-000000000000'::uuid`;

export const complianceReports = pgTable(
  'compliance_reports',
  {
    id: id(),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    projectId: uuid('project_id').references(() => projects.id, { onDelete: 'cascade' }),
    branchId: uuid('branch_id').references(() => branches.id, { onDelete: 'set null' }),
    scope: text('scope').notNull().$type<ComplianceReportScope>(),
    status: text('status').notNull().default('pending').$type<ComplianceReportStatus>(),
    createdBy: uuid('created_by').references(() => users.id, { onDelete: 'set null' }),
    createdByName: text('created_by_name').notNull(),
    createdAt: createdAt(),
    completedAt: at('completed_at'),
    standards: jsonb('standards').notNull().$type<ComplianceStandardRef[]>(),
    summary: jsonb('summary').$type<unknown>(),
    data: bytea('data'),
    sha256: char('sha256', { length: 64 }),
    sizeBytes: integer('size_bytes'),
    error: text('error'),
  },
  (t) => [
    index('compliance_reports_organization_idx').on(t.organizationId, t.id),
    index('compliance_reports_project_idx')
      .on(t.projectId, t.id)
      .where(sql`project_id IS NOT NULL`),
    index('compliance_reports_branch_idx')
      .on(t.branchId)
      .where(sql`branch_id IS NOT NULL`),
    index('compliance_reports_created_by_idx')
      .on(t.createdBy)
      .where(sql`created_by IS NOT NULL`),
    uniqueIndex('compliance_reports_pending_key')
      .on(t.organizationId, sql`coalesce(project_id, ${NIL_UUID})`)
      .where(sql`status = 'pending'`),
    check(
      'compliance_reports_scope_check',
      sql`(scope = 'project' AND project_id IS NOT NULL) OR (scope = 'organization' AND project_id IS NULL)`,
    ),
    check('compliance_reports_status_check', sql`status IN ('pending','ready','failed')`),
    check(
      'compliance_reports_ready_check',
      sql`status <> 'ready' OR (data IS NOT NULL AND sha256 IS NOT NULL AND summary IS NOT NULL AND completed_at IS NOT NULL AND size_bytes IS NOT NULL)`,
    ),
    check('compliance_reports_sha256_format', sql`sha256 ~ '^[0-9a-f]{64}$'`),
    check('compliance_reports_summary_size', sql`octet_length(summary::text) <= 65536`),
    check('compliance_reports_error_length', sql`char_length(error) <= 500`),
    check('compliance_reports_name_length', sql`char_length(created_by_name) <= 255`),
  ],
);

// ─── 4.9 Single sign-on and SCIM (Phase 4D, sso-scim.md §13) ────────────────

export const SSO_PROTOCOLS = ['oidc', 'saml'] as const;
export type SsoProtocol = (typeof SSO_PROTOCOLS)[number];
/** How an identity was linked to its user (sso-scim.md §8); never by username. */
export const IDENTITY_LINK_METHODS = [
  'jit',
  'verified_email',
  'user',
  'scim',
  'scim_match',
] as const;
export type IdentityLinkMethod = (typeof IDENTITY_LINK_METHODS)[number];
export const SSO_STATE_KINDS = ['oidc', 'saml-request', 'saml-assertion', 'finish'] as const;
export type SsoStateKind = (typeof SSO_STATE_KINDS)[number];

/** The SCIM `name` of a user (sso-scim.md §12.4). */
export interface ScimName {
  givenName?: string;
  familyName?: string;
  formatted?: string;
}

/**
 * An instance-level IdP connection (sso-scim.md §4). `config` holds only the non-secret fields;
 * the OIDC client secret and the SAML SP key are AES-256-GCM envelopes (data-model.md §2).
 */
export const ssoConnections = pgTable(
  'sso_connections',
  {
    id: id(),
    name: text('name').notNull(),
    protocol: text('protocol').notNull().$type<SsoProtocol>(),
    enabled: boolean('enabled').notNull().default(false),
    config: jsonb('config').notNull().$type<unknown>(),
    secretEnc: jsonb('secret_enc').$type<EncryptedValue>(),
    spKeyEnc: jsonb('sp_key_enc').$type<EncryptedValue>(),
    createdBy: uuid('created_by').references(() => users.id, { onDelete: 'set null' }),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [
    uniqueIndex('sso_connections_name_key').on(sql`lower(${t.name})`),
    index('sso_connections_created_by_idx')
      .on(t.createdBy)
      .where(sql`created_by IS NOT NULL`),
    check('sso_connections_protocol_check', sql`protocol IN ('oidc','saml')`),
    check(
      'sso_connections_secret_check',
      sql`(protocol = 'oidc' AND sp_key_enc IS NULL) OR (protocol = 'saml' AND secret_enc IS NULL)`,
    ),
    check('sso_connections_config_size', sql`octet_length(config::text) <= 65536`),
  ],
);
export type SsoConnectionRow = typeof ssoConnections.$inferSelect;

/** A person at an IdP, linked to one user; with a SCIM record it is also the SCIM User. */
export const identities = pgTable(
  'identities',
  {
    id: id(),
    connectionId: uuid('connection_id')
      .notNull()
      .references(() => ssoConnections.id, { onDelete: 'cascade' }),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    subject: text('subject'),
    linkedBy: text('linked_by').notNull().$type<IdentityLinkMethod>(),
    scimUserName: citext('scim_user_name'),
    scimExternalId: text('scim_external_id'),
    scimName: jsonb('scim_name').$type<ScimName>(),
    lastSignInAt: at('last_sign_in_at'),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [
    uniqueIndex('identities_connection_subject_key')
      .on(t.connectionId, t.subject)
      .where(sql`subject IS NOT NULL`),
    uniqueIndex('identities_connection_user_key').on(t.connectionId, t.userId),
    uniqueIndex('identities_connection_scim_user_name_key')
      .on(t.connectionId, t.scimUserName)
      .where(sql`scim_user_name IS NOT NULL`),
    uniqueIndex('identities_connection_scim_external_id_key')
      .on(t.connectionId, t.scimExternalId)
      .where(sql`scim_external_id IS NOT NULL`),
    index('identities_user_idx').on(t.userId),
    check(
      'identities_subject_length',
      sql`subject IS NULL OR char_length(subject) BETWEEN 1 AND 255`,
    ),
    check(
      'identities_subject_or_scim_check',
      sql`subject IS NOT NULL OR scim_user_name IS NOT NULL`,
    ),
    check(
      'identities_linked_by_check',
      sql`linked_by IN ('jit','verified_email','user','scim','scim_match')`,
    ),
  ],
);
export type IdentityRow = typeof identities.$inferSelect;

/** SCIM bearer tokens (sso-scim.md §12.2): SHA-256 at rest, found by prefix, one connection each. */
export const scimTokens = pgTable(
  'scim_tokens',
  {
    id: id(),
    connectionId: uuid('connection_id')
      .notNull()
      .references(() => ssoConnections.id, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    prefix: text('prefix').notNull(),
    secretHash: bytea('secret_hash').notNull(),
    expiresAt: at('expires_at'),
    lastUsedAt: at('last_used_at'),
    revokedAt: at('revoked_at'),
    createdBy: uuid('created_by').references(() => users.id, { onDelete: 'set null' }),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [
    index('scim_tokens_prefix_idx').on(t.prefix),
    index('scim_tokens_connection_idx').on(t.connectionId),
    index('scim_tokens_created_by_idx')
      .on(t.createdBy)
      .where(sql`created_by IS NOT NULL`),
  ],
);
export type ScimTokenRow = typeof scimTokens.$inferSelect;

export const scimGroups = pgTable(
  'scim_groups',
  {
    id: id(),
    connectionId: uuid('connection_id')
      .notNull()
      .references(() => ssoConnections.id, { onDelete: 'cascade' }),
    displayName: text('display_name').notNull(),
    externalId: text('external_id'),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [
    uniqueIndex('scim_groups_display_name_key').on(t.connectionId, sql`lower(${t.displayName})`),
    uniqueIndex('scim_groups_external_id_key')
      .on(t.connectionId, t.externalId)
      .where(sql`external_id IS NOT NULL`),
  ],
);
export type ScimGroupRow = typeof scimGroups.$inferSelect;

export const scimGroupMembers = pgTable(
  'scim_group_members',
  {
    groupId: uuid('group_id')
      .notNull()
      .references(() => scimGroups.id, { onDelete: 'cascade' }),
    identityId: uuid('identity_id')
      .notNull()
      .references(() => identities.id, { onDelete: 'cascade' }),
    createdAt: createdAt(),
  },
  (t) => [
    primaryKey({ columns: [t.groupId, t.identityId] }),
    index('scim_group_members_identity_idx').on(t.identityId),
  ],
);

/** An IdP group (or `*`) mapped onto a 4C role in an organisation or one project (§9.2). */
export const ssoGroupMappings = pgTable(
  'sso_group_mappings',
  {
    id: id(),
    connectionId: uuid('connection_id')
      .notNull()
      .references(() => ssoConnections.id, { onDelete: 'cascade' }),
    groupValue: text('group_value').notNull(),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    projectId: uuid('project_id').references(() => projects.id, { onDelete: 'cascade' }),
    role: text('role').notNull().$type<OrganizationRole>(),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [
    // A constraint, not uniqueIndex: drizzle 0.45's uniqueIndex has no NULLS NOT DISTINCT. The
    // constraint's backing index carries the same name, so a duplicate names it either way.
    unique('sso_group_mappings_unique')
      .on(t.connectionId, t.groupValue, t.organizationId, t.projectId)
      .nullsNotDistinct(),
    index('sso_group_mappings_organization_idx').on(t.organizationId),
    index('sso_group_mappings_project_idx')
      .on(t.projectId)
      .where(sql`project_id IS NOT NULL`),
    check('sso_group_mappings_group_length', sql`char_length(group_value) BETWEEN 1 AND 255`),
    check(
      'sso_group_mappings_role_check',
      sql`role IN ('admin','project_admin','member','viewer')`,
    ),
    check(
      'sso_group_mappings_project_role_check',
      sql`project_id IS NULL OR role IN ('project_admin','member','viewer')`,
    ),
  ],
);
export type SsoGroupMappingRow = typeof ssoGroupMappings.$inferSelect;

/**
 * Short-lived flow state every replica sees (sso-scim.md §7.1): pending flows, used SAML
 * assertion ids and finish codes. Taken with `DELETE … RETURNING`; expired rows are ignored by
 * every read and pruned daily.
 */
export const ssoStates = pgTable(
  'sso_states',
  {
    key: text('key').primaryKey(),
    kind: text('kind').notNull().$type<SsoStateKind>(),
    connectionId: uuid('connection_id')
      .notNull()
      .references(() => ssoConnections.id, { onDelete: 'cascade' }),
    payload: jsonb('payload').notNull().default({}).$type<unknown>(),
    expiresAt: at('expires_at').notNull(),
    createdAt: createdAt(),
  },
  (t) => [
    index('sso_states_expires_idx').on(t.expiresAt),
    index('sso_states_connection_idx').on(t.connectionId),
    check('sso_states_kind_check', sql`kind IN ('oidc','saml-request','saml-assertion','finish')`),
    check('sso_states_payload_size', sql`octet_length(payload::text) <= 16384`),
  ],
);
export type SsoStateRow = typeof ssoStates.$inferSelect;

// ─── 4.10 Mail (E1 spec, migration 0009_mail) ───────────────────────────────

export const MAIL_STATUSES = ['pending', 'sent', 'failed'] as const;
export type MailStatus = (typeof MAIL_STATUSES)[number];

/**
 * One message to one recipient: the outbox while `pending`, then the delivery log. The rendered
 * body is kept encrypted (`payload_enc`, AAD `mail_messages.payload:<id>`) only while pending.
 */
export const mailMessages = pgTable(
  'mail_messages',
  {
    // queueMail makes the id first: the payload's AAD names it.
    id: id(),
    kind: text('kind').notNull(),
    userId: uuid('user_id').references(() => users.id, { onDelete: 'set null' }),
    toAddress: citext('to_address').notNull(),
    subject: text('subject').notNull(),
    status: text('status').notNull().default('pending').$type<MailStatus>(),
    attempts: integer('attempts').notNull().default(0),
    lastError: text('last_error'),
    smtpResponse: text('smtp_response'),
    payloadEnc: jsonb('payload_enc').$type<EncryptedValue>(),
    dedupeKey: text('dedupe_key'),
    nextAttemptAt: at('next_attempt_at'),
    sentAt: at('sent_at'),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [
    // The delivery log and housekeeping's retention.
    index('mail_messages_log_idx').on(t.createdAt.desc(), t.id.desc()),
    index('mail_messages_dedupe_idx')
      .on(t.dedupeKey, t.createdAt)
      .where(sql`dedupe_key IS NOT NULL`),
    index('mail_messages_pending_idx')
      .on(t.status)
      .where(sql`status = 'pending'`),
    // The user FK's index (§2).
    index('mail_messages_user_idx')
      .on(t.userId)
      .where(sql`user_id IS NOT NULL`),
    check('mail_messages_kind_check', sql`kind ~ '^[a-z0-9.-]{1,64}$'`),
    check('mail_messages_status_check', sql`status IN ('pending','sent','failed')`),
    check('mail_messages_subject_length', sql`char_length(subject) <= 300`),
    check('mail_messages_last_error_length', sql`octet_length(last_error) <= 1024`),
    check('mail_messages_smtp_response_length', sql`octet_length(smtp_response) <= 1024`),
    check('mail_messages_dedupe_key_length', sql`char_length(dedupe_key) <= 200`),
    check('mail_messages_payload_check', sql`payload_enc IS NULL OR status = 'pending'`),
  ],
);
export type MailMessageRow = typeof mailMessages.$inferSelect;

// ─── 4.11 Account tokens (mail E2, migration 0010_account_tokens) ──────────

export const ACCOUNT_TOKEN_KINDS = ['password_reset', 'invitation'] as const;
export type AccountTokenKind = (typeof ACCOUNT_TOKEN_KINDS)[number];

/**
 * Mail E2 A1: the one-time links of a password reset (60 minutes) and an invitation (7 days). The
 * key is the SHA-256 hex of the raw secret, which only the email holds; one row per user and kind,
 * taken with DELETE … RETURNING so each link works once on any replica.
 */
export const accountTokens = pgTable(
  'account_tokens',
  {
    key: text('key').primaryKey(),
    kind: text('kind').notNull().$type<AccountTokenKind>(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    createdBy: uuid('created_by').references(() => users.id, { onDelete: 'set null' }),
    expiresAt: at('expires_at').notNull(),
    createdAt: createdAt(),
  },
  (t) => [
    uniqueIndex('account_tokens_user_kind_unique').on(t.userId, t.kind),
    index('account_tokens_expires_idx').on(t.expiresAt),
    // The creator FK's index (§2).
    index('account_tokens_created_by_idx')
      .on(t.createdBy)
      .where(sql`created_by IS NOT NULL`),
    check('account_tokens_kind_check', sql`kind IN ('password_reset','invitation')`),
    check('account_tokens_key_format', sql`key ~ '^[0-9a-f]{64}$'`),
  ],
);

// ─── 4.12 Project notifications (mail E3) ───────────────────────────────────

/** mail E3 N3: a watch covers the main branch only, or every branch and merge request. */
export const WATCH_BRANCHES = ['main', 'all'] as const;
export type WatchBranches = (typeof WATCH_BRANCHES)[number];

/** mail E3 N1–N3: one person's watch of one project; opt-in, removed with either. */
export const projectWatches = pgTable(
  'project_watches',
  {
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    projectId: uuid('project_id')
      .notNull()
      .references(() => projects.id, { onDelete: 'cascade' }),
    branches: text('branches').notNull().default('main').$type<WatchBranches>(),
    gateFailed: boolean('gate_failed').notNull().default(true),
    gateRecovered: boolean('gate_recovered').notNull().default(true),
    analysisFailed: boolean('analysis_failed').notNull().default(true),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [
    primaryKey({ columns: [t.userId, t.projectId] }),
    index('project_watches_project_idx').on(t.projectId),
    check('project_watches_branches_check', sql`branches IN ('main','all')`),
  ],
);

/** mail E3 N6: a person's notification switches; no row means both on. */
export const notificationPreferences = pgTable('notification_preferences', {
  userId: uuid('user_id')
    .primaryKey()
    .references(() => users.id, { onDelete: 'cascade' }),
  email: boolean('email').notNull().default(true),
  orgWebhookFailures: boolean('org_webhook_failures').notNull().default(true),
  updatedAt: updatedAt(),
});

// ─── OAuth and MCP (Phase 6N, migration 0013_oauth) ──────────────────────────

export type OAuthClientSource = 'cimd' | 'dcr';
export type OAuthRequestStatus = 'pending' | 'code_issued' | 'used' | 'denied';
export type OAuthTokenKind = 'access' | 'refresh';

/** An OAuth client: a fetched CIMD document (cached) or a DCR registration (spec §4.5). */
export const oauthClients = pgTable(
  'oauth_clients',
  {
    id: id(),
    /** The CIMD URL, or `qlr_cli_…` for DCR. */
    clientId: text('client_id').notNull(),
    source: text('source').notNull().$type<OAuthClientSource>(),
    name: text('name').notNull(),
    redirectUris: text('redirect_uris').array().notNull(),
    logoUri: text('logo_uri'),
    clientUri: text('client_uri'),
    /** The CIMD document or the DCR request as received (validated). */
    metadata: jsonb('metadata').notNull().$type<Record<string, unknown>>(),
    fetchedAt: at('fetched_at'),
    /** CIMD only: when the cached document must be fetched again. */
    expiresAt: at('expires_at'),
    lastUsedAt: at('last_used_at'),
    createdAt: createdAt(),
  },
  (t) => [
    uniqueIndex('oauth_clients_client_id_idx').on(t.clientId),
    check('oauth_clients_source_check', sql`source IN ('cimd','dcr')`),
  ],
);

/** What a user allowed a client (spec §4.5); one live grant per user and client. */
export const oauthGrants = pgTable(
  'oauth_grants',
  {
    id: id(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    clientRowId: uuid('client_row_id')
      .notNull()
      .references(() => oauthClients.id, { onDelete: 'cascade' }),
    scopes: text('scopes').array().notNull(),
    createdAt: createdAt(),
    lastUsedAt: at('last_used_at'),
    revokedAt: at('revoked_at'),
    revokedBy: uuid('revoked_by').references(() => users.id, { onDelete: 'set null' }),
  },
  (t) => [
    index('oauth_grants_user_idx').on(t.userId),
    index('oauth_grants_client_idx').on(t.clientRowId),
    index('oauth_grants_revoked_by_idx')
      .on(t.revokedBy)
      .where(sql`revoked_by IS NOT NULL`),
    uniqueIndex('oauth_grants_live_idx')
      .on(t.userId, t.clientRowId)
      .where(sql`revoked_at IS NULL`),
  ],
);

/** A pending authorization request, then its code (spec §4.5, §6). */
export const oauthRequests = pgTable(
  'oauth_requests',
  {
    id: id(),
    clientRowId: uuid('client_row_id')
      .notNull()
      .references(() => oauthClients.id, { onDelete: 'cascade' }),
    redirectUri: text('redirect_uri').notNull(),
    state: text('state'),
    scopes: text('scopes').array().notNull(),
    codeChallenge: text('code_challenge').notNull(),
    resource: text('resource').notNull(),
    /** Set when a signed-in user first opens the consent screen; nobody else may answer it. */
    userId: uuid('user_id').references(() => users.id, { onDelete: 'cascade' }),
    grantId: uuid('grant_id').references(() => oauthGrants.id, { onDelete: 'cascade' }),
    codePrefix: text('code_prefix'),
    codeHash: bytea('code_hash'),
    status: text('status').notNull().default('pending').$type<OAuthRequestStatus>(),
    createdAt: createdAt(),
    expiresAt: at('expires_at').notNull(),
  },
  (t) => [
    index('oauth_requests_code_prefix_idx')
      .on(t.codePrefix)
      .where(sql`code_prefix IS NOT NULL`),
    index('oauth_requests_client_idx').on(t.clientRowId),
    index('oauth_requests_grant_idx')
      .on(t.grantId)
      .where(sql`grant_id IS NOT NULL`),
    index('oauth_requests_user_idx')
      .on(t.userId)
      .where(sql`user_id IS NOT NULL`),
    index('oauth_requests_expires_idx').on(t.expiresAt),
    check('oauth_requests_status_check', sql`status IN ('pending','code_issued','used','denied')`),
  ],
);

/** Access and refresh tokens of a grant, stored as hashes (spec §4.5). */
export const oauthTokens = pgTable(
  'oauth_tokens',
  {
    id: id(),
    grantId: uuid('grant_id')
      .notNull()
      .references(() => oauthGrants.id, { onDelete: 'cascade' }),
    kind: text('kind').notNull().$type<OAuthTokenKind>(),
    prefix: text('prefix').notNull(),
    secretHash: bytea('secret_hash').notNull(),
    expiresAt: at('expires_at').notNull(),
    /** Refresh rotation: the token that replaced this one; presenting a replaced one is reuse. */
    replacedBy: uuid('replaced_by'),
    revokedAt: at('revoked_at'),
    createdAt: createdAt(),
  },
  (t) => [
    index('oauth_tokens_prefix_idx').on(t.prefix),
    index('oauth_tokens_grant_idx').on(t.grantId),
    check('oauth_tokens_kind_check', sql`kind IN ('access','refresh')`),
  ],
);

// ─── AI review snapshots (Phase 6I-2, migration 0015_review_snapshots) ───────

export const REVIEW_SNAPSHOT_STATUSES = ['uploaded', 'ready', 'rejected'] as const;
export type ReviewSnapshotStatus = (typeof REVIEW_SNAPSHOT_STATUSES)[number];

/** What a snapshot's change line says happened to a path since the merge base. */
export const SNAPSHOT_CHANGES = ['added', 'modified', 'renamed', 'deleted'] as const;
export type SnapshotChange = (typeof SNAPSHOT_CHANGES)[number];

/** An instruction file (`AGENTS.md`, `CLAUDE.md`, `REVIEW.md`) as the merge base held it. */
export interface SnapshotInstruction {
  name: string;
  text: string;
}

/**
 * The copy of a merge request's repository the scanner uploads for the AI review (6I-2 R2, R3):
 * gzip'd JSON Lines, kept as sent in `body` while `uploaded`, then unpacked by a job into
 * `review_snapshot_files` (`ready`, `body` cleared) or refused (`rejected`, `error` says why).
 * One per analysis; `branch_id` is set when the analysis has succeeded on a merge request branch,
 * and the newest snapshot of a branch replaces the older ones. Not encrypted, like
 * `analysis_reports.body`; never served back through the API.
 */
export const reviewSnapshots = pgTable(
  'review_snapshots',
  {
    id: id(),
    analysisId: uuid('analysis_id')
      .notNull()
      .unique()
      .references(() => analyses.id, { onDelete: 'cascade' }),
    projectId: uuid('project_id')
      .notNull()
      .references(() => projects.id, { onDelete: 'cascade' }),
    branchId: uuid('branch_id').references(() => branches.id, { onDelete: 'cascade' }),
    status: text('status').notNull().default('uploaded').$type<ReviewSnapshotStatus>(),
    /** `SNAPSHOT_INVALID:<reason>` on a rejected snapshot. */
    error: text('error'),
    /** The upload as sent: present exactly while the status is `uploaded`. */
    body: bytea('body'),
    compressedBytes: integer('compressed_bytes').notNull(),
    inflatedBytes: bigint('inflated_bytes', { mode: 'number' }),
    /** The merge request's head commit, the merge base, and the last reviewed commit. */
    headSha: text('head_sha'),
    baseSha: text('base_sha'),
    sinceSha: text('since_sha'),
    targetBranch: text('target_branch'),
    mrTitle: text('mr_title'),
    mrDescription: text('mr_description'),
    instructions: jsonb('instructions')
      .notNull()
      .default(emptyJsonArray)
      .$type<SnapshotInstruction[]>(),
    /** The scanner left files out to stay within the limits (the review says so). */
    partial: boolean('partial').notNull().default(false),
    fileCount: integer('file_count').notNull().default(0),
    createdAt: createdAt(),
    unpackedAt: at('unpacked_at'),
  },
  (t) => [
    // The branch FK's index, and the other snapshots of one merge request.
    index('review_snapshots_branch_idx')
      .on(t.branchId)
      .where(sql`branch_id IS NOT NULL`),
    // The project FK's index (§2).
    index('review_snapshots_project_idx').on(t.projectId),
    // Housekeeping's retention.
    index('review_snapshots_created_idx').on(t.createdAt),
    check('review_snapshots_status_check', sql`status IN ('uploaded','ready','rejected')`),
    check('review_snapshots_body_by_status', sql`(status = 'uploaded') = (body IS NOT NULL)`),
    check('review_snapshots_head_sha_format', sql`head_sha ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'`),
    check('review_snapshots_base_sha_format', sql`base_sha ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'`),
    check('review_snapshots_since_sha_format', sql`since_sha ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'`),
  ],
);
export type ReviewSnapshotRow = typeof reviewSnapshots.$inferSelect;

/**
 * One row per path of an unpacked snapshot: the file's text at the head, an omission (a file the
 * scanner did not send, with the reason), and the change line (status, old path, patch and the
 * line ranges changed since the last review), merged by path. A path that fails the path rule of
 * the snapshot format (unsafe, or over 1 024 bytes) is never stored, not even as an omission: the
 * scanner leaves it out, and a snapshot that names one is rejected.
 */
export const reviewSnapshotFiles = pgTable(
  'review_snapshot_files',
  {
    snapshotId: uuid('snapshot_id')
      .notNull()
      .references(() => reviewSnapshots.id, { onDelete: 'cascade' }),
    path: text('path').notNull(),
    /** UTF-8 text, secrets masked by the scanner; null for an omitted or deleted file. */
    text: text('text'),
    bytes: integer('bytes').notNull().default(0),
    /** Why the text was not sent: one of the eight reasons the CHECK lists. */
    omitted: text('omitted'),
    change: text('change').$type<SnapshotChange>(),
    oldPath: text('old_path'),
    patch: text('patch'),
    /** 1-based inclusive line ranges changed since the last reviewed commit. */
    since: jsonb('since').$type<[number, number][]>(),
  },
  (t) => [
    primaryKey({ columns: [t.snapshotId, t.path] }),
    check(
      'review_snapshot_files_omitted_check',
      sql`omitted IN ('binary','too_large','excluded','credentials','symlink','submodule','limit','not_utf8')`,
    ),
    check(
      'review_snapshot_files_change_check',
      sql`change IN ('added','modified','renamed','deleted')`,
    ),
    check('review_snapshot_files_omitted_has_no_text', sql`text IS NULL OR omitted IS NULL`),
    check(
      'review_snapshot_files_deleted_has_no_text',
      sql`change IS DISTINCT FROM 'deleted' OR text IS NULL`,
    ),
  ],
);
export type ReviewSnapshotFileRow = typeof reviewSnapshotFiles.$inferSelect;

// ─── AI review runs and findings (Phase 6I-3, migration 0016_review_runs) ────

export const REVIEW_RUN_STATUSES = [
  'waiting',
  'running',
  'done',
  'skipped',
  'failed',
  'superseded',
] as const;
export type ReviewRunStatus = (typeof REVIEW_RUN_STATUSES)[number];

/** Why a run ended `skipped`: `reason` is one of these exactly when the status is `skipped`. */
export const REVIEW_SKIP_REASONS = [
  'no_snapshot',
  'snapshot_rejected',
  'draft',
  'closed',
  'inactive',
  'empty_diff',
  'unchanged',
  'budget_spent',
] as const;
export type ReviewSkipReason = (typeof REVIEW_SKIP_REASONS)[number];

/** Why a run ended `failed`: `reason` is one of these exactly when the status is `failed`. */
export const REVIEW_FAILURE_REASONS = [
  'provider_error',
  'provider_no_tools',
  'bad_answer',
  'internal',
] as const;
export type ReviewFailureReason = (typeof REVIEW_FAILURE_REASONS)[number];

/** What a `running` run is doing; `phase` is null in every other status. */
export const REVIEW_PHASES = ['specialists', 'judge', 'verification', 'storing'] as const;
export type ReviewPhase = (typeof REVIEW_PHASES)[number];

/** How much review the size of the change earned. */
export const REVIEW_TIERS = ['trivial', 'lite', 'full'] as const;
export type ReviewTier = (typeof REVIEW_TIERS)[number];

/** The categories of an AI finding; the rule of its issue is `ai:<category>`. */
export const AI_CATEGORIES = [
  'logic',
  'error-handling',
  'compatibility',
  'concurrency',
  'security',
  'performance',
  'tests',
  'docs',
] as const;
export type AiCategory = (typeof AI_CATEGORIES)[number];

/**
 * One AI review of one merge request analysis (6I-3, R15). The ingestion stage creates it
 * `waiting` for the scanner's snapshot; the `ai-review` worker runs it and ends it `done`,
 * `skipped` (`reason` says why), `failed`, or `superseded` by a newer analysis of the merge
 * request. It keeps the lifecycle, the spend and the summary; the findings themselves are issues
 * of engine `ai`, each with a `review_findings` row.
 */
export const reviewRuns = pgTable(
  'review_runs',
  {
    id: id(),
    projectId: uuid('project_id')
      .notNull()
      .references(() => projects.id, { onDelete: 'cascade' }),
    branchId: uuid('branch_id')
      .notNull()
      .references(() => branches.id, { onDelete: 'cascade' }),
    analysisId: uuid('analysis_id')
      .notNull()
      .unique()
      .references(() => analyses.id, { onDelete: 'cascade' }),
    /** The snapshot the run reads: null until it has one, and after the snapshot was deleted. */
    snapshotId: uuid('snapshot_id').references(() => reviewSnapshots.id, { onDelete: 'set null' }),
    status: text('status').notNull().default('waiting').$type<ReviewRunStatus>(),
    /** Set only while `running`. */
    phase: text('phase').$type<ReviewPhase>(),
    /** A skip reason exactly when `skipped`, a failure reason exactly when `failed`, else null. */
    reason: text('reason').$type<ReviewSkipReason | ReviewFailureReason>(),
    /** At most 200 characters: a code such as `SNAPSHOT_INVALID`, never content. */
    detail: text('detail'),
    /**
     * The SCM user name (at most 255 characters) of the person whose `qualor review` note asked for
     * this run, null for a run that began with its analysis. A requested run is reviewed as a draft too.
     */
    requestedBy: text('requested_by'),
    /** The merge request's head commit the review is of, and the last reviewed commit before it. */
    headSha: text('head_sha'),
    sinceSha: text('since_sha'),
    /** sha256 of the reviewable changes, to recognise a diff that has not changed. */
    diffDigest: char('diff_digest', { length: 64 }),
    tier: text('tier').$type<ReviewTier>(),
    /** The specialist reviewers that ran. */
    reviewers: text('reviewers').array().notNull().default(emptyTextArray),
    /** Where the provider calls went. */
    providerHost: text('provider_host'),
    model: text('model'),
    modelCalls: integer('model_calls').notNull().default(0),
    toolCalls: integer('tool_calls').notNull().default(0),
    inputTokens: bigint('input_tokens', { mode: 'number' }).notNull().default(0),
    outputTokens: bigint('output_tokens', { mode: 'number' }).notNull().default(0),
    /** Estimated, as in `llm_requests`: null when no prices are set. */
    costMicroUsd: bigint('cost_micro_usd', { mode: 'number' }),
    /**
     * A conversation used up its tokens and answered with what it had, or had none to start with
     * (a turn limit is no token limit: the summary's notes say it).
     */
    tokenLimitReached: boolean('token_limit_reached').notNull().default(false),
    /** The scanner left files out of the snapshot to stay within its limits. */
    snapshotPartial: boolean('snapshot_partial').notNull().default(false),
    /** `{ verdict, walkthrough[], notes[] }`, validated by `reviewSummarySchema`. */
    summary: jsonb('summary').$type<unknown>(),
    findingsNew: integer('findings_new').notNull().default(0),
    findingsOpen: integer('findings_open').notNull().default(0),
    findingsFixed: integer('findings_fixed').notNull().default(0),
    /** When a `waiting` run stops waiting for its snapshot. */
    deadlineAt: at('deadline_at').notNull(),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
    startedAt: at('started_at'),
    finishedAt: at('finished_at'),
  },
  (t) => [
    // The branch FK's index; a branch's runs, newest first (its last reviewed commit and digest).
    // NULLS FIRST is what DESC means without a clause: only then is a plain `ORDER BY created_at
    // DESC` read from the index in order (drizzle's `.desc()` alone adds NULLS LAST).
    index('review_runs_branch_idx').on(t.branchId, t.createdAt.desc().nullsFirst()),
    // The project FK's index (§2).
    index('review_runs_project_idx').on(t.projectId),
    // The snapshot FK's index (§2).
    index('review_runs_snapshot_idx')
      .on(t.snapshotId)
      .where(sql`snapshot_id IS NOT NULL`),
    // The runs still to do: the deadline, the supersede and the worker look only at these.
    index('review_runs_active_idx')
      .on(t.status)
      .where(sql`status IN ('waiting','running')`),
    check(
      'review_runs_status_check',
      sql`status IN ('waiting','running','done','skipped','failed','superseded')`,
    ),
    check(
      'review_runs_phase_check',
      sql`phase IN ('specialists','judge','verification','storing')`,
    ),
    check('review_runs_phase_only_while_running', sql`phase IS NULL OR status = 'running'`),
    // `reason IS NOT NULL AND` keeps a missing reason a violation: a NULL result would pass a CHECK.
    check(
      'review_runs_reason_by_status',
      sql`CASE status WHEN 'skipped' THEN reason IS NOT NULL AND reason IN ('no_snapshot','snapshot_rejected','draft','closed','inactive','empty_diff','unchanged','budget_spent') WHEN 'failed' THEN reason IS NOT NULL AND reason IN ('provider_error','provider_no_tools','bad_answer','internal') ELSE reason IS NULL END`,
    ),
    check('review_runs_detail_length', sql`char_length(detail) <= 200`),
    check('review_runs_requested_by_length', sql`char_length(requested_by) <= 255`),
    check('review_runs_head_sha_format', sql`head_sha ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'`),
    check('review_runs_since_sha_format', sql`since_sha ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'`),
    check('review_runs_diff_digest_format', sql`diff_digest ~ '^[0-9a-f]{64}$'`),
    check('review_runs_tier_check', sql`tier IN ('trivial','lite','full')`),
  ],
);
export type ReviewRunRow = typeof reviewRuns.$inferSelect;

/**
 * What an AI finding keeps beside its issue (6I-3, R18): the text, the one-click suggestion and
 * where its thread sits. One row per issue of engine `ai`, deleted with the issue. `run_id` is
 * the run that last emitted or re-checked the finding, and goes null when that run is deleted.
 */
export const reviewFindings = pgTable(
  'review_findings',
  {
    issueId: uuid('issue_id')
      .primaryKey()
      .references(() => issues.id, { onDelete: 'cascade' }),
    runId: uuid('run_id').references(() => reviewRuns.id, { onDelete: 'set null' }),
    category: text('category').notNull().$type<AiCategory>(),
    /** At most 2 000 characters. */
    body: text('body').notNull(),
    /** At most 300 characters: what the finding takes for granted. */
    assumption: text('assumption'),
    /** The independent verification of a security finding; null when it was not verified. */
    verification: text('verification').$type<'confirmed' | 'needs_validation'>(),
    /** A one-click replacement: the head lines `startLine` to `endLine` become `lines`. */
    suggestion: jsonb('suggestion').$type<{
      startLine: number;
      endLine: number;
      lines: string[];
    }>(),
    /** The added line a thread sits on; null when the finding cannot be placed inline. */
    anchorLine: integer('anchor_line'),
    /**
     * The head commit its `anchor_line` and `suggestion` were made for. The three are written
     * together, when a review raises the finding, or raises it again where it can be placed on that
     * head. A finding the review only finds still there, or closes, keeps the head of its last
     * placement (`run_id` says which review looked at it last).
     */
    reviewedHeadSha: text('reviewed_head_sha').notNull(),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [
    // The run FK's index (§2); the issue FK is the primary key.
    index('review_findings_run_idx')
      .on(t.runId)
      .where(sql`run_id IS NOT NULL`),
    check(
      'review_findings_category_check',
      sql`category IN ('logic','error-handling','compatibility','concurrency','security','performance','tests','docs')`,
    ),
    check('review_findings_body_length', sql`char_length(body) <= 2000`),
    check('review_findings_assumption_length', sql`char_length(assumption) <= 300`),
    check(
      'review_findings_verification_check',
      sql`verification IN ('confirmed','needs_validation')`,
    ),
    check(
      'review_findings_reviewed_head_sha_format',
      sql`reviewed_head_sha ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'`,
    ),
  ],
);
export type ReviewFindingRow = typeof reviewFindings.$inferSelect;

// ─── AI review replies and commands (Phase 6I-4, migration 0017_review_replies) ─

/** What Qualor handles a note as: a reply in one of its threads, or a command such as `qualor review`. */
export const REPLY_KINDS = ['reply', 'command'] as const;
export type ReplyKind = (typeof REPLY_KINDS)[number];

/** The commands a note can give; `command` is set exactly when the kind is `command`. */
export const REPLY_COMMANDS = ['review', 'fix', 'stop'] as const;
export type ReplyCommand = (typeof REPLY_COMMANDS)[number];

export const REPLY_STATUSES = ['queued', 'running', 'done', 'skipped', 'failed'] as const;
export type ReplyStatus = (typeof REPLY_STATUSES)[number];

/**
 * What the model decided about the issue of a thread: `keep` leaves it as it is, the other two are
 * the statuses a reply may give it.
 */
export const REPLY_VERDICTS = ['keep', 'wont_fix', 'false_positive'] as const;
export type ReplyVerdict = (typeof REPLY_VERDICTS)[number];

/** How a handled note came out: the first five for a reply, the others for a command. */
export const REPLY_OUTCOMES = [
  'answered',
  'acknowledged',
  'explained',
  'wont_fix',
  'false_positive',
  'review_requested',
  'in_progress',
  'already_reviewed',
  'not_available',
  'review_off',
] as const;
export type ReplyOutcome = (typeof REPLY_OUTCOMES)[number];

/**
 * Why a note was not answered: the first six are reasons to skip it (`superseded`: a newer round
 * of its thread answers its notes; `expired`: it waited longer than the reply window, for an SCM
 * connection or a model provider that was failing), the others how it failed.
 */
export const REPLY_REASONS = [
  'budget_spent',
  'inactive',
  'closed',
  'thread_gone',
  'superseded',
  'expired',
  'provider_error',
  'provider_no_tools',
  'bad_answer',
  'internal',
] as const;
export type ReplyReason = (typeof REPLY_REASONS)[number];

/**
 * The thread ids the replies ledger takes (its CHECK `review_replies_thread_id_format`, written
 * from this pattern): a GitLab discussion's lower-case hexadecimal id, or the digits of a GitHub
 * comment's id. The same shapes a reply can be posted to.
 */
export const THREAD_ID = /^[0-9a-f]{1,64}$|^[0-9]{1,20}$/;
/** That pattern as a quoted SQL literal for the CHECK. */
const THREAD_ID_SQL = `'${THREAD_ID.source}'`;

/**
 * What Qualor does with people's notes in a merge request: one row for each note it handles, a
 * reply in one of its threads or a command. A note is one row for its project, provider and kind
 * (on GitHub a reply is a review comment and a command an issue comment, two id spaces that can
 * share a number), which is what makes it answered once, whichever of decoration and a webhook
 * finds it first. The model's decision is stored before anything is posted, and the id of the
 * answer note once it is, so that a retry resumes after the last step done and never asks the
 * model twice.
 */
export const reviewReplies = pgTable(
  'review_replies',
  {
    id: id(),
    projectId: uuid('project_id')
      .notNull()
      .references(() => projects.id, { onDelete: 'cascade' }),
    branchId: uuid('branch_id')
      .notNull()
      .references(() => branches.id, { onDelete: 'cascade' }),
    provider: text('provider').notNull().$type<'gitlab' | 'github'>(),
    /** The SCM's id of the note (GitLab) or comment (GitHub), which it counts upwards. */
    noteId: bigint('note_id', { mode: 'number' }).notNull(),
    /**
     * The thread the note is in: GitLab's discussion id (hexadecimal), or the id of the first
     * comment of a GitHub thread (digits). Null for a note outside any thread: GitHub's top-level
     * comment.
     */
    threadId: text('thread_id'),
    /** The issue the thread is about; null for a command, and once the issue is deleted. */
    issueId: uuid('issue_id').references(() => issues.id, { onDelete: 'set null' }),
    kind: text('kind').notNull().$type<ReplyKind>(),
    /** Set exactly when `kind` is `command`. */
    command: text('command').$type<ReplyCommand>(),
    /** The SCM user name of the person who wrote the note: at most 255 characters. */
    author: text('author').notNull(),
    status: text('status').notNull().default('queued').$type<ReplyStatus>(),
    /** How the note came out, once handled. */
    outcome: text('outcome').$type<ReplyOutcome>(),
    /** Why a note was skipped or failed. */
    reason: text('reason').$type<ReplyReason>(),
    /** The model's decision, with its `answer` (at most 1 200 characters; may be empty). */
    verdict: text('verdict').$type<ReplyVerdict>(),
    answer: text('answer'),
    /** The id of the note Qualor posted as its answer. */
    answerNoteId: bigint('answer_note_id', { mode: 'number' }),
    /** The model that decided, and what its calls spent: no model where no call was made. */
    model: text('model'),
    inputTokens: integer('input_tokens').notNull().default(0),
    outputTokens: integer('output_tokens').notNull().default(0),
    /** Estimated, as in `llm_requests`: null when no prices are set. */
    costMicroUsd: bigint('cost_micro_usd', { mode: 'number' }),
    createdAt: createdAt(),
    startedAt: at('started_at'),
    /** Set exactly when the status is `done`, `skipped` or `failed`. */
    finishedAt: at('finished_at'),
  },
  (t) => [
    // Also the project FK's index.
    unique('review_replies_note_unique').on(t.projectId, t.provider, t.kind, t.noteId),
    // A thread's notes by id, for the newest note the ledger holds of each; also the branch FK's index.
    index('review_replies_thread_idx').on(t.branchId, t.threadId, t.noteId),
    // The issue FK's index (§2).
    index('review_replies_issue_idx')
      .on(t.issueId)
      .where(sql`issue_id IS NOT NULL`),
    // The rows still to answer: the sweep after every reap reads only these.
    index('review_replies_active_idx')
      .on(t.status)
      .where(sql`status IN ('queued','running')`),
    check('review_replies_provider_check', sql`provider IN ('gitlab','github')`),
    check('review_replies_kind_check', sql`kind IN ('reply','command')`),
    check('review_replies_command_check', sql`command IN ('review','fix','stop')`),
    // `kind` is never NULL and neither is `IS NOT NULL`: a NULL result would pass a CHECK.
    check('review_replies_command_by_kind', sql`(kind = 'command') = (command IS NOT NULL)`),
    check('review_replies_author_length', sql`char_length(author) <= 255`),
    check(
      'review_replies_status_check',
      sql`status IN ('queued','running','done','skipped','failed')`,
    ),
    // A row has ended exactly when it has its finish time. Both sides are never NULL.
    check(
      'review_replies_finished_by_status',
      sql`(status IN ('done','skipped','failed')) = (finished_at IS NOT NULL)`,
    ),
    check(
      'review_replies_outcome_check',
      sql`outcome IN ('answered','acknowledged','explained','wont_fix','false_positive','review_requested','in_progress','already_reviewed','not_available','review_off')`,
    ),
    check(
      'review_replies_reason_check',
      sql`reason IN ('budget_spent','inactive','closed','thread_gone','superseded','expired','provider_error','provider_no_tools','bad_answer','internal')`,
    ),
    check('review_replies_verdict_check', sql`verdict IN ('keep','wont_fix','false_positive')`),
    check('review_replies_answer_length', sql`char_length(answer) <= 1200`),
    check('review_replies_thread_id_format', sql`thread_id ~ ${sql.raw(THREAD_ID_SQL)}`),
  ],
);
