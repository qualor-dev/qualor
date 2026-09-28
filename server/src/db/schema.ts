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
     * github.md §2.5: the GitHub webhook secret, AES-256-GCM with AAD
     * `scm_connections.webhook_secret_enc`; NULL when unset, and always for GitLab.
     */
    webhookSecretEnc: jsonb('webhook_secret_enc').$type<EncryptedValue>(),
    createdAt: createdAt(),
  },
  (t) => [
    index('scm_connections_organization_idx').on(t.organizationId),
    check('scm_connections_provider_check', sql`provider IN ('gitlab','github')`),
    // A NULL app_id would make the regex test NULL, which a CHECK lets through: hence IS NOT NULL.
    check(
      'scm_connections_github_app_check',
      sql`(provider = 'gitlab' AND app_id IS NULL AND webhook_secret_enc IS NULL) OR (provider = 'github' AND app_id IS NOT NULL AND app_id ~ '^[0-9]{1,20}$')`,
    ),
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
    check('rules_quality_check', sql`quality IN ('security','reliability','maintainability')`),
    check('rules_kind_check', sql`kind IN ('issue','hotspot')`),
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
    createdAt: createdAt(),
  },
  (t) => [
    primaryKey({ columns: [t.profileId, t.ruleId] }),
    index('profile_rules_rule_idx').on(t.ruleId),
    check(
      'profile_rules_severity_check',
      sql`severity_override IN ('blocker','high','medium','low','info')`,
    ),
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
    check('issues_quality_check', sql`quality IN ('security','reliability','maintainability')`),
    check('issues_kind_check', sql`kind IN ('issue','hotspot')`),
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

export const webhookSubscriptions = pgTable(
  'webhook_subscriptions',
  {
    id: id(),
    organizationId: uuid('organization_id')
      .notNull()
      .references(() => organizations.id, { onDelete: 'cascade' }),
    projectId: uuid('project_id').references(() => projects.id, { onDelete: 'cascade' }),
    url: text('url').notNull(),
    secretEnc: jsonb('secret_enc').notNull().$type<EncryptedValue>(),
    events: text('events').array().notNull(),
    active: boolean('active').notNull().default(true),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [
    index('webhook_subscriptions_organization_idx').on(t.organizationId),
    index('webhook_subscriptions_project_idx')
      .on(t.projectId)
      .where(sql`project_id IS NOT NULL`),
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
    feature: text('feature').notNull().$type<'explain' | 'triage' | 'fix'>(),
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
    check('llm_requests_feature_check', sql`feature IN ('explain','triage','fix')`),
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
