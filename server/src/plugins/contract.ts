/**
 * The plugin contract v1 (api.md §5, enterprise.md §10). Core owns it; `enterprise/` implements it
 * and imports it with `import type` only (enterprise.md §12). Everything a plugin may do goes
 * through the context: it gets no Fastify instance, no configuration and no secret key.
 */
import type { Readable } from 'node:stream';
import type { FastifyBaseLogger, FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify';
import type { AuditEventRecord } from '../audit/chain';
import type { AuditFilter } from '../audit/query';
import type { AuditActorContext, AuditEventInput } from '../audit/recorder';
import type { AuditSettingsInput, AuditSettingsView } from '../audit/settings';
import type { AuditHead, AuditVerification } from '../audit/verify';
import type { OrganizationAccess } from '../auth/access';
import type {
  ComplianceDatasets,
  ComplianceFindingGroup,
  ComplianceFindingRow,
  ComplianceProjectSource,
  ComplianceReportScope,
  ComplianceReportStatus,
  ComplianceSource,
  ComplianceStandardRef,
  ComplianceTriageRow,
  ComplianceVulnerability,
  FindingSection,
  Severity,
} from '../compliance/types';
import type { OrganizationPermission, ProjectPermission } from '../auth/policy';
import type { UserPrincipal } from '../auth/principal';
import type { Db } from '../db/client';
import type { Granularity } from '../portfolio/periods';
import type {
  PortfolioAggregate,
  PortfolioOverview,
  PortfolioProjectRow,
  PortfolioScopeInput,
  PortfolioSort,
  PortfolioTrendPoint,
  Rating,
  SeverityCounts,
} from '../portfolio/types';
import type { ProjectRole } from '../db/schema';
import type { LicensePayload } from '../license/token';
import type { PluginLimitOverride } from '../limits';
import type { ScimTokenView } from '../scim/tokens';
import type { IdentityView } from '../sso/accounts';
import type {
  SsoConnectionInput,
  SsoConnectionPatch,
  SsoConnectionView,
  SsoTestResult,
} from '../sso/connections';
import type { SsoGroupMappingInput, SsoGroupMappingView } from '../sso/groups';
import type {
  SamlMetadataPreview,
  ScimTokenInput,
  SignInSettingsInput,
  SignInSettingsView,
} from '../sso/service';

/** The core types the 4D services use (sso-scim.md §17.1), for the plugin's `import type`. */
export type {
  IdentityView,
  SamlMetadataPreview,
  ScimTokenInput,
  ScimTokenView,
  SignInSettingsInput,
  SignInSettingsView,
  SsoConnectionInput,
  SsoConnectionPatch,
  SsoConnectionView,
  SsoGroupMappingInput,
  SsoGroupMappingView,
  SsoTestResult,
};

/** The core types the 4E-2 portfolio service uses (4E-2 §2), for the plugin's `import type`. */
export type {
  Granularity,
  PortfolioAggregate,
  PortfolioOverview,
  PortfolioProjectRow,
  PortfolioScopeInput,
  PortfolioSort,
  PortfolioTrendPoint,
  Rating,
  SeverityCounts,
};

/** The core types the 4E-1 compliance service uses (4E-1 §1.1), for the plugin's `import type`. */
export type {
  ComplianceDatasets,
  ComplianceFindingGroup,
  ComplianceFindingRow,
  ComplianceProjectSource,
  ComplianceReportScope,
  ComplianceReportStatus,
  ComplianceSource,
  ComplianceStandardRef,
  ComplianceTriageRow,
  ComplianceVulnerability,
  FindingSection,
  Severity,
};

/** The core types the 4C services use, for the plugin to import with `import type`. */
export type {
  AuditActorContext,
  AuditEventInput,
  AuditEventRecord,
  AuditFilter,
  AuditHead,
  AuditSettingsInput,
  AuditSettingsView,
  AuditVerification,
  OrganizationAccess,
  OrganizationPermission,
  ProjectPermission,
  ProjectRole,
  UserPrincipal,
};

export const PLUGIN_API_VERSION = 1;

export type PluginLogger = Pick<FastifyBaseLogger, 'debug' | 'info' | 'warn' | 'error'>;

export interface PluginJob {
  id: string;
  queue: string;
  payload: unknown;
  attempts: number;
  /** Aborted when the job's time limit ends (enterprise.md §10.3); pass it to the job's I/O. */
  signal: AbortSignal;
}

export type PluginJobHandler = (job: PluginJob) => Promise<void>;

/**
 * 4E-1 §2.4 (additive): how a job is queued. `concurrencyKey` (`ee.<name>`, as a queue name): no
 * two jobs with the same key run at once, across workers and replicas; none by default.
 * `maxAttempts`: 1 to 5 (the default); a failed attempt is retried with a backoff.
 */
export interface PluginEnqueueOptions {
  concurrencyKey?: string;
  maxAttempts?: number;
}

/**
 * enterprise.md §10.4: an entry shown while its feature is active. `settings.nav`: a navigation
 * entry under Settings, `path` = `/settings/ee/<id>`. `project.tab` (4E-1 §4): a tab of the
 * project page, `path` a relative tab path (`^[a-z][a-z0-9-]{0,31}$`). `main.nav` (4E-2 §4): an
 * entry in the main navigation, `path` absolute (`^/[a-z][a-z0-9/-]{0,63}$`).
 */
export interface UiExtension {
  point: 'settings.nav' | 'project.tab' | 'main.nav';
  id: string;
  label: string;
  path: string;
}

export interface QualorPlugin {
  /** `^[a-z][a-z0-9-]{0,63}$`, unique among loaded plugins. */
  name: string;
  apiVersion: typeof PLUGIN_API_VERSION;
  /** The features it implements (enterprise.md §7.1); each registration names one of them. */
  features: readonly string[];
  register(ctx: PluginContext): Promise<void> | void;
}

export interface PluginContext {
  readonly apiVersion: typeof PLUGIN_API_VERSION;
  readonly serverVersion: string;
  readonly license: Readonly<LicensePayload>;
  readonly logger: PluginLogger;
  readonly db: Db;
  /** Mounted under /api/v0/ee; 403 FEATURE_NOT_LICENSED while the feature is inactive. */
  routes(feature: string, routes: FastifyPluginAsync): void;
  /** Queue names `^ee\.[a-z0-9][a-z0-9.-]{0,62}$`; skipped while the feature is inactive. */
  jobs(feature: string, handlers: Readonly<Record<string, PluginJobHandler>>): void;
  /** Only queues this plugin registered. */
  enqueue(queue: string, payload: unknown, options?: PluginEnqueueOptions): Promise<string>;
  limits(feature: string, override: PluginLimitOverride): void;
  ui(feature: string, extension: UiExtension): void;
  /** rbac-audit.md §15 (4C, additive): the route checks core routes use. */
  readonly access: PluginAccess;
  /** The audit log; the caller is checked first through `access`. */
  readonly audit: PluginAudit;
  /**
   * Runs the queue's job every `everySeconds` (10–86 400, whole seconds), one at a time across
   * replicas, while the feature is active. Only a queue this plugin registers with `jobs`.
   */
  schedule(feature: string, queue: string, everySeconds: number): void;
  /** sso-scim.md §17.1 (4D, additive): SSO connections, sign-in settings and the flows. */
  readonly sso: PluginSso;
  /** sso-scim.md §17.1 (4D, additive): the SCIM protocol and its tokens. */
  readonly scim: PluginScim;
  /** 4E-1 §1.1 (additive): compliance reports, with core's permission checks. */
  readonly compliance: PluginCompliance;
  /** 4E-2 §2 (additive): portfolio reports, with core's permission checks. */
  readonly portfolio: PluginPortfolio;
  /** 4E-3b §4 (additive): the support bundle, with core's permission check. */
  readonly support: PluginSupport;
}

export type PluginPage<T> = { items: T[]; nextCursor: string | null };

/** rbac-audit.md §15: the route checks, the same functions core routes use. */
export interface PluginAccess {
  requireUser(request: FastifyRequest, scope?: 'read' | 'write' | 'admin'): UserPrincipal;
  requireInstanceAdmin(request: FastifyRequest): UserPrincipal;
  requireOrganizationAccess(
    request: FastifyRequest,
    organizationId: string,
    permission: OrganizationPermission,
  ): Promise<OrganizationAccess>;
  projectForUser(
    request: FastifyRequest,
    projectId: string,
    permission: ProjectPermission,
  ): Promise<{ id: string; key: string; organizationId: string }>;
  actor(request: FastifyRequest): AuditActorContext;
  /** A core problem (api.md §2.1) to throw: the plugin cannot import ProblemError. */
  problem(status: number, code: string, title: string, detail?: string): Error;
}

export interface PluginAudit {
  query(
    filter: AuditFilter,
    page: { limit: number; cursor?: string },
  ): Promise<PluginPage<AuditEventRecord>>;
  exportLines(filter: AuditFilter & { from: Date; to: Date }): AsyncIterable<string>;
  record(actor: AuditActorContext, event: AuditEventInput): Promise<void>;
  head(): Promise<AuditHead>;
  /** `fromSeq` and `toSeq` are decimal strings, as seqs are everywhere in the API (§10.3). */
  verify(range: { fromSeq?: string; toSeq?: string }): Promise<AuditVerification>;
  settings(): Promise<AuditSettingsView>;
  updateSettings(
    actor: AuditActorContext,
    input: AuditSettingsInput,
  ): Promise<{ view: AuditSettingsView; secret: string | null }>;
  regenerateStreamSecret(actor: AuditActorContext): Promise<string>;
  testStream(): Promise<{ ok: boolean; status: number | null; excerpt: string | null }>;
  streamOnce(signal: AbortSignal): Promise<void>;
}

/**
 * sso-scim.md §17.1: built by core. Every member answers 403 FEATURE_NOT_LICENSED while `sso` is
 * inactive (ruling SS1). The admin members check nothing about the caller: the plugin's route
 * checks it first through `access`. The browser flows carry their own checks and write the
 * redirect, the cookies and the session themselves.
 */
export interface PluginSso {
  // instance admin (the route calls ctx.access.requireInstanceAdmin first)
  listConnections(): Promise<SsoConnectionView[]>;
  getConnection(id: string): Promise<SsoConnectionView>;
  createConnection(actor: AuditActorContext, input: SsoConnectionInput): Promise<SsoConnectionView>;
  updateConnection(
    actor: AuditActorContext,
    id: string,
    input: SsoConnectionPatch,
  ): Promise<SsoConnectionView>;
  deleteConnection(actor: AuditActorContext, id: string): Promise<void>;
  testConnection(id: string): Promise<SsoTestResult>;
  readSamlMetadata(id: string): Promise<SamlMetadataPreview>;
  mappings(id: string): Promise<SsoGroupMappingView[]>;
  replaceMappings(
    actor: AuditActorContext,
    id: string,
    input: SsoGroupMappingInput[],
  ): Promise<SsoGroupMappingView[]>;
  signInSettings(): Promise<SignInSettingsView>;
  updateSignInSettings(
    actor: AuditActorContext,
    input: SignInSettingsInput,
  ): Promise<SignInSettingsView>;
  userIdentities(userId: string): Promise<IdentityView[]>;
  unlinkIdentity(
    actor: AuditActorContext,
    userId: string,
    identityId: string,
    byAdmin: boolean,
  ): Promise<void>;
  // browser flows: core writes the redirect, the cookies and the session
  spMetadata(id: string): Promise<string>;
  start(request: FastifyRequest, reply: FastifyReply, id: string): Promise<FastifyReply>;
  startLink(request: FastifyRequest, reply: FastifyReply, id: string): Promise<{ url: string }>;
  oidcCallback(request: FastifyRequest, reply: FastifyReply, id: string): Promise<FastifyReply>;
  samlAcs(request: FastifyRequest, reply: FastifyReply, id: string): Promise<FastifyReply>;
  finish(request: FastifyRequest, reply: FastifyReply): Promise<FastifyReply>;
}

/** sso-scim.md §17.1: the token members answer 403 FEATURE_NOT_LICENSED while `scim` is off. */
export interface PluginScim {
  /** Parses the body types, authenticates the token, rate-limits, dispatches, and writes a SCIM answer or error. */
  handle(request: FastifyRequest, reply: FastifyReply): Promise<FastifyReply>;
  listTokens(connectionId?: string): Promise<ScimTokenView[]>;
  createToken(
    actor: AuditActorContext,
    input: ScimTokenInput,
  ): Promise<{ view: ScimTokenView; token: string }>;
  revokeToken(actor: AuditActorContext, id: string): Promise<void>;
}

export type ComplianceDownloadFormat = 'json' | 'csv' | 'pdf';

/** 4E-1 §3: a report as the API shows it; never its data. */
export interface ComplianceReportView {
  id: string;
  scope: ComplianceReportScope;
  organization: { id: string; key: string; name: string };
  project: { id: string; key: string; name: string } | null;
  branch: { id: string; name: string } | null;
  status: ComplianceReportStatus;
  createdBy: string;
  createdAt: string;
  completedAt: string | null;
  standards: ComplianceStandardRef[];
  sha256: string | null;
  sizeBytes: number | null;
  error: string | null;
  summary: unknown | null;
  /** The caller may delete it (org.compliance.manage on its organisation). */
  canDelete: boolean;
}

export type ComplianceCreateInput =
  { organizationId: string } | { projectId: string; branchId?: string };
export type ComplianceListFilter = { organizationId: string } | { projectId: string };

/**
 * 4E-2 §2: built by core, computed on request over the projects the caller can read. Every member
 * answers 403 FEATURE_NOT_LICENSED while `portfolio` is inactive and checks the caller itself.
 */
export interface PluginPortfolio {
  overview(
    request: FastifyRequest,
    input: PortfolioScopeInput,
    options: { granularity: Granularity },
  ): Promise<PortfolioOverview>;
  projects(
    request: FastifyRequest,
    input: PortfolioScopeInput,
    page: { sort: PortfolioSort; cursor?: string; limit: number },
  ): Promise<PluginPage<PortfolioProjectRow>>;
  exportRows(
    request: FastifyRequest,
    input: PortfolioScopeInput,
  ): AsyncIterable<PortfolioProjectRow>;
}

/**
 * 4E-3b §4: built by core. `bundle` answers 403 FEATURE_NOT_LICENSED while `support-bundle` is
 * inactive, requires an instance admin, and records `support.bundle_downloaded` (target null,
 * details `{ source: 'ui', bytes }`). The stream is the whole zip, at most 20 MiB, with no secret
 * value in it; the plugin's route sends it as `fileName`.
 */
export interface PluginSupport {
  bundle(request: FastifyRequest): Promise<{ fileName: string; stream: Readable }>;
}

/**
 * 4E-1 §1.1: built by core. Every member except `housekeeping` answers 403 FEATURE_NOT_LICENSED
 * while `compliance-export` is inactive. The members that take the request check the caller
 * themselves (a report it cannot read is a 404) and write their audit events; the job-side
 * members take no caller.
 */
export interface PluginCompliance {
  create(
    request: FastifyRequest,
    input: ComplianceCreateInput,
    standards: readonly ComplianceStandardRef[],
  ): Promise<ComplianceReportView>;
  list(
    request: FastifyRequest,
    filter: ComplianceListFilter,
    page: { limit: number; cursor?: string },
  ): Promise<PluginPage<ComplianceReportView>>;
  get(request: FastifyRequest, id: string): Promise<ComplianceReportView>;
  /** The view and the gunzipped canonical JSON; records `compliance.report.downloaded`. */
  download(
    request: FastifyRequest,
    id: string,
    format: ComplianceDownloadFormat,
  ): Promise<{ view: ComplianceReportView; canonical: Buffer }>;
  remove(request: FastifyRequest, id: string): Promise<void>;
  /** A known build failure rejects with a problem of code REPORT_BUILD_FAILED and a `detail`. */
  collect(id: string, options: { limit: number; signal?: AbortSignal }): Promise<ComplianceSource>;
  /**
   * False when the row is gone or no longer pending (nothing written), or when core failed it
   * (a summary over 64 KiB, or a `sha256` that is not the SHA-256 of `canonical`). `standards`,
   * the refs the build used, replace the ones stored at creation, so the row and the JSON agree.
   */
  complete(
    id: string,
    result: {
      canonical: Buffer;
      sha256: string;
      summary: unknown;
      standards?: readonly ComplianceStandardRef[];
    },
  ): Promise<boolean>;
  fail(id: string, error: string): Promise<boolean>;
  housekeeping(): Promise<{ deleted: number; failed: number }>;
}

export interface PluginReport {
  name: string;
  state: 'loaded' | 'failed';
  features: string[];
  error: string | null;
}
