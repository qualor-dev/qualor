/**
 * The plugin contract v1 (api.md §5, enterprise.md §10). Core owns it; `enterprise/` implements it
 * and imports it with `import type` only (enterprise.md §12). Everything a plugin may do goes
 * through the context: it gets no Fastify instance, no configuration and no secret key.
 */
import type { FastifyBaseLogger, FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify';
import type { AuditEventRecord } from '../audit/chain';
import type { AuditFilter } from '../audit/query';
import type { AuditActorContext, AuditEventInput } from '../audit/recorder';
import type { AuditSettingsInput, AuditSettingsView } from '../audit/settings';
import type { AuditHead, AuditVerification } from '../audit/verify';
import type { OrganizationAccess } from '../auth/access';
import type { OrganizationPermission, ProjectPermission } from '../auth/policy';
import type { UserPrincipal } from '../auth/principal';
import type { Db } from '../db/client';
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

/** enterprise.md §10.4: a navigation entry under Settings, shown while its feature is active. */
export interface UiExtension {
  point: 'settings.nav';
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
  enqueue(queue: string, payload: unknown): Promise<string>;
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

export interface PluginReport {
  name: string;
  state: 'loaded' | 'failed';
  features: string[];
  error: string | null;
}
