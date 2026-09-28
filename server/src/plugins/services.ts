import type { FastifyBaseLogger, FastifyRequest } from 'fastify';
import { exportAuditLines, queryAuditEvents } from '../audit/query';
import { actorOf, type AuditRecorder } from '../audit/recorder';
import {
  auditSeqString,
  auditSettingsView,
  regenerateStreamSecret,
  updateAuditSettings,
} from '../audit/settings';
import { streamAuditEvents, testAuditStream, type StreamDeps } from '../audit/stream';
import { auditHead, verifyAuditChain } from '../audit/verify';
import {
  requireOrganizationAccess,
  requireUser,
  requireInstanceAdmin,
  type AccessContext,
  type AccessScope,
} from '../auth/access';
import type { Config } from '../config';
import type { Db } from '../db/client';
import { ProblemError, validationFailed } from '../http/problem';
import type { Edition } from '../license/edition';
import { projectForUser } from '../projects/access';
import { createScimService, createSsoService } from '../sso/service';
import type { PluginAccess, PluginAudit, PluginScim, PluginSso } from './contract';
import { MISSING_SCIM, MISSING_SSO, PluginError } from './registry';

/** rbac-audit.md §15, sso-scim.md §17.1: what core passes to a plugin's context, besides 4B's. */
export interface PluginServices {
  readonly access: PluginAccess;
  readonly audit: PluginAudit;
  readonly sso: PluginSso;
  readonly scim: PluginScim;
}

/**
 * What the sso and scim services need, all three or none: without them (a script or a test that
 * builds only the 4C services) `sso` and `scim` are the stand-ins that throw.
 */
type SsoServiceInputs =
  | {
      /** publicUrl, ssoInternalHosts, sessionTtlHours, forcePasswordSignIn, secretKey. */
      config: Config;
      /** A getter: bootEnterprise creates the edition after the services. */
      edition: () => Edition;
      /** The flows' and SCIM's logger (fixed fields only; never a token, claim or assertion). */
      logger: FastifyBaseLogger;
    }
  | { config?: undefined; edition?: undefined; logger?: undefined };

const SCOPES: readonly AccessScope[] = ['read', 'write', 'admin'];
const PROBLEM_CODE = /^[A-Z][A-Z0-9_]{0,63}$/;

/** A seq of the verify range: a decimal string within MAX_SAFE_INTEGER, else 422 on the query. */
function seqOf(value: string | undefined, name: 'fromSeq' | 'toSeq'): number | undefined {
  if (value === undefined) return undefined;
  const parsed = auditSeqString.safeParse(value);
  if (!parsed.success) {
    throw validationFailed([{ path: `query.${name}`, message: 'Use a sequence number' }]);
  }
  return Number(parsed.data);
}

function problemOf(status: number, code: string, title: string, detail?: string): ProblemError {
  if (!Number.isInteger(status) || status < 400 || status > 599) {
    throw new PluginError(`a problem's status is 400 to 599, not ${String(status)}`);
  }
  if (typeof code !== 'string' || !PROBLEM_CODE.test(code)) {
    throw new PluginError('a problem code is UPPER_SNAKE_CASE');
  }
  if (typeof title !== 'string' || title.trim() === '') {
    throw new PluginError('a problem has a title');
  }
  if (detail !== undefined && typeof detail !== 'string') {
    throw new PluginError("a problem's detail is a string");
  }
  return new ProblemError(status, code, title, detail === undefined ? {} : { detail });
}

/**
 * rbac-audit.md §15: the plugin's access and audit services, built from the same core functions
 * core routes call. They check nothing about the caller: the plugin's route checks it first
 * through `access`. Every settings change is recorded through `recorder`, the one the app records
 * with, so no change made through a plugin goes unrecorded. Everything is frozen; the plugin
 * reaches the database only through these functions (and the 4B `ctx.db`). The grant routes are
 * core routes since 5B (§16), so there is no rbac service.
 */
export function createPluginServices(
  deps: {
    db: Db;
    isFeatureActive: (feature: string) => boolean;
    secretKey: string;
    version: string;
    recorder: AuditRecorder;
    now?: () => Date;
    /** Stream warnings (events that aged out unsent), never a URL, body or secret. */
    log?: { warn: (message: string) => void };
  } & SsoServiceInputs,
): PluginServices {
  const { db, recorder } = deps;
  const accessContext = (): AccessContext => ({ db });
  const settingsDeps = { secretKey: deps.secretKey, recorder };
  const streamDeps = (): StreamDeps => ({
    db,
    secretKey: deps.secretKey,
    version: deps.version,
    // rbac-audit.md §14.4: both, checked again here whatever the plugin registered.
    active: () => deps.isFeatureActive('audit-log') && deps.isFeatureActive('audit-log.stream'),
    ...(deps.now ? { now: deps.now } : {}),
    ...(deps.log ? { log: deps.log } : {}),
  });

  /** rbac-audit.md §14.4: the route guard's own answer, naming the feature. */
  const requireStream = (): void => {
    if (!streamDeps().active()) {
      throw problemOf(
        403,
        'FEATURE_NOT_LICENSED',
        'The enterprise feature "audit-log.stream" is not licensed',
      );
    }
  };

  const access: PluginAccess = Object.freeze({
    requireUser: (request: FastifyRequest, scope: AccessScope = 'read') => {
      if (!SCOPES.includes(scope)) throw new PluginError(`unknown scope ${String(scope)}`);
      return requireUser(request, scope);
    },
    requireInstanceAdmin: (request: FastifyRequest) => requireInstanceAdmin(request),
    requireOrganizationAccess: (request, organizationId, permission) =>
      requireOrganizationAccess(accessContext(), requireUser(request), organizationId, permission),
    projectForUser: async (request, projectId, permission) => {
      const p = await projectForUser(accessContext(), requireUser(request), projectId, permission);
      return { id: p.id, key: p.key, organizationId: p.organizationId };
    },
    actor: (request) => actorOf(request),
    problem: problemOf,
  } satisfies PluginAccess);

  const audit: PluginAudit = Object.freeze({
    query: (filter, page) => queryAuditEvents(db, filter, page),
    exportLines: (filter) => exportAuditLines(db, filter),
    record: (actor, event) => recorder.record(db, actor, [event]),
    head: () => auditHead(db),
    verify: async (range) =>
      verifyAuditChain(db, {
        ...(range.fromSeq === undefined ? {} : { fromSeq: seqOf(range.fromSeq, 'fromSeq') }),
        ...(range.toSeq === undefined ? {} : { toSeq: seqOf(range.toSeq, 'toSeq') }),
      }),
    settings: () => auditSettingsView(db),
    // §14.4: a stream object, or a new secret, needs audit-log.stream; checked before anything is
    // read or written. Retention alone, and `stream: null`, need audit-log only.
    updateSettings: async (actor, input) => {
      if (input.stream) requireStream();
      return updateAuditSettings(db, settingsDeps, actor, input);
    },
    regenerateStreamSecret: async (actor) => {
      requireStream();
      return regenerateStreamSecret(db, settingsDeps, actor);
    },
    testStream: () => testAuditStream(streamDeps()),
    streamOnce: async (signal) => {
      await streamAuditEvents(streamDeps(), signal);
    },
  } satisfies PluginAudit);

  // sso-scim.md §17.1: through the one recorder, so no SSO or SCIM change goes unrecorded.
  const ssoDeps =
    deps.config === undefined
      ? null
      : { db, config: deps.config, edition: deps.edition, audit: recorder, log: deps.logger };
  const sso: PluginSso = ssoDeps ? createSsoService(ssoDeps) : MISSING_SSO;
  const scim: PluginScim = ssoDeps ? createScimService(ssoDeps) : MISSING_SCIM;

  return Object.freeze({ access, audit, sso, scim });
}
