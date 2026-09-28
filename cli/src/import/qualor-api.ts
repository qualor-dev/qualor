import {
  SEVERITIES,
  STATUS_IMPORT_OUTCOMES,
  type PlannedRow,
  type StatusImportRequestItem,
  type StatusImportResult,
} from '@qualor/shared';
import { z } from 'zod';
import { CliError, EXIT } from '../errors';
import {
  describeFailure,
  parseJson,
  parseProblem,
  pathSegment,
  request,
  retryAfterMs,
  type HttpResponse,
  type RequestOptions,
  type ServerEndpoint,
} from '../server/http';

export type UnknownRules = 'activate' | 'ignore';

export interface QualorProfile {
  id: string;
  name: string;
  language: string;
  isBuiltin: boolean;
  isDefault: boolean;
  unknownRules: UnknownRules;
  /** The profile it inherits from, or `null`: its inherited rows are not its own (spec §13). */
  parentId: string | null;
}
export interface QualorCondition {
  id: string;
  metric: string;
  operator: 'gt' | 'lt';
  threshold: number;
}
export interface QualorGate {
  id: string;
  name: string;
  isBuiltin: boolean;
  isDefault: boolean;
  conditions: QualorCondition[];
}
export interface QualorProject {
  id: string;
  organizationId: string;
  key: string;
  qualityGateId: string | null;
}
export interface Membership {
  organizationId: string;
  organizationKey: string;
  /** Null where the user sees the organisation only through a project grant (rbac-audit.md §16). */
  role: 'admin' | 'project_admin' | 'member' | 'viewer' | null;
}
/** `competitors`: the `open` items the server counted (spec §11.2). */
export type StatusImportAnswer =
  | { kind: 'ok'; results: StatusImportResult[]; competitors: number }
  | { kind: 'not_analysed' }
  | { kind: 'too_large' };
export type NewCondition = Omit<QualorCondition, 'id'>;

/**
 * Qualor's REST API as the import uses it (import-sonarqube.md §11.1). Every path segment built
 * from an id, a rule key or a language goes through `pathSegment`.
 */
export interface QualorApi {
  me(): Promise<{ isInstanceAdmin: boolean; memberships: Membership[] }>;
  organizations(): Promise<{ id: string; key: string }[]>;
  profiles(orgId: string): Promise<QualorProfile[]>;
  createProfile(orgId: string, name: string, language: string): Promise<QualorProfile>;
  /** `PATCH /quality-profiles/{id}` `{ unknownRules }` (the import always sets `activate`). */
  setProfileUnknownRules(profileId: string, unknownRules: UnknownRules): Promise<void>;
  /** The profile's own rows (`source: profile`), not inherited or default ones. */
  profileRows(profileId: string): Promise<PlannedRow[]>;
  setProfileRule(profileId: string, row: PlannedRow): Promise<void>;
  deleteProfileRule(profileId: string, ruleKey: string): Promise<void>;
  setDefaultProfile(profileId: string): Promise<void>;
  gates(orgId: string): Promise<QualorGate[]>;
  createGate(orgId: string, name: string): Promise<QualorGate>;
  addCondition(gateId: string, c: NewCondition): Promise<void>;
  updateCondition(gateId: string, condId: string, c: NewCondition): Promise<void>;
  deleteCondition(gateId: string, condId: string): Promise<void>;
  setDefaultGate(gateId: string): Promise<void>;
  projectByKey(key: string): Promise<QualorProject | null>;
  createProject(
    orgId: string,
    key: string,
    name: string,
    mainBranchName: string,
  ): Promise<QualorProject>;
  projectProfiles(
    projectId: string,
  ): Promise<{ language: string; profileId: string | null; source: 'project' | 'default' }[]>;
  setProjectProfile(projectId: string, language: string, profileId: string): Promise<void>;
  setProjectGate(projectId: string, gateId: string): Promise<void>;
  importStatuses(
    projectId: string,
    items: readonly StatusImportRequestItem[],
    dryRun: boolean,
  ): Promise<StatusImportAnswer>;
}

export class QualorApiError extends CliError {
  override name = 'QualorApiError';
  constructor(
    readonly status: number,
    readonly code: string | null,
    message: string,
  ) {
    super(EXIT.SERVER, message);
  }
}

const id = z.uuid();
const profileSchema = z.looseObject({
  id,
  name: z.string(),
  language: z.string(),
  isBuiltin: z.boolean(),
  isDefault: z.boolean(),
  unknownRules: z.enum(['activate', 'ignore']),
  parentId: id.nullable(),
});
const gateSchema = z.looseObject({
  id,
  name: z.string(),
  isBuiltin: z.boolean(),
  isDefault: z.boolean(),
  conditions: z.array(
    z.looseObject({
      id,
      metric: z.string(),
      operator: z.enum(['gt', 'lt']),
      threshold: z.number(),
    }),
  ),
});
const projectSchema = z.looseObject({
  id,
  organizationId: id,
  key: z.string(),
  qualityGateId: id.nullable(),
});
const page = <T>(item: z.ZodType<T>) =>
  z.looseObject({ items: z.array(item), nextCursor: z.string().min(1).nullable() });
const MAX_ANSWER_BYTES = 8 * 1024 * 1024;
/** Pages of a list read before giving up (500 items each): a server that never ends a list. */
const MAX_PAGES = 1000;
const MAX_CONFLICT_RETRIES = 3;
const sleeper = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

export function httpQualorApi(
  ep: ServerEndpoint,
  sleep: (ms: number) => Promise<void> = sleeper,
): QualorApi {
  /** One request; retries a 503 `CONCURRENCY_CONFLICT` (the server's lock was busy). */
  async function send(o: RequestOptions): Promise<HttpResponse> {
    for (let attempt = 0; ; attempt += 1) {
      const res = await request(ep, { maxResponseBytes: MAX_ANSWER_BYTES, ...o });
      if (res.status >= 200 && res.status < 300) return res;
      const problem = parseProblem(res.body);
      if (
        res.status === 503 &&
        problem?.code === 'CONCURRENCY_CONFLICT' &&
        attempt < MAX_CONFLICT_RETRIES
      ) {
        await sleep(retryAfterMs(res.headers, 1000, 30_000) ?? 2000);
        continue;
      }
      // A 403 of any kind, PASSWORD_CHANGE_REQUIRED included, stops the whole import: no later
      // request of this user can succeed either.
      if (res.status === 401 || res.status === 403) {
        throw new CliError(
          EXIT.AUTH,
          `Qualor refused ${o.method} /${o.path}: ${describeFailure(res)}`,
        );
      }
      throw new QualorApiError(
        res.status,
        problem?.code ?? null,
        `Qualor answered ${describeFailure(res)} to ${o.method} /${o.path}`,
      );
    }
  }
  async function call<T>(o: RequestOptions, schema: z.ZodType<T>, what: string): Promise<T> {
    return parseJson(await send(o), schema, what);
  }
  async function write(o: RequestOptions): Promise<void> {
    await send(o);
  }
  async function all<T>(
    path: string,
    query: Record<string, string>,
    item: z.ZodType<T>,
    what: string,
  ): Promise<T[]> {
    const out: T[] = [];
    let cursor: string | null = null;
    for (let n = 0; n < MAX_PAGES; n += 1) {
      const p: { items: T[]; nextCursor: string | null } = await call(
        {
          method: 'GET',
          path,
          query: { ...query, limit: '500', ...(cursor !== null && { cursor }) },
        },
        page(item),
        what,
      );
      out.push(...p.items);
      if (p.nextCursor === null) return out;
      cursor = p.nextCursor;
    }
    throw new CliError(EXIT.SERVER, `the server sent an invalid ${what} (it never ends)`);
  }
  const profilePath = (profileId: string) => `api/v0/quality-profiles/${pathSegment(profileId)}`;
  const rulePath = (profileId: string, ruleKey: string) =>
    `${profilePath(profileId)}/rules/${pathSegment(ruleKey)}`;
  const gatePath = (gateId: string) => `api/v0/quality-gates/${pathSegment(gateId)}`;
  const conditionPath = (gateId: string, condId: string) =>
    `${gatePath(gateId)}/conditions/${pathSegment(condId)}`;
  const projectPath = (projectId: string) => `api/v0/projects/${pathSegment(projectId)}`;

  return {
    me: async () => {
      const m = await call(
        { method: 'GET', path: 'api/v0/auth/me' },
        z.looseObject({
          user: z.looseObject({ isInstanceAdmin: z.boolean() }),
          memberships: z.array(
            z.looseObject({
              organizationId: id,
              organizationKey: z.string(),
              role: z.enum(['admin', 'project_admin', 'member', 'viewer']).nullable(),
            }),
          ),
        }),
        'current user',
      );
      return {
        isInstanceAdmin: m.user.isInstanceAdmin,
        memberships: m.memberships.map((x) => ({
          organizationId: x.organizationId,
          organizationKey: x.organizationKey,
          role: x.role,
        })),
      };
    },
    organizations: async () =>
      (
        await all(
          'api/v0/organizations',
          {},
          z.looseObject({ id, key: z.string() }),
          'organisation list',
        )
      ).map((o) => ({ id: o.id, key: o.key })),
    profiles: (orgId) =>
      all('api/v0/quality-profiles', { organizationId: orgId }, profileSchema, 'profile list'),
    createProfile: (orgId, name, language) =>
      call(
        {
          method: 'POST',
          path: 'api/v0/quality-profiles',
          json: { organizationId: orgId, name, language },
        },
        profileSchema,
        'profile',
      ),
    setProfileUnknownRules: async (profileId, unknownRules) =>
      write({ method: 'PATCH', path: profilePath(profileId), json: { unknownRules } }),
    profileRows: async (profileId) =>
      (
        await all(
          `${profilePath(profileId)}/rules`,
          { scope: 'all' },
          z.looseObject({
            rule: z.looseObject({ key: z.string() }),
            active: z.boolean(),
            severityOverride: z.enum(SEVERITIES).nullable(),
            source: z.enum(['profile', 'inherited', 'default']),
          }),
          'profile rule list',
        )
      )
        .filter((r) => r.source === 'profile')
        .map((r) => ({
          ruleKey: r.rule.key,
          active: r.active,
          severityOverride: r.severityOverride,
        })),
    setProfileRule: async (profileId, row) =>
      write({
        method: 'PUT',
        path: rulePath(profileId, row.ruleKey),
        json: { active: row.active, severityOverride: row.severityOverride },
      }),
    deleteProfileRule: async (profileId, ruleKey) =>
      write({ method: 'DELETE', path: rulePath(profileId, ruleKey) }),
    setDefaultProfile: async (profileId) =>
      write({ method: 'POST', path: `${profilePath(profileId)}/set-default`, json: {} }),
    gates: (orgId) =>
      all('api/v0/quality-gates', { organizationId: orgId }, gateSchema, 'gate list'),
    createGate: (orgId, name) =>
      call(
        { method: 'POST', path: 'api/v0/quality-gates', json: { organizationId: orgId, name } },
        gateSchema,
        'gate',
      ),
    addCondition: async (gateId, c) =>
      write({
        method: 'POST',
        path: `${gatePath(gateId)}/conditions`,
        json: { metric: c.metric, operator: c.operator, threshold: c.threshold },
      }),
    updateCondition: async (gateId, condId, c) =>
      write({
        method: 'PATCH',
        path: conditionPath(gateId, condId),
        json: { metric: c.metric, operator: c.operator, threshold: c.threshold },
      }),
    deleteCondition: async (gateId, condId) =>
      write({ method: 'DELETE', path: conditionPath(gateId, condId) }),
    setDefaultGate: async (gateId) =>
      write({ method: 'POST', path: `${gatePath(gateId)}/set-default`, json: {} }),
    projectByKey: async (key) => {
      try {
        return await call(
          { method: 'GET', path: 'api/v0/projects/by-key', query: { key } },
          projectSchema,
          'project',
        );
      } catch (err) {
        if (err instanceof QualorApiError && err.status === 404) return null;
        throw err;
      }
    },
    createProject: (orgId, key, name, mainBranchName) =>
      call(
        {
          method: 'POST',
          path: 'api/v0/projects',
          json: { organizationId: orgId, key, name, mainBranchName },
        },
        projectSchema,
        'project',
      ),
    projectProfiles: async (projectId) =>
      (
        await call(
          { method: 'GET', path: `${projectPath(projectId)}/quality-profiles` },
          z.array(
            z.looseObject({
              language: z.string(),
              profile: z.looseObject({ id }).nullable(),
              source: z.enum(['project', 'default']),
            }),
          ),
          'project profile list',
        )
      ).map((r) => ({ language: r.language, profileId: r.profile?.id ?? null, source: r.source })),
    setProjectProfile: async (projectId, language, profileId) =>
      write({
        method: 'PUT',
        path: `${projectPath(projectId)}/quality-profiles/${pathSegment(language)}`,
        json: { profileId },
      }),
    setProjectGate: async (projectId, gateId) =>
      write({ method: 'PATCH', path: projectPath(projectId), json: { qualityGateId: gateId } }),
    importStatuses: async (projectId, items, dryRun) => {
      try {
        const r = await call(
          {
            method: 'POST',
            path: `${projectPath(projectId)}/issue-status-import`,
            json: { dryRun, items },
          },
          z.looseObject({
            results: z.array(
              z.looseObject({
                ref: z.string(),
                outcome: z.enum(STATUS_IMPORT_OUTCOMES),
                issueId: id.nullable(),
                status: z.string().nullable(),
              }),
            ),
            competitors: z.number().int().min(0),
          }),
          'status import',
        );
        return {
          kind: 'ok',
          results: r.results.map((x) => ({
            ref: x.ref,
            outcome: x.outcome,
            issueId: x.issueId,
            status: x.status,
          })),
          competitors: r.competitors,
        };
      } catch (err) {
        if (err instanceof QualorApiError && err.code === 'PROJECT_NOT_ANALYSED') {
          return { kind: 'not_analysed' };
        }
        // IMPORT_TOO_LARGE (too many candidates), BODY_TOO_LARGE, or a proxy's own 413: split.
        if (err instanceof QualorApiError && err.status === 413) return { kind: 'too_large' };
        throw err;
      }
    },
  };
}
