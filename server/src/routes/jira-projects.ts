import { SEVERITIES } from '@qualor/shared';
import { eq, sql, type SQL } from 'drizzle-orm';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import type { PROJECT_JIRA_CHANGED_FIELDS } from '../audit/catalogue';
import { recordProjectEvent } from '../audit/refs';
import { accessOf, requireUser } from '../auth/access';
import { boardsMappingOf, trackerInUse } from '../boards/mapping';
import type { Executor } from '../db/client';
import { first } from '../db/rows';
import {
  jiraConnections,
  projectJiraSettings,
  projects,
  type JiraAutoSeverity,
  type JiraPriorities,
} from '../db/schema';
import {
  conflict,
  notFound,
  ProblemError,
  validationFailed,
  type FieldError,
} from '../http/problem';
import { idParams, noContent, noNul, text } from '../http/schemas';
import { JiraError, type JiraClient } from '../jira/client';
import { analyzeIssueType } from '../jira/createmeta';
import {
  connectionOf,
  jiraClientFor,
  sameAddress,
  type JiraConnectionRow,
} from '../jira/connection';
import { mappingDto, mappingOf, type JiraMappingRow } from '../jira/mapping';
import {
  backgroundCodeOf,
  CREDENTIAL_PROBLEM_CODES,
  JIRA_PROBLEM_TEXT,
  problemCodeOf,
  setConnectionProblem,
  type JiraProblemCode,
} from '../jira/problems';
import { projectForUser, type ProjectRow } from '../projects/access';
import { priorityNotLicensed } from '../vulndb/priority/feature';
import { monitoringOn } from '../vulnerabilities/targets';
import { jiraProblemSchema } from './jira';

const JIRA_ID = /^\d{1,18}$/;
const JIRA_KEY = /^[A-Z][A-Z0-9_]{0,254}$/i;
const CREDENTIAL_CODES: ReadonlySet<string> = new Set(CREDENTIAL_PROBLEM_CODES);

const jiraId = z.string().regex(JIRA_ID, { message: 'A Jira id is 1-18 digits' });
const jiraProjectRef = z.object({ id: z.string(), key: z.string(), name: z.string() });
const namedId = z.object({ id: z.string(), name: z.string() });
const severity = z.enum(['blocker', 'high', 'medium', 'low', 'info']);

const mappingSchema = z.object({
  jiraProject: jiraProjectRef,
  issueType: namedId,
  labels: z.array(z.string()),
  priorities: z.partialRecord(severity, z.string()).nullable(),
  /** Whether the issue type's create screen had the labels / priority field when saved. */
  labelsAvailable: z.boolean(),
  priorityAvailable: z.boolean(),
  autoCreate: z.object({
    minSeverity: z.enum(['critical', 'high', 'medium', 'low']).nullable(),
    exploited: z.boolean(),
    since: z.iso.datetime().nullable(),
  }),
  updatedAt: z.iso.datetime(),
});

const answerSchema = z.object({
  mapping: mappingSchema.nullable(),
  connection: z
    .object({
      deployment: z.enum(['cloud', 'data_center']),
      siteUrl: z.string(),
      problem: jiraProblemSchema.nullable(),
    })
    .nullable(),
  /** The automatic rule acts only while the instance and the project monitor vulnerabilities. */
  monitoringOn: z.boolean(),
  /** Whether `autoCreate.exploited` may be turned on (the `vuln.priority` licence). */
  exploitedAvailable: z.boolean(),
});

const putBody = z.strictObject({
  jiraProject: z.strictObject({
    id: jiraId,
    key: z.string().regex(JIRA_KEY, { message: 'Not a Jira project key' }),
    name: text(255),
  }),
  issueType: z.strictObject({ id: jiraId, name: text(255) }),
  labels: z
    .array(noNul(z.string().regex(/^\S{1,100}$/, { message: '1-100 characters, no whitespace' })))
    .max(10)
    .refine((labels) => new Set(labels).size === labels.length, { message: 'Labels must differ' })
    .meta({ description: 'At most 10 extra labels, added to `qualor` and the link label' }),
  priorities: z
    .strictObject({
      blocker: jiraId.optional(),
      high: jiraId.optional(),
      medium: jiraId.optional(),
      low: jiraId.optional(),
      info: jiraId.optional(),
    })
    .nullable()
    .meta({
      description:
        "Jira priority ids (from the issue type's `allowedValues`) by issue severity; null sets none",
    }),
  autoCreate: z.strictObject({
    minSeverity: z.enum(['critical', 'high', 'medium', 'low']).nullable(),
    exploited: z.boolean().meta({
      description: 'Turning it on needs the `vuln.priority` licence (403 FEATURE_NOT_LICENSED)',
    }),
  }),
});

const projectItems = z.object({ items: z.array(jiraProjectRef) });
const issueTypeItems = z.object({
  items: z.array(
    z.object({
      id: z.string(),
      name: z.string(),
      supported: z.boolean(),
      /** The names of the required fields Qualor cannot fill. */
      missingFields: z.array(z.string()),
      labels: z.boolean(),
      priority: z
        .object({
          allowed: z.array(namedId),
          /** True when a create must set the priority: the mapping then needs one per severity. */
          required: z.boolean(),
        })
        .nullable(),
    }),
  ),
});

/** The priorities as stored: null when none is set. */
function normalPriorities(input: JiraPriorities | null): JiraPriorities | null {
  if (input === null) return null;
  const set = SEVERITIES.filter((s) => input[s] !== undefined);
  return set.length === 0 ? null : Object.fromEntries(set.map((s) => [s, input[s]]));
}

const prioritiesKey = (p: JiraPriorities | null): string =>
  JSON.stringify(SEVERITIES.map((s) => p?.[s] ?? null));

/** The names, among those of PROJECT_JIRA_CHANGED_FIELDS, of what the save changes (R11). */
function changedFields(
  before: JiraMappingRow | null,
  next: {
    jiraProject: { id: string; key: string; name: string };
    issueType: { id: string; name: string };
    labels: string[];
    priorities: JiraPriorities | null;
    minSeverity: JiraAutoSeverity | null;
    exploited: boolean;
  },
): (typeof PROJECT_JIRA_CHANGED_FIELDS)[number][] {
  if (before === null) return ['mapping'];
  const changed: (typeof PROJECT_JIRA_CHANGED_FIELDS)[number][] = [];
  if (
    before.jiraProjectId !== next.jiraProject.id ||
    before.jiraProjectKey !== next.jiraProject.key ||
    before.jiraProjectName !== next.jiraProject.name
  ) {
    changed.push('jiraProject');
  }
  if (before.issueTypeId !== next.issueType.id || before.issueTypeName !== next.issueType.name) {
    changed.push('issueType');
  }
  if (before.labels.join('\n') !== next.labels.join('\n')) changed.push('labels');
  if (prioritiesKey(before.priorities) !== prioritiesKey(next.priorities)) {
    changed.push('priorities');
  }
  if (before.autoMinSeverity !== next.minSeverity || before.autoExploited !== next.exploited) {
    changed.push('autoCreate');
  }
  return changed;
}

/** The 422 errors of priorities the issue type does not offer: none when none is set. */
function priorityErrors(
  priorities: JiraPriorities | null,
  field: { allowed: { id: string }[] } | null,
): FieldError[] {
  if (priorities === null || SEVERITIES.every((s) => priorities[s] === undefined)) return [];
  if (field === null) {
    return [{ path: 'body.priorities', message: 'The issue type has no priority field' }];
  }
  const allowed = new Set(field.allowed.map((p) => p.id));
  return SEVERITIES.flatMap((s) => {
    const id = priorities[s];
    if (id === undefined || allowed.has(id)) return [];
    return [{ path: `body.priorities.${s}`, message: 'Not a priority the type offers' }];
  });
}

/** spec §6.6: the rule's `since`, now whenever the rule changes, else kept; null while it is off. */
function autoSinceOf(
  rule: { minSeverity: JiraAutoSeverity | null; exploited: boolean },
  before: JiraMappingRow | null,
): SQL | Date | null {
  if (rule.minSeverity === null && !rule.exploited) return null;
  const changed =
    before === null ||
    before.autoMinSeverity !== rule.minSeverity ||
    before.autoExploited !== rule.exploited;
  return changed ? sql`now()` : (before?.autoSince ?? null);
}

/**
 * The connection's row, shared until the transaction ends, once it is known to keep the address
 * that the Jira answers were read from: 409 when it is gone, 503 (retry) when it moved, since the
 * answers would be the old site's.
 */
async function lockUnmoved(tx: Executor, row: JiraConnectionRow): Promise<void> {
  const [current] = await tx
    .select()
    .from(jiraConnections)
    .where(eq(jiraConnections.id, row.id))
    .for('share');
  if (!current) throw conflict('JIRA_NOT_CONNECTED', 'The organisation has no Jira connection');
  if (!sameAddress(current, row)) {
    throw new ProblemError(
      503,
      'CONCURRENCY_CONFLICT',
      'The request conflicted with a concurrent change; retry it',
      { headers: { 'retry-after': '1' } },
    );
  }
}

/**
 * spec §6.2, §6.8: a project's Jira mapping: the picker, the issue types and the automatic rule
 * (project admins, `project.settings`). Jira's own words never reach the answer: a failed call is
 * 502 JIRA_UNAVAILABLE with the fixed text of its problem code.
 */
export const jiraProjectRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (
  app,
  { deps },
) => {
  const jiraDeps = {
    secretKey: deps.config.secretKey,
    internalHosts: deps.config.jiraInternalHosts,
  };

  /** The 502 for a failed Jira call; a credential failure is also recorded on the connection. */
  const unavailable = async (
    row: JiraConnectionRow,
    code: JiraProblemCode,
    background: string | null,
  ): Promise<never> => {
    if (background !== null && CREDENTIAL_CODES.has(background)) {
      await setConnectionProblem(
        deps.db,
        row.id,
        background as Parameters<typeof setConnectionProblem>[2],
      );
    }
    throw new ProblemError(502, 'JIRA_UNAVAILABLE', 'Jira could not be asked', {
      detail: JIRA_PROBLEM_TEXT[code],
    });
  };

  /** The organisation's connection and a client for it: 409 without one, 502 when it is unusable. */
  const clientOf = async (
    project: ProjectRow,
  ): Promise<{ row: JiraConnectionRow; client: JiraClient }> => {
    const row = await connectionOf(deps.db, project.organizationId);
    if (!row) throw conflict('JIRA_NOT_CONNECTED', 'The organisation has no Jira connection');
    const found = jiraClientFor(row, jiraDeps);
    if ('problem' in found) return unavailable(row, found.problem, found.problem);
    return { row, client: found.client };
  };

  const asked = async <T>(row: JiraConnectionRow, call: () => Promise<T>): Promise<T> => {
    try {
      return await call();
    } catch (err) {
      if (err instanceof JiraError)
        return unavailable(row, problemCodeOf(err), backgroundCodeOf(err));
      throw err;
    }
  };

  const answer = async (db: Executor, project: ProjectRow) => {
    const [mapping, connection, monitoring] = await Promise.all([
      mappingOf(db, project.id),
      connectionOf(db, project.organizationId),
      monitoringOn(db, project.id),
    ]);
    return {
      mapping: mapping === null ? null : mappingDto(mapping),
      connection:
        connection === null
          ? null
          : {
              deployment: connection.deployment,
              siteUrl: connection.siteUrl,
              problem: connection.problem
                ? {
                    code: connection.problem.code as z.infer<typeof jiraProblemSchema>['code'],
                    message: connection.problem.message,
                    at: new Date(connection.problem.at).toISOString(),
                  }
                : null,
            },
      monitoringOn: monitoring,
      exploitedAvailable: deps.edition.limits().vulnerabilities.priority,
    };
  };

  app.get(
    '/projects/:id/jira',
    {
      schema: {
        tags: ['jira'],
        summary:
          "The project's Jira mapping or null, the organisation's connection (deployment, address, background problem) or null, whether vulnerability monitoring is on, and whether `exploited` of the automatic rule is licensed",
        params: idParams,
        response: { 200: answerSchema },
      },
    },
    async (request) => {
      const project = await projectForUser(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'project.read',
      );
      return answer(deps.db, project);
    },
  );

  app.get(
    '/projects/:id/jira/projects',
    {
      config: {
        openapi: {
          problems: [409, 502],
          problemDescriptions: {
            409: 'JIRA_NOT_CONNECTED: the organisation has no Jira connection',
            502: "JIRA_UNAVAILABLE: the Jira call failed; `detail` is the fixed text of its problem code, never Jira's own words",
          },
        },
      },
      schema: {
        tags: ['jira'],
        summary:
          'The picker (project admins): at most 50 Jira projects the connection can see whose key or name contains `query`',
        params: idParams,
        querystring: z.strictObject({ query: noNul(z.string().max(100)).default('') }),
        response: { 200: projectItems },
      },
    },
    async (request) => {
      const project = await projectForUser(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'project.settings',
      );
      const { row, client } = await clientOf(project);
      const items = await asked(row, () => client.searchProjects(request.query.query));
      return { items };
    },
  );

  app.get(
    '/projects/:id/jira/issue-types',
    {
      config: {
        openapi: {
          problems: [409, 502],
          problemDescriptions: {
            409: 'JIRA_NOT_CONNECTED: the organisation has no Jira connection',
            502: "JIRA_UNAVAILABLE: the Jira call failed; `detail` is the fixed text of its problem code, never Jira's own words",
          },
        },
      },
      schema: {
        tags: ['jira'],
        summary:
          'The issue types of a Jira project (project admins), sub-tasks left out, each with whether Qualor can create it, the names of the required fields it cannot fill, and its labels and priority fields. A required priority without default counts as settable: the mapping then needs a priority for every severity',
        params: idParams,
        querystring: z.strictObject({
          jiraProject: z.string().regex(JIRA_KEY, { message: 'Not a Jira project key' }),
        }),
        response: { 200: issueTypeItems },
      },
    },
    async (request) => {
      const project = await projectForUser(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'project.settings',
      );
      const { row, client } = await clientOf(project);
      const key = request.query.jiraProject;
      const types = await asked(row, () => client.issueTypes(key));
      const items = [];
      for (const type of types) {
        const fields = await asked(row, () => client.issueTypeFields(key, type.id));
        items.push({ id: type.id, name: type.name, ...analyzeIssueType(fields, 'any') });
      }
      return { items };
    },
  );

  app.put(
    '/projects/:id/jira',
    {
      config: {
        openapi: {
          problems: [403, 409, 502],
          problemDescriptions: {
            403: 'FEATURE_NOT_LICENSED: `autoCreate.exploited` is turned on without the `vuln.priority` licence',
            409: 'JIRA_NOT_CONNECTED: the organisation has no Jira connection; TRACKER_IN_USE: the project has an Azure Boards mapping (a project uses one tracker)',
            502: "JIRA_UNAVAILABLE: the Jira call failed; `detail` is the fixed text of its problem code, never Jira's own words",
          },
        },
      },
      schema: {
        tags: ['jira'],
        summary:
          "Create or replace the project's Jira mapping (project admins). The issue type is checked against Jira's create screen: 422 JIRA_ISSUE_TYPE_UNSUPPORTED (with `missingFields`) when it needs fields Qualor cannot fill, 422 on `body.issueType.id` for an unknown or sub-task type, 422 on `body.priorities.<severity>` for a priority the type does not offer. Whether the screen has labels and priority is stored. `autoCreate.since` is set whenever the rule changes and cleared when it goes off",
        params: idParams,
        body: putBody,
        response: { 200: answerSchema },
      },
    },
    async (request) => {
      const project = await projectForUser(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'project.settings',
      );
      const { body } = request;
      const priorities = normalPriorities(body.priorities);
      const { row, client } = await clientOf(project);
      // Azure DevOps design §7.8: a project uses one tracker.
      if ((await boardsMappingOf(deps.db, project.id)) !== null) throw trackerInUse('boards');
      const key = body.jiraProject.key;
      const types = await asked(row, () => client.issueTypes(key));
      const type = types.find((t) => t.id === body.issueType.id);
      if (!type) {
        throw validationFailed([
          {
            path: 'body.issueType.id',
            message: 'Not an issue type of that Jira project (sub-tasks are not offered)',
          },
        ]);
      }
      const fields = await asked(row, () => client.issueTypeFields(key, type.id));
      const complete = SEVERITIES.every((s) => priorities?.[s] !== undefined);
      const support = analyzeIssueType(fields, complete);
      if (!support.supported) {
        throw new ProblemError(
          422,
          'JIRA_ISSUE_TYPE_UNSUPPORTED',
          'Qualor cannot create issues of this type',
          {
            detail: `The type has required fields Qualor cannot fill: ${support.missingFields.join(', ')}`,
            extensions: { missingFields: support.missingFields },
          },
        );
      }
      const errors = priorityErrors(priorities, support.priority);
      if (errors.length > 0) throw validationFailed(errors);
      const { minSeverity, exploited } = body.autoCreate;
      await deps.db.transaction(async (tx) => {
        await tx
          .select({ id: projects.id })
          .from(projects)
          .where(eq(projects.id, project.id))
          .for('no key update');
        await lockUnmoved(tx, row);
        // Under the project's row lock, which the Boards PUT takes too.
        if ((await boardsMappingOf(tx, project.id)) !== null) throw trackerInUse('boards');
        const before = await mappingOf(tx, project.id);
        // R10: only turning it on needs the licence; a stored true is kept as it is.
        if (
          exploited &&
          before?.autoExploited !== true &&
          !deps.edition.limits().vulnerabilities.priority
        ) {
          throw priorityNotLicensed();
        }
        const values = {
          connectionId: row.id,
          jiraProjectId: body.jiraProject.id,
          jiraProjectKey: body.jiraProject.key,
          jiraProjectName: body.jiraProject.name,
          issueTypeId: type.id,
          issueTypeName: type.name,
          labels: body.labels,
          priorities,
          labelsAvailable: support.labels,
          priorityAvailable: support.priority !== null,
          autoMinSeverity: minSeverity,
          autoExploited: exploited,
          autoSince: autoSinceOf(body.autoCreate, before),
          updatedAt: sql`now()`,
        };
        first(
          await tx
            .insert(projectJiraSettings)
            .values({ projectId: project.id, ...values })
            .onConflictDoUpdate({ target: projectJiraSettings.projectId, set: values })
            .returning({ projectId: projectJiraSettings.projectId }),
        );
        const changed = changedFields(before, {
          jiraProject: body.jiraProject,
          issueType: { id: type.id, name: type.name },
          labels: body.labels,
          priorities,
          minSeverity,
          exploited,
        });
        if (changed.length > 0) {
          await recordProjectEvent(deps.audit, tx, request, project, 'project.jira_updated', {
            changed,
          });
        }
      });
      return answer(deps.db, project);
    },
  );

  app.delete(
    '/projects/:id/jira',
    {
      schema: {
        tags: ['jira'],
        summary:
          "Remove the project's Jira mapping (project admins); its links stay and keep syncing, nothing new is created. 404 without a mapping",
        params: idParams,
        response: { 204: noContent },
      },
    },
    async (request, reply) => {
      const project = await projectForUser(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'project.settings',
      );
      await deps.db.transaction(async (tx) => {
        const removed = await tx
          .delete(projectJiraSettings)
          .where(eq(projectJiraSettings.projectId, project.id))
          .returning({ projectId: projectJiraSettings.projectId });
        if (removed.length === 0) throw notFound('Jira mapping');
        await recordProjectEvent(deps.audit, tx, request, project, 'project.jira_updated', {
          changed: ['mapping'],
        });
      });
      return reply.code(204).send();
    },
  );
};
