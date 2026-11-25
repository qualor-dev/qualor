import { and, asc, eq, sql, type SQL } from 'drizzle-orm';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import type { PROJECT_BOARDS_CHANGED_FIELDS } from '../audit/catalogue';
import { recordProjectEvent } from '../audit/refs';
import { accessOf, requireUser } from '../auth/access';
import { syncBoardsNow } from '../boards/jobs';
import {
  analyzeWorkItemType,
  AZURE_WORDS_MAX,
  boardsMappingDto,
  boardsMappingOf,
  mappingCheckOps,
  MAX_BOARDS_TAGS,
  QUALOR_TAG,
  trackerInUse,
  type BoardsMappingRow,
} from '../boards/mapping';
import type { Executor } from '../db/client';
import { first } from '../db/rows';
import {
  projectBoardsSettings,
  projectJiraSettings,
  projects,
  scmConnections,
  type JiraAutoSeverity,
} from '../db/schema';
import { conflict, notFound, ProblemError } from '../http/problem';
import { idParams, noContent, noNul, text } from '../http/schemas';
import { cutText } from '../jira/markup';
import { projectForUser, type ProjectRow } from '../projects/access';
import { AzureError, type AzureDevOpsClient, type AzureWorkItemType } from '../scm/azure/client';
import { azureClientFor, clientProblemCode, problemCode } from '../scm/azure/connections';
import { AZURE_REPOSITORY_ID } from '../scm/azure/url';
import {
  scmDepsOf,
  TEST_PROBLEM_CODES,
  type ScmConnectionRow,
  type TestProblemCode,
} from '../scm/connections';
import { ScmError } from '../scm/provider';
import { priorityNotLicensed } from '../vulndb/priority/feature';
import { monitoringOn } from '../vulnerabilities/targets';

/** An Azure DevOps project id (a GUID) in any case; the routes use it in lower case. */
const azureProjectId = z
  .string()
  .regex(AZURE_REPOSITORY_ID, { message: 'An Azure DevOps project id is a GUID' });
/** An area or iteration path as the create takes it (`<project>\<child>`); null is the root. */
const classificationPath = text(4000).nullable();
/**
 * A tag of the mapping (design §7.8, probe item 30j): 1-100 characters, no `;` or `,` (Azure DevOps
 * splits tags on both), no control character, no space at either end (Azure DevOps trims it).
 */
const TAG = /^[^;,\s\p{Cc}](?:[^;,\p{Cc}]{0,98}[^;,\s\p{Cc}])?$/u;
const severity = z.enum(['critical', 'high', 'medium', 'low']);

const mappingSchema = z.object({
  connectionId: z.uuid(),
  azureProject: z.object({ id: z.string(), name: z.string() }),
  /** The type by its reference name, which survives a rename, and its name when saved. */
  workItemType: z.object({ referenceName: z.string(), name: z.string() }),
  /** Null: the project's root. */
  areaPath: z.string().nullable(),
  iterationPath: z.string().nullable(),
  tags: z.array(z.string()),
  autoCreate: z.object({
    minSeverity: severity.nullable(),
    exploited: z.boolean(),
    since: z.iso.datetime().nullable(),
  }),
  updatedAt: z.iso.datetime(),
});

const answerSchema = z.object({
  mapping: mappingSchema.nullable(),
  /** The organisation's Azure DevOps connections, oldest first. Never a credential. */
  connections: z.array(
    z.object({
      id: z.uuid(),
      /** The organisation (Services) or collection (Server) the base URL names. */
      name: z.string(),
      baseUrl: z.string(),
      /** The connection's recorded credential or hook problem; null when none. */
      problem: z.object({ code: z.enum(TEST_PROBLEM_CODES), at: z.iso.datetime() }).nullable(),
    }),
  ),
  /** The automatic rule acts only while the instance and the project monitor vulnerabilities. */
  monitoringOn: z.boolean(),
  /** Whether `autoCreate.exploited` may be turned on (the `vuln.priority` licence). */
  exploitedAvailable: z.boolean(),
});

const putBody = z.strictObject({
  connectionId: z
    .uuid()
    .meta({ description: "An Azure DevOps connection of the project's organisation" }),
  azureProject: z.strictObject({ id: azureProjectId, name: text(255) }),
  workItemType: z.strictObject({ referenceName: text(255) }),
  areaPath: classificationPath.meta({
    description:
      "One of the project's area paths (`GET …/boards/paths`); null is the project's root",
  }),
  iterationPath: classificationPath.meta({
    description:
      "One of the project's iteration paths (`GET …/boards/paths`); null is the project's root",
  }),
  tags: z
    .array(
      noNul(
        z.string().regex(TAG, {
          message: '1-100 characters, no ; or , no control character and no space at either end',
        }),
      ),
    )
    .max(MAX_BOARDS_TAGS)
    .refine((tags) => !tags.some((t) => t.toLowerCase() === QUALOR_TAG), {
      message: 'qualor is the tag Qualor adds itself',
    })
    .refine((tags) => new Set(tags.map((t) => t.toLowerCase())).size === tags.length, {
      message: 'Tags must differ, whatever their case',
    })
    .meta({ description: 'At most 10 tags, added to `qualor`' }),
  autoCreate: z.strictObject({
    minSeverity: severity.nullable(),
    exploited: z.boolean().meta({
      description: 'Turning it on needs the `vuln.priority` licence (403 FEATURE_NOT_LICENSED)',
    }),
  }),
});

const connectionQuery = { connection: z.uuid() };
const projectItems = z.object({ items: z.array(z.object({ id: z.string(), name: z.string() })) });
const typeItems = z.object({
  items: z.array(
    z.object({
      referenceName: z.string(),
      name: z.string(),
      supported: z.boolean(),
      /** The reference names of the always-required fields Qualor cannot fill. */
      missingFields: z.array(z.string()),
    }),
  ),
});
const pathItems = z.object({ areas: z.array(z.string()), iterations: z.array(z.string()) });

const NOT_CONNECTED =
  "BOARDS_NOT_CONNECTED: the connection is not one of the organisation's Azure DevOps connections";
const UNAVAILABLE =
  "BOARDS_UNAVAILABLE: the Azure DevOps call failed; `detail` is the fixed text of its problem (its code in `problemCode`), never Azure DevOps' own words";

const byName = (a: { name: string }, b: { name: string }) =>
  a.name.localeCompare(b.name, 'en', { sensitivity: 'base' }) || a.name.localeCompare(b.name);

/** The organisation (Services) or collection (Server) a connection's base URL names: its last segment. */
function connectionName(baseUrl: string): string {
  const url = new URL(baseUrl);
  const last = url.pathname
    .split('/')
    .filter((s) => s !== '')
    .at(-1);
  if (last === undefined) return url.host;
  try {
    return decodeURIComponent(last);
  } catch {
    return last;
  }
}

const notConnected = () =>
  conflict(
    'BOARDS_NOT_CONNECTED',
    "The connection is not one of the organisation's Azure DevOps connections",
  );

const typeUnsupported = (missingFields: string[]) =>
  new ProblemError(
    422,
    'BOARDS_WORK_ITEM_TYPE_UNSUPPORTED',
    'Qualor cannot create work items of this type',
    {
      detail:
        missingFields.length === 0
          ? 'The Azure DevOps project offers no such work item type'
          : `The type has required fields Qualor cannot fill: ${missingFields.join(', ')}`,
      extensions: { missingFields },
    },
  );

const pathUnknown = (field: 'areaPath' | 'iterationPath') => {
  const what = field === 'areaPath' ? 'area' : 'iteration';
  const message = `Not an ${what} path of the Azure DevOps project`;
  return new ProblemError(422, 'BOARDS_PATH_UNKNOWN', `Unknown ${what} path`, {
    detail: message,
    errors: [{ path: `body.${field}`, message }],
  });
};

/** The names, among those of PROJECT_BOARDS_CHANGED_FIELDS, of what the save changes. */
function changedFields(
  before: BoardsMappingRow | null,
  next: Pick<
    BoardsMappingRow,
    | 'connectionId'
    | 'azureProjectId'
    | 'azureProjectName'
    | 'workItemTypeRef'
    | 'workItemTypeName'
    | 'areaPath'
    | 'iterationPath'
    | 'tags'
    | 'autoMinSeverity'
    | 'autoExploited'
  >,
): (typeof PROJECT_BOARDS_CHANGED_FIELDS)[number][] {
  if (before === null) return ['mapping'];
  const changed: (typeof PROJECT_BOARDS_CHANGED_FIELDS)[number][] = [];
  if (before.connectionId !== next.connectionId) changed.push('connection');
  if (
    before.azureProjectId !== next.azureProjectId ||
    before.azureProjectName !== next.azureProjectName
  ) {
    changed.push('azureProject');
  }
  if (
    before.workItemTypeRef !== next.workItemTypeRef ||
    before.workItemTypeName !== next.workItemTypeName
  ) {
    changed.push('workItemType');
  }
  if (before.areaPath !== next.areaPath) changed.push('areaPath');
  if (before.iterationPath !== next.iterationPath) changed.push('iterationPath');
  if (before.tags.join('\n') !== next.tags.join('\n')) changed.push('tags');
  if (
    before.autoMinSeverity !== next.autoMinSeverity ||
    before.autoExploited !== next.autoExploited
  ) {
    changed.push('autoCreate');
  }
  return changed;
}

/** As the Jira mapping: the rule's `since`, now whenever the rule changes, else kept; null while off. */
function autoSinceOf(
  rule: { minSeverity: JiraAutoSeverity | null; exploited: boolean },
  before: BoardsMappingRow | null,
): SQL | Date | null {
  if (rule.minSeverity === null && !rule.exploited) return null;
  const changed =
    before === null ||
    before.autoMinSeverity !== rule.minSeverity ||
    before.autoExploited !== rule.exploited;
  return changed ? sql`now()` : (before?.autoSince ?? null);
}

/** The listed spelling of `wanted` (paths compare without case, as Azure DevOps compares them). */
function listedPath(listed: readonly string[], wanted: string): string | null {
  const lower = wanted.toLowerCase();
  return listed.find((p) => p.toLowerCase() === lower) ?? null;
}

/**
 * The connection's row, shared until the transaction ends, once it is known to be the same
 * organisation's Azure DevOps connection at the address the answers came from: 409 when it is
 * gone, 503 (retry) when it moved.
 */
async function lockUnmoved(tx: Executor, row: ScmConnectionRow): Promise<void> {
  const [current] = await tx
    .select()
    .from(scmConnections)
    .where(eq(scmConnections.id, row.id))
    .for('share');
  if (!current || current.organizationId !== row.organizationId || current.provider !== 'azure') {
    throw notConnected();
  }
  if (current.baseUrl !== row.baseUrl) {
    throw new ProblemError(
      503,
      'CONCURRENCY_CONFLICT',
      'The request conflicted with a concurrent change; retry it',
      { headers: { 'retry-after': '1' } },
    );
  }
}

/** Whether the project has a Jira mapping (one tracker per project). */
async function jiraMapped(db: Executor, projectId: string): Promise<boolean> {
  const [row] = await db
    .select({ projectId: projectJiraSettings.projectId })
    .from(projectJiraSettings)
    .where(eq(projectJiraSettings.projectId, projectId));
  return row !== undefined;
}

/**
 * Design §7.8: a project's Azure Boards mapping on one of its organisation's Azure DevOps
 * connections: the pickers, the work item type check and the automatic rule (project admins,
 * `project.settings`). Azure DevOps' own words reach the answer only in 422
 * BOARDS_CREATE_REFUSED; any other failed call is 502 BOARDS_UNAVAILABLE with a fixed text.
 */
export const boardsProjectRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (
  app,
  { deps },
) => {
  const scmDeps = scmDepsOf(deps.config);

  const unavailable = (detail: string, code: TestProblemCode): never => {
    throw new ProblemError(502, 'BOARDS_UNAVAILABLE', 'Azure DevOps could not be asked', {
      detail,
      extensions: { problemCode: code },
    });
  };

  /** The organisation's Azure DevOps connection `id`: 409 BOARDS_NOT_CONNECTED for any other. */
  const connectionOf = async (project: ProjectRow, id: string): Promise<ScmConnectionRow> => {
    const [row] = await deps.db
      .select()
      .from(scmConnections)
      .where(
        and(
          eq(scmConnections.id, id),
          eq(scmConnections.organizationId, project.organizationId),
          eq(scmConnections.provider, 'azure'),
        ),
      );
    if (!row) throw notConnected();
    return row;
  };

  /** A client for the connection; 502 when none can be made (a credential that no longer reads). */
  const clientOf = (row: ScmConnectionRow): AzureDevOpsClient => {
    const made = azureClientFor(row, scmDeps, deps.scmRuntime);
    if ('problem' in made) return unavailable(made.problem, clientProblemCode(made.problem));
    return made.client;
  };

  const asked = async <T>(call: () => Promise<T>): Promise<T> => {
    try {
      return await call();
    } catch (err) {
      if (err instanceof ScmError) return unavailable(err.message, problemCode(err));
      throw err;
    }
  };

  /** The project's work item types without the hidden ones (Test Plan, Code Review ...). */
  const visibleTypes = async (
    client: AzureDevOpsClient,
    azureProject: string,
  ): Promise<AzureWorkItemType[]> => {
    const [types, hidden] = await asked(() =>
      Promise.all([client.workItemTypes(azureProject), client.hiddenWorkItemTypes(azureProject)]),
    );
    return types.filter((t) => !hidden.has(t.name));
  };

  const answer = async (db: Executor, project: ProjectRow) => {
    const [mapping, connections, monitoring] = await Promise.all([
      boardsMappingOf(db, project.id),
      db
        .select()
        .from(scmConnections)
        .where(
          and(
            eq(scmConnections.organizationId, project.organizationId),
            eq(scmConnections.provider, 'azure'),
          ),
        )
        .orderBy(asc(scmConnections.createdAt), asc(scmConnections.id)),
      monitoringOn(db, project.id),
    ]);
    return {
      mapping: mapping === null ? null : boardsMappingDto(mapping),
      connections: connections.map((c) => ({
        id: c.id,
        name: connectionName(c.baseUrl),
        baseUrl: c.baseUrl,
        problem: c.problem && { code: c.problem.code, at: new Date(c.problem.at).toISOString() },
      })),
      monitoringOn: monitoring,
      exploitedAvailable: deps.edition.limits().vulnerabilities.priority,
    };
  };

  app.get(
    '/projects/:id/boards',
    {
      schema: {
        tags: ['boards'],
        summary:
          "The project's Azure Boards mapping or null, the organisation's Azure DevOps connections (name, address, background problem), whether vulnerability monitoring is on, and whether `exploited` of the automatic rule is licensed",
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
    '/projects/:id/boards/projects',
    {
      config: {
        openapi: {
          problems: [409, 502],
          problemDescriptions: { 409: NOT_CONNECTED, 502: UNAVAILABLE },
        },
      },
      schema: {
        tags: ['boards'],
        summary:
          'The picker (project admins): the Azure DevOps projects the connection sees, by name (at most 1000)',
        params: idParams,
        querystring: z.strictObject(connectionQuery),
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
      const client = clientOf(await connectionOf(project, request.query.connection));
      const found = await asked(() => client.projects());
      return { items: found.map((p) => ({ id: p.id, name: p.name })).sort(byName) };
    },
  );

  app.get(
    '/projects/:id/boards/work-item-types',
    {
      config: {
        openapi: {
          problems: [409, 502],
          problemDescriptions: { 409: NOT_CONNECTED, 502: UNAVAILABLE },
        },
      },
      schema: {
        tags: ['boards'],
        summary:
          'The work item types of an Azure DevOps project by name (project admins), hidden ones left out, each with whether Qualor can create it and the reference names of the always-required fields without a default it cannot fill (it sets Title, Description, Repro Steps, Tags, Area and Iteration; a type needs Description or Repro Steps)',
        params: idParams,
        querystring: z.strictObject({ ...connectionQuery, azureProject: azureProjectId }),
        response: { 200: typeItems },
      },
    },
    async (request) => {
      const project = await projectForUser(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'project.settings',
      );
      const client = clientOf(await connectionOf(project, request.query.connection));
      const types = await visibleTypes(client, request.query.azureProject.toLowerCase());
      const items = types.sort(byName).map((t) => {
        const { supported, missingFields } = analyzeWorkItemType(t);
        return { referenceName: t.referenceName, name: t.name, supported, missingFields };
      });
      return { items };
    },
  );

  app.get(
    '/projects/:id/boards/paths',
    {
      config: {
        openapi: {
          problems: [409, 502],
          problemDescriptions: { 409: NOT_CONNECTED, 502: UNAVAILABLE },
        },
      },
      schema: {
        tags: ['boards'],
        summary:
          "The area and iteration paths of an Azure DevOps project (project admins), as a work item takes them (`<project>\\<child>`): the root (the project's name) first, then depth first, at most 10 levels and 2000 paths each",
        params: idParams,
        querystring: z.strictObject({ ...connectionQuery, azureProject: azureProjectId }),
        response: { 200: pathItems },
      },
    },
    async (request) => {
      const project = await projectForUser(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'project.settings',
      );
      const client = clientOf(await connectionOf(project, request.query.connection));
      const azureProject = request.query.azureProject.toLowerCase();
      const [areas, iterations] = await asked(() =>
        Promise.all([
          client.classificationPaths(azureProject, 'areas'),
          client.classificationPaths(azureProject, 'iterations'),
        ]),
      );
      return { areas, iterations };
    },
  );

  app.put(
    '/projects/:id/boards',
    {
      config: {
        openapi: {
          problems: [403, 409, 502],
          problemDescriptions: {
            403: 'FEATURE_NOT_LICENSED: `autoCreate.exploited` is turned on without the `vuln.priority` licence',
            409: `${NOT_CONNECTED}; TRACKER_IN_USE: the project has a Jira mapping (a project uses one tracker)`,
            422: 'Validation failed (VALIDATION_FAILED; errors[] names each field); BOARDS_WORK_ITEM_TYPE_UNSUPPORTED: the type is not a visible type of the Azure DevOps project, or has always-required fields Qualor cannot fill (their reference names in `missingFields`); BOARDS_PATH_UNKNOWN: the area or iteration path is not one the project lists (errors[] names the field); BOARDS_CREATE_REFUSED: Azure DevOps refused a `validateOnly` work item with the mapping, its own words cut to 500 characters in `detail`',
            502: UNAVAILABLE,
          },
        },
      },
      schema: {
        tags: ['boards'],
        summary:
          "Create or replace the project's Azure Boards mapping (project admins). Checked in order: the connection is an Azure DevOps connection of the organisation (409 BOARDS_NOT_CONNECTED); the project has no Jira mapping (409 TRACKER_IN_USE); the type is a visible type of the Azure DevOps project that Qualor can fill (422 BOARDS_WORK_ITEM_TYPE_UNSUPPORTED, with `missingFields`); a set area or iteration path is one the project lists (422 BOARDS_PATH_UNKNOWN); a `validateOnly` create with the mapping succeeds (422 BOARDS_CREATE_REFUSED, with Azure DevOps' words cut to 500 characters in `detail`); turning `exploited` on needs `vuln.priority` (403). The type's name and the paths are stored as Azure DevOps lists them. `autoCreate.since` is set whenever the rule changes and cleared when it goes off",
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
      const row = await connectionOf(project, body.connectionId);
      if (await jiraMapped(deps.db, project.id)) throw trackerInUse('jira');
      const client = clientOf(row);
      const azureProject = body.azureProject.id.toLowerCase();
      const type = (await visibleTypes(client, azureProject)).find(
        (t) => t.referenceName === body.workItemType.referenceName,
      );
      if (!type) throw typeUnsupported([]);
      const support = analyzeWorkItemType(type);
      if (!support.supported) throw typeUnsupported(support.missingFields);
      const areaPath =
        body.areaPath === null
          ? null
          : listedPath(
              await asked(() => client.classificationPaths(azureProject, 'areas')),
              body.areaPath,
            );
      if (body.areaPath !== null && areaPath === null) throw pathUnknown('areaPath');
      const iterationPath =
        body.iterationPath === null
          ? null
          : listedPath(
              await asked(() => client.classificationPaths(azureProject, 'iterations')),
              body.iterationPath,
            );
      if (body.iterationPath !== null && iterationPath === null) throw pathUnknown('iterationPath');
      try {
        await client.validateWorkItem(
          azureProject,
          type.name,
          mappingCheckOps({ tags: body.tags, areaPath, iterationPath }, support.reproSteps),
        );
      } catch (err) {
        if (err instanceof AzureError) {
          // Probe item 30d: the type was removed or renamed away since the list was read.
          if (err.kind === 'not_found' && err.azureTypeKey === 'WorkItemTypeNotFoundException') {
            throw typeUnsupported([]);
          }
          if (err.kind === 'refused' && err.azureMessage !== null) {
            throw new ProblemError(
              422,
              'BOARDS_CREATE_REFUSED',
              'Azure DevOps refused a work item with this mapping',
              { detail: cutText(err.azureMessage, AZURE_WORDS_MAX) },
            );
          }
        }
        if (err instanceof ScmError) unavailable(err.message, problemCode(err));
        throw err;
      }
      const { minSeverity, exploited } = body.autoCreate;
      await deps.db.transaction(async (tx) => {
        await tx
          .select({ id: projects.id })
          .from(projects)
          .where(eq(projects.id, project.id))
          .for('no key update');
        await lockUnmoved(tx, row);
        // Under the project's row lock, which the Jira PUT takes too: one tracker per project.
        if (await jiraMapped(tx, project.id)) throw trackerInUse('jira');
        const before = await boardsMappingOf(tx, project.id);
        // As the Jira mapping (R10): only turning it on needs the licence; a stored true is kept.
        if (
          exploited &&
          before?.autoExploited !== true &&
          !deps.edition.limits().vulnerabilities.priority
        ) {
          throw priorityNotLicensed();
        }
        const next = {
          connectionId: row.id,
          azureProjectId: azureProject,
          azureProjectName: body.azureProject.name,
          workItemTypeRef: type.referenceName,
          workItemTypeName: type.name,
          areaPath,
          iterationPath,
          tags: body.tags,
          autoMinSeverity: minSeverity,
          autoExploited: exploited,
        };
        const values = {
          ...next,
          autoSince: autoSinceOf(body.autoCreate, before),
          updatedAt: sql`now()`,
        };
        first(
          await tx
            .insert(projectBoardsSettings)
            .values({ projectId: project.id, ...values })
            .onConflictDoUpdate({ target: projectBoardsSettings.projectId, set: values })
            .returning({ projectId: projectBoardsSettings.projectId }),
        );
        const changed = changedFields(before, next);
        if (changed.length > 0) {
          // The connection's pass now (a new mapping, a new rule or another project), queued in
          // this transaction as the Jira connection PUT queues its pass: the schedule lock before
          // the audit chain's.
          await syncBoardsNow(tx, row.id);
          await recordProjectEvent(deps.audit, tx, request, project, 'project.boards_updated', {
            changed,
          });
        }
      });
      return answer(deps.db, project);
    },
  );

  app.delete(
    '/projects/:id/boards',
    {
      schema: {
        tags: ['boards'],
        summary:
          "Remove the project's Azure Boards mapping (project admins); its links stay and keep syncing, nothing new is created. 404 without a mapping",
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
          .delete(projectBoardsSettings)
          .where(eq(projectBoardsSettings.projectId, project.id))
          .returning({ projectId: projectBoardsSettings.projectId });
        if (removed.length === 0) throw notFound('Boards mapping');
        await recordProjectEvent(deps.audit, tx, request, project, 'project.boards_updated', {
          changed: ['mapping'],
        });
      });
      return reply.code(204).send();
    },
  );
};
