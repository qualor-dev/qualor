import { and, eq } from 'drizzle-orm';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import type {
  CLEANUP_SETTINGS_CHANGED_FIELDS,
  PROJECT_CLEANUP_CHANGED_FIELDS,
} from '../audit/catalogue';
import { actorOf } from '../audit/recorder';
import { recordProjectEvent } from '../audit/refs';
import { accessOf, requireInstanceAdmin, requireUser } from '../auth/access';
import {
  CLEANUP_MAX_DAYS,
  cleanupDefaultsSchema,
  effectiveCleanup,
  lockCleanupDefaults,
  MAX_KEEP_BRANCHES,
  readCleanupDefaults,
  writeCleanupDefaults,
  type CleanupDefaults,
} from '../cleanup/settings';
import type { Executor } from '../db/client';
import { first } from '../db/rows';
import { branches, projects } from '../db/schema';
import { notFound, validationFailed } from '../http/problem';
import { idParams, noNul } from '../http/schemas';
import { projectForUser, type ProjectRow } from '../projects/access';
import { normalizePatterns, validGlob } from '../versions/branches';
import { vulnerabilitySettings } from '../versions/settings';

const rulesSchema = z.object({
  branchesDays: z.number().int().nullable(),
  mergeRequestsDays: z.number().int().nullable(),
});

const projectAnswer = z.object({
  branchesDays: z
    .number()
    .int()
    .nullable()
    .describe(
      "The project's own days for branches: null takes the server default, 0 is off for this project",
    ),
  mergeRequestsDays: z
    .number()
    .int()
    .nullable()
    .describe(
      "The project's own days for merge requests: null takes the server default, 0 is off for this project",
    ),
  /** Globs of the branches the cleanup never deletes. */
  keepBranches: z.array(z.string()),
  serverDefaults: rulesSchema.describe('The server defaults (null: off)'),
  effective: rulesSchema.describe('The rules in force for the project (null: off)'),
  alwaysKept: z
    .object({
      /** The main branch's name; null while the project has none. */
      mainBranch: z.string().nullable(),
      /** The vulnerability-monitoring branch patterns (tracked branches). */
      trackedPatterns: z.array(z.string()),
    })
    .describe('What the cleanup never deletes besides the keep patterns'),
});
type ProjectAnswer = z.infer<typeof projectAnswer>;

const projectDays = z.number().int().min(0).max(CLEANUP_MAX_DAYS).nullable();
const projectBody = z.strictObject({
  branchesDays: projectDays,
  mergeRequestsDays: projectDays,
  keepBranches: z.array(noNul(z.string().trim().min(1).max(255))).max(MAX_KEEP_BRANCHES),
});

/** A project's own cleanup columns. */
const CLEANUP_COLUMNS = {
  id: projects.id,
  cleanupBranchesDays: projects.cleanupBranchesDays,
  cleanupMergeRequestsDays: projects.cleanupMergeRequestsDays,
  cleanupKeepBranches: projects.cleanupKeepBranches,
};
type ProjectCleanup = Pick<
  ProjectRow,
  'id' | 'cleanupBranchesDays' | 'cleanupMergeRequestsDays' | 'cleanupKeepBranches'
>;

const sameValue = (a: unknown, b: unknown): boolean => JSON.stringify(a) === JSON.stringify(b);

async function projectAnswerOf(db: Executor, project: ProjectCleanup): Promise<ProjectAnswer> {
  const [defaults, monitoring, [main]] = await Promise.all([
    readCleanupDefaults(db),
    vulnerabilitySettings(db, project.id),
    db
      .select({ name: branches.name })
      .from(branches)
      .where(and(eq(branches.projectId, project.id), eq(branches.isMain, true)))
      .limit(1),
  ]);
  return {
    branchesDays: project.cleanupBranchesDays,
    mergeRequestsDays: project.cleanupMergeRequestsDays,
    keepBranches: [...project.cleanupKeepBranches],
    serverDefaults: defaults,
    effective: effectiveCleanup(project, defaults),
    alwaysKept: { mainBranch: main?.name ?? null, trackedPatterns: monitoring.branchPatterns },
  };
}

/**
 * Issue #38: the cleanup of inactive branches and merge requests. The server defaults are the
 * instance administrator's; a project admin overrides them per project.
 */
export const cleanupRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (app, { deps }) => {
  app.get(
    '/system/cleanup',
    {
      schema: {
        tags: ['system'],
        summary:
          'The server defaults of the cleanup (instance admins): the days after which branches and merge requests not analysed are deleted, null while a rule is off',
        response: { 200: cleanupDefaultsSchema },
      },
    },
    async (request) => {
      requireInstanceAdmin(request);
      return readCleanupDefaults(deps.db);
    },
  );

  app.put(
    '/system/cleanup',
    {
      schema: {
        tags: ['system'],
        summary:
          'Save the server defaults of the cleanup (instance admins): 1-3650 days, or null for off. A project without its own value follows them',
        body: cleanupDefaultsSchema,
        response: { 200: cleanupDefaultsSchema },
      },
    },
    async (request) => {
      requireInstanceAdmin(request);
      const next: CleanupDefaults = request.body;
      await deps.db.transaction(async (tx) => {
        const before = await lockCleanupDefaults(tx);
        const changed: (typeof CLEANUP_SETTINGS_CHANGED_FIELDS)[number][] = (
          ['branchesDays', 'mergeRequestsDays'] as const
        ).filter((field) => before[field] !== next[field]);
        if (changed.length === 0) return;
        await writeCleanupDefaults(tx, next);
        await deps.audit.record(tx, actorOf(request), [
          {
            action: 'cleanup.settings_updated',
            target: { type: 'cleanup_settings', id: 'cleanup' },
            details: { changed },
          },
        ]);
      });
      return readCleanupDefaults(deps.db);
    },
  );

  app.get(
    '/projects/:id/cleanup',
    {
      schema: {
        tags: ['branches'],
        summary:
          "The project's cleanup of inactive branches and merge requests: its own values, the server defaults, the rules in force and what is always kept",
        params: idParams,
        response: { 200: projectAnswer },
      },
    },
    async (request) => {
      const project = await projectForUser(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'project.read',
      );
      return projectAnswerOf(deps.db, project);
    },
  );

  app.put(
    '/projects/:id/cleanup',
    {
      schema: {
        tags: ['branches'],
        summary:
          "Save the project's cleanup (project admins): days of 1-3650, 0 for off, or null for the server default, and at most 20 keep patterns (branch globs, as the vulnerability-monitoring patterns)",
        params: idParams,
        body: projectBody,
        response: { 200: projectAnswer },
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
      if (!body.keepBranches.every(validGlob)) {
        throw validationFailed([
          { path: 'body.keepBranches', message: 'A pattern is not a valid branch glob' },
        ]);
      }
      const next = {
        branchesDays: body.branchesDays,
        mergeRequestsDays: body.mergeRequestsDays,
        keepBranches: normalizePatterns(body.keepBranches),
      };
      const saved = await deps.db.transaction(async (tx) => {
        const [before] = await tx
          .select(CLEANUP_COLUMNS)
          .from(projects)
          .where(eq(projects.id, project.id))
          .for('no key update');
        // Deleted since projectForUser read it.
        if (!before) throw notFound('Project');
        const changed: (typeof PROJECT_CLEANUP_CHANGED_FIELDS)[number][] = [];
        if (before.cleanupBranchesDays !== next.branchesDays) changed.push('branchesDays');
        if (before.cleanupMergeRequestsDays !== next.mergeRequestsDays) {
          changed.push('mergeRequestsDays');
        }
        if (!sameValue(before.cleanupKeepBranches, next.keepBranches)) changed.push('keepBranches');
        if (changed.length === 0) return before;
        const after = first(
          await tx
            .update(projects)
            .set({
              cleanupBranchesDays: next.branchesDays,
              cleanupMergeRequestsDays: next.mergeRequestsDays,
              cleanupKeepBranches: next.keepBranches,
            })
            .where(eq(projects.id, project.id))
            .returning(CLEANUP_COLUMNS),
        );
        await recordProjectEvent(deps.audit, tx, request, project, 'project.cleanup_updated', {
          changed,
        });
        return after;
      });
      return projectAnswerOf(deps.db, saved);
    },
  );
};
