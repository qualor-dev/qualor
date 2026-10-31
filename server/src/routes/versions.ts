import { and, eq, inArray, sql } from 'drizzle-orm';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import picomatch from 'picomatch';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { actorOf } from '../audit/recorder';
import { projectRefs } from '../audit/refs';
import { accessOf, requireUser } from '../auth/access';
import type { Executor } from '../db/client';
import { first } from '../db/rows';
import {
  branches,
  projectVersions,
  projectVulnerabilitySettings,
  projects,
  versionDependencies,
  type ProjectVersionRow,
} from '../db/schema';
import { decodeCursor, encodeCursor, pageQuery, pageSchema } from '../http/pagination';
import { notFound, validationFailed } from '../http/problem';
import { idParams, iso, noNul } from '../http/schemas';
import { projectForUser } from '../projects/access';
import { branchMatches, normalizePatterns } from '../versions/branches';
import { parseVersionLabel } from '../versions/label';
import { vulnerabilitySettings, type VulnerabilitySettings } from '../versions/settings';
import { computeTracking, type TrackingReason } from '../versions/tracking';
import { enqueueRecheck } from '../vulnerabilities/recheck';
import { readVulndbSettings } from '../vulndb/settings';

/** Lists in the monitoring answer are bounded. */
const LIST_LIMIT = 50;
const MAX_PATTERNS = 10;
const MAX_LINES = 20;

const TRACKING_REASONS = [
  'pinned',
  'unsupported',
  'prerelease',
  'newest_in_line',
  'replaced',
  'older_line',
  'recent',
  'older',
  'rule_all',
  'rule_none',
] as const satisfies readonly TrackingReason[];

const trackingOverride = z.enum(['auto', 'pinned', 'unsupported']);

const versionSchema = z.object({
  id: z.uuid(),
  /** `project.version`, else the tag. */
  label: z.string(),
  /** `tag`: a tag scan; `label`: taken from a branch analysis that carries `project.version`. */
  source: z.enum(['tag', 'label']),
  tag: z.string().nullable(),
  analyzedAt: z.iso.datetime(),
  /** The user's override. */
  tracking: trackingOverride,
  /** Whether vulnerabilities are monitored for this version under the project's rule. */
  tracked: z.boolean(),
  trackingReason: z.enum(TRACKING_REASONS),
  /** A pre-release label such as 2.4.0-rc.1. */
  prerelease: z.boolean(),
  /** Entries of the version's dependency inventory. */
  packages: z.number().int(),
});
type VersionDto = z.infer<typeof versionSchema>;

const versionRuleSchema = z.discriminatedUnion('kind', [
  z.strictObject({ kind: z.literal('lines'), lines: z.number().int().min(1).max(MAX_LINES) }),
  z.strictObject({ kind: z.literal('all') }),
  z.strictObject({ kind: z.literal('none') }),
]);

const monitoringSchema = z.object({
  enabled: z.boolean(),
  /** Globs of the branch names tracked besides the main branch. */
  branchPatterns: z.array(z.string()),
  versionRule: versionRuleSchema,
  /** Also take versions from branch analyses that carry `project.version`. */
  labelVersions: z.boolean(),
  mainBranchName: z.string(),
  /** Branches that match the patterns now (at most 50, by name). */
  matchingBranches: z.array(z.string()),
  /** Labels of the tracked versions, newest first (at most 50). */
  trackedVersions: z.array(z.string()),
  versionCount: z.number().int(),
});

const monitoringBody = z.strictObject({
  enabled: z.boolean(),
  branchPatterns: z.array(noNul(z.string().trim().min(1).max(255))).max(MAX_PATTERNS),
  versionRule: versionRuleSchema,
  labelVersions: z.boolean(),
});

/** Whether picomatch can compile the glob and it holds no control character. */
function validGlob(pattern: string): boolean {
  for (let i = 0; i < pattern.length; i++) {
    const code = pattern.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return false;
  }
  try {
    // Without debug, picomatch swallows the RegExp error and returns a match-nothing regex.
    picomatch.makeRe(pattern, { dot: true, debug: true });
    return true;
  } catch {
    return false;
  }
}

interface VersionTrack {
  row: Pick<ProjectVersionRow, 'id' | 'label' | 'source' | 'tag' | 'analyzedAt' | 'tracking'>;
  tracked: boolean;
  reason: TrackingReason;
}

/** Every version of the project, newest analysis first, with the tracking the rule decides. */
async function trackVersions(
  db: Executor,
  projectId: string,
  settings: VulnerabilitySettings,
): Promise<VersionTrack[]> {
  const rows = await db
    .select({
      id: projectVersions.id,
      label: projectVersions.label,
      source: projectVersions.source,
      tag: projectVersions.tag,
      analyzedAt: projectVersions.analyzedAt,
      tracking: projectVersions.tracking,
    })
    .from(projectVersions)
    .where(eq(projectVersions.projectId, projectId));
  const decisions = computeTracking(rows, settings.versionRule);
  return rows
    .sort(
      (a, b) =>
        b.analyzedAt.getTime() - a.analyzedAt.getTime() || (a.id < b.id ? 1 : a.id > b.id ? -1 : 0),
    )
    .map((row) => {
      const decision = decisions.get(row.id);
      return { row, tracked: decision?.tracked ?? false, reason: decision?.reason ?? 'older' };
    });
}

/** The inventory sizes of the versions. */
async function packageCounts(db: Executor, ids: readonly string[]): Promise<Map<string, number>> {
  if (ids.length === 0) return new Map();
  const counts = await db
    .select({ id: versionDependencies.versionId, n: sql<number>`count(*)::int` })
    .from(versionDependencies)
    .where(inArray(versionDependencies.versionId, [...ids]))
    .groupBy(versionDependencies.versionId);
  return new Map(counts.map((c) => [c.id, c.n]));
}

function versionDto(track: VersionTrack, packages: number): VersionDto {
  const { row } = track;
  return {
    id: row.id,
    label: row.label,
    source: row.source,
    tag: row.tag,
    analyzedAt: iso(row.analyzedAt),
    tracking: row.tracking,
    tracked: track.tracked,
    trackingReason: track.reason,
    prerelease: parseVersionLabel(row.label)?.prerelease ?? false,
    packages,
  };
}

async function monitoringDto(
  db: Executor,
  project: { id: string; mainBranchName: string },
): Promise<z.infer<typeof monitoringSchema>> {
  const settings = await vulnerabilitySettings(db, project.id);
  const [tracks, branchRows] = await Promise.all([
    trackVersions(db, project.id, settings),
    settings.branchPatterns.length === 0
      ? []
      : db
          .select({ name: branches.name })
          .from(branches)
          .where(
            and(
              eq(branches.projectId, project.id),
              eq(branches.kind, 'branch'),
              eq(branches.isMain, false),
            ),
          ),
  ]);
  const matching = branchRows
    .map((b) => b.name)
    .filter((name) => branchMatches(name, settings.branchPatterns))
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
    .slice(0, LIST_LIMIT);
  return {
    ...settings,
    mainBranchName: project.mainBranchName,
    matchingBranches: matching,
    trackedVersions: tracks
      .filter((t) => t.tracked)
      .slice(0, LIST_LIMIT)
      .map((t) => t.row.label),
    versionCount: tracks.length,
  };
}

const sameValue = (a: unknown, b: unknown): boolean => JSON.stringify(a) === JSON.stringify(b);

/**
 * What the project tracks changed: its vulnerability rows follow at a re-check. Last in the
 * transaction (enqueueRecheck holds a global lock until the commit); none while monitoring is off.
 */
async function recheckProject(tx: Executor, projectId: string): Promise<void> {
  if ((await readVulndbSettings(tx)).enabled) await enqueueRecheck(tx, { projectIds: [projectId] });
}

export const versionRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (app, { deps }) => {
  app.get(
    '/projects/:id/versions',
    {
      schema: {
        tags: ['versions'],
        summary: 'Released versions of a project, newest analysis first, with their tracking',
        params: idParams,
        querystring: z.strictObject({
          limit: z.coerce.number().int().min(1).max(100).default(50),
          cursor: pageQuery.cursor,
        }),
        response: { 200: pageSchema(versionSchema) },
      },
    },
    async (request) => {
      const project = await projectForUser(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'project.read',
      );
      const { limit } = request.query;
      const settings = await vulnerabilitySettings(deps.db, project.id);
      const tracks = await trackVersions(deps.db, project.id, settings);
      const after = decodeCursor(request.query.cursor);
      let start = 0;
      if (after !== undefined) {
        const at = tracks.findIndex((t) => t.row.id === after);
        if (at < 0) throw validationFailed([{ path: 'query.cursor', message: 'Invalid cursor' }]);
        start = at + 1;
      }
      const page = tracks.slice(start, start + limit);
      const counts = await packageCounts(
        deps.db,
        page.map((t) => t.row.id),
      );
      const last = page.at(-1);
      return {
        items: page.map((t) => versionDto(t, counts.get(t.row.id) ?? 0)),
        nextCursor: last && start + limit < tracks.length ? encodeCursor(last.row.id) : null,
      };
    },
  );

  app.patch(
    '/projects/:id/versions/:versionId',
    {
      schema: {
        tags: ['versions'],
        summary: "Pin a version, mark it unsupported, or leave its tracking to the project's rule",
        params: z.strictObject({ id: z.uuid(), versionId: z.uuid() }),
        body: z.strictObject({ tracking: trackingOverride }),
        response: { 200: versionSchema },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      const project = await projectForUser(
        accessOf(deps),
        principal,
        request.params.id,
        'project.settings',
      );
      return deps.db.transaction(async (tx) => {
        const [version] = await tx
          .update(projectVersions)
          .set({ tracking: request.body.tracking, updatedAt: sql`now()` })
          .where(
            and(
              eq(projectVersions.id, request.params.versionId),
              eq(projectVersions.projectId, project.id),
            ),
          )
          .returning({ id: projectVersions.id, label: projectVersions.label });
        if (!version) throw notFound('Version');
        const settings = await vulnerabilitySettings(tx, project.id);
        const tracks = await trackVersions(tx, project.id, settings);
        const track = tracks.find((t) => t.row.id === version.id);
        if (!track) throw notFound('Version');
        if (deps.audit.active()) {
          const refs = await projectRefs(tx, project.id);
          await deps.audit.record(tx, actorOf(request), [
            {
              action: 'project_version.updated',
              organization: refs.organization,
              project: refs.project,
              target: { type: 'project', id: project.id, label: project.name },
              details: { label: version.label, tracking: request.body.tracking },
            },
          ]);
        }
        const counts = await packageCounts(tx, [version.id]);
        await recheckProject(tx, project.id);
        return versionDto(track, counts.get(version.id) ?? 0);
      });
    },
  );

  app.get(
    '/projects/:id/vulnerability-monitoring',
    {
      schema: {
        tags: ['versions'],
        summary: 'What the project monitors for vulnerabilities: branches and released versions',
        params: idParams,
        response: { 200: monitoringSchema },
      },
    },
    async (request) => {
      const project = await projectForUser(
        accessOf(deps),
        requireUser(request),
        request.params.id,
        'project.read',
      );
      return monitoringDto(deps.db, project);
    },
  );

  app.put(
    '/projects/:id/vulnerability-monitoring',
    {
      schema: {
        tags: ['versions'],
        summary: 'Save what the project monitors for vulnerabilities',
        params: idParams,
        body: monitoringBody,
        response: { 200: monitoringSchema },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      const project = await projectForUser(
        accessOf(deps),
        principal,
        request.params.id,
        'project.settings',
      );
      const { body } = request;
      if (!body.branchPatterns.every(validGlob)) {
        throw validationFailed([
          { path: 'body.branchPatterns', message: 'A pattern is not a valid branch glob' },
        ]);
      }
      const branchPatterns = normalizePatterns(body.branchPatterns);
      const next: VulnerabilitySettings = {
        enabled: body.enabled,
        branchPatterns,
        versionRule: body.versionRule,
        labelVersions: body.labelVersions,
      };
      return deps.db.transaction(async (tx) => {
        await tx
          .select({ id: projects.id })
          .from(projects)
          .where(eq(projects.id, project.id))
          .for('no key update');
        const before = await vulnerabilitySettings(tx, project.id);
        const values = {
          enabled: next.enabled,
          branchPatterns: next.branchPatterns,
          versionRule: next.versionRule.kind,
          labelVersions: next.labelVersions,
          updatedAt: sql`now()`,
          ...(next.versionRule.kind === 'lines' && { versionLines: next.versionRule.lines }),
        };
        first(
          await tx
            .insert(projectVulnerabilitySettings)
            .values({ projectId: project.id, ...values })
            .onConflictDoUpdate({ target: projectVulnerabilitySettings.projectId, set: values })
            .returning({ projectId: projectVulnerabilitySettings.projectId }),
        );
        const changed = (
          ['enabled', 'branchPatterns', 'versionRule', 'labelVersions'] as const
        ).filter((field) => !sameValue(before[field], next[field]));
        if (changed.length > 0 && deps.audit.active()) {
          const refs = await projectRefs(tx, project.id);
          await deps.audit.record(tx, actorOf(request), [
            {
              action: 'project.vulnerability_monitoring_updated',
              organization: refs.organization,
              project: refs.project,
              target: { type: 'project', id: project.id, label: project.name },
              details: { changed },
            },
          ]);
        }
        const dto = await monitoringDto(tx, project);
        if (changed.length > 0) await recheckProject(tx, project.id);
        return dto;
      });
    },
  );
};
