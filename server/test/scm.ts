import type { Report } from '@qualor/shared';
import { inArray, sql } from 'drizzle-orm';
import type { Config } from '../src/config';
import { jobs } from '../src/db/schema';
import { AI_FIX_QUEUE } from '../src/llm/post';
import { runUntilIdle } from '../src/queue/worker';
import { scmHandlers, type DecorationDeps } from '../src/scm/decorate';
import { SCM_QUEUE } from '../src/scm/queue';
import { createScmRuntime } from '../src/scm/runtime';
import type { FakeGitLab } from './fake-gitlab';
import type { IngestHarness, IngestProject } from './ingest';
import { reportWith, type ReportParts } from './reports';

export const PUBLIC_URL = 'https://qualor.example.com';
/**
 * The fake GitLab listens on 127.0.0.1 on a port of its own, which the operator must list with
 * that port (scm.md §2.1: an entry without a port allows only the scheme's default port).
 */
export function scmTestConfig(fake: FakeGitLab): Partial<Config> {
  return {
    scmInternalHosts: new Set([new URL(fake.url).host]) as ReadonlySet<string>,
    publicUrl: PUBLIC_URL,
  };
}
export const silentLogger = {
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
};

/** One connection per organisation and fake, shared by the projects of a test file. */
const sharedConnections = new Map<string, string>();

/**
 * A Qualor project mapped to GitLab project `gitlabProjectId` of the fake, through the API: on the
 * organisation's shared connection to the fake (an organisation has at most 10), or on a new one
 * of its own with `ownConnection` (for a test that changes or deletes it).
 */
export async function mappedProject(
  h: IngestHarness,
  fake: FakeGitLab,
  key: string,
  gitlabProjectId: number,
  options: { ownConnection?: boolean } = {},
): Promise<IngestProject & { connectionId: string }> {
  const cacheKey = `${h.organizationId}|${fake.url}`;
  let connectionId = options.ownConnection ? undefined : sharedConnections.get(cacheKey);
  if (connectionId === undefined) {
    const created = await h.ctx.app.inject({
      method: 'POST',
      url: '/api/v0/scm-connections',
      headers: h.orgAdmin.headers,
      payload: {
        organizationId: h.organizationId,
        provider: 'gitlab',
        baseUrl: fake.url,
        token: fake.token,
      },
    });
    if (created.statusCode !== 201) throw new Error(`connection: ${created.body}`);
    connectionId = (created.json() as { id: string }).id;
    if (!options.ownConnection) sharedConnections.set(cacheKey, connectionId);
  }
  const project = await h.project(key);
  const mapped = await h.ctx.app.inject({
    method: 'PATCH',
    url: `/api/v0/projects/${project.id}`,
    headers: h.orgAdmin.headers,
    payload: { scmConnectionId: connectionId, scmProjectRef: String(gitlabProjectId) },
  });
  if (mapped.statusCode !== 200) throw new Error(`mapping: ${mapped.body}`);
  return { ...project, connectionId };
}

export function decorationDeps(
  h: IngestHarness,
  overrides: Partial<DecorationDeps> = {},
): DecorationDeps {
  return {
    db: h.ctx.db,
    scm: {
      secretKey: h.ctx.config.secretKey,
      internalHosts: h.ctx.config.scmInternalHosts,
      clientOptions: { timeoutMs: 2_000 },
      githubClientOptions: { timeoutMs: 2_000 },
    },
    runtime: createScmRuntime(),
    publicUrl: h.ctx.config.publicUrl,
    logger: h.ctx.app.log,
    ...overrides,
  };
}

/** Makes every queued decoration and AI fix post due now, then runs the `scm` worker's queues until idle. */
export async function runDecorations(h: IngestHarness, deps: DecorationDeps): Promise<number> {
  await h.ctx.db
    .update(jobs)
    .set({ runAt: sql`now()` })
    .where(inArray(jobs.queue, [SCM_QUEUE, AI_FIX_QUEUE]));
  return runUntilIdle(h.ctx.db, scmHandlers(deps), silentLogger);
}

/** Queued decoration jobs, oldest first. */
export async function queuedDecorations(h: IngestHarness) {
  return h.ctx.db
    .select()
    .from(jobs)
    .where(sql`${jobs.queue} = ${SCM_QUEUE} AND ${jobs.status} = 'queued'`)
    .orderBy(jobs.id);
}

/** A merge request report from GitLab CI: `!iid` of `source` into main at `revision`. */
export function mergeRequestReport(
  iid: number,
  revision: string,
  parts: ReportParts & { gitlab?: Report['scm']['gitlab'] } = {},
): Report {
  const { gitlab, ...rest } = parts;
  const report = reportWith({
    branch: 'feature/x',
    mergeRequest: { id: String(iid), targetBranch: 'main', sourceBranch: 'feature/x' },
    revision,
    baseline: { revision: 'b'.repeat(40), kind: 'merge_base', status: 'ok' },
    ...rest,
  });
  return gitlab === undefined ? report : { ...report, scm: { ...report.scm, gitlab } };
}
