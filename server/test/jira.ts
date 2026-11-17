import { and, eq, sql } from 'drizzle-orm';
import type { Config } from '../src/config';
import type { Executor } from '../src/db/client';
import { jiraLinks, jobs } from '../src/db/schema';
import { JIRA_QUEUE } from '../src/jira/jobs';
import { jiraHandlers, type JiraJobDeps } from '../src/jira/run';
import { communityLimits } from '../src/limits';
import { runUntilIdle } from '../src/queue/worker';
import type { FakeJira } from './fake-jira';
import type { IngestHarness } from './ingest';

/**
 * The fake Jira listens on 127.0.0.1 on a port of its own, which the operator must list with that
 * port (an entry without a port allows only the scheme's default one).
 */
export function jiraTestConfig(fake: FakeJira): Partial<Config> {
  return { jiraInternalHosts: new Set([new URL(fake.url).host]) as ReadonlySet<string> };
}

/**
 * Connects the harness's organisation to the (Data Center) fake through the API and returns the
 * connection's id. The first pass is moved a day ahead, so no test runs a pass by accident.
 */
export async function connectJira(
  h: IngestHarness,
  fake: FakeJira,
  body: object = {},
): Promise<string> {
  const res = await h.ctx.app.inject({
    method: 'PUT',
    url: `/api/v0/organizations/${h.organizationId}/jira`,
    headers: h.orgAdmin.headers,
    payload: { deployment: 'data_center', siteUrl: fake.url, token: fake.token, ...body },
  });
  if (res.statusCode !== 200) throw new Error(`jira connection: ${res.body}`);
  await h.ctx.db
    .update(jobs)
    .set({ runAt: sql`now() + interval '1 day'` })
    .where(and(eq(jobs.queue, JIRA_QUEUE), eq(jobs.status, 'queued')));
  return (res.json() as { id: string }).id;
}

let seeded = 0;

/**
 * A link row, a pending vulnerability one unless `row` says otherwise (a `kind: 'issue'` row needs
 * its `issueId`). Returns its id.
 */
export async function seedJiraLink(
  db: Executor,
  row: Partial<typeof jiraLinks.$inferInsert> & { projectId: string; connectionId: string },
): Promise<string> {
  seeded += 1;
  const target =
    row.kind === 'issue'
      ? {}
      : {
          packageName: `pkg-${seeded}`,
          vulnerabilityId: `CVE-2026-${String(seeded).padStart(4, '0')}`,
        };
  const [created] = await db
    .insert(jiraLinks)
    .values({ kind: 'vulnerability', state: 'pending', origin: 'manual', ...target, ...row })
    .returning({ id: jiraLinks.id });
  return created!.id;
}

/**
 * Maps the project to the fake's `QUAL` project (id 10000, as the tests add it) and its `Bug` type,
 * with no labels, no priorities and the automatic rule off; `body` overrides any of it.
 */
export async function mapJira(
  h: IngestHarness,
  projectId: string,
  body: object = {},
): Promise<void> {
  const res = await h.ctx.app.inject({
    method: 'PUT',
    url: `/api/v0/projects/${projectId}/jira`,
    headers: h.orgAdmin.headers,
    payload: {
      jiraProject: { id: '10000', key: 'QUAL', name: 'Qualor findings' },
      issueType: { id: '10001', name: 'Bug' },
      labels: [],
      priorities: null,
      autoCreate: { minSeverity: null, exploited: false },
      ...body,
    },
  });
  if (res.statusCode !== 200) throw new Error(`jira mapping: ${res.body}`);
}

/**
 * The create and sync jobs' deps for the harness's app: its secret key, internal hosts, public URL
 * and limits, and a 1 s deadline per Jira request so a hang costs a second, not ten.
 */
export function jiraJobDeps(h: IngestHarness, overrides: Partial<JiraJobDeps> = {}): JiraJobDeps {
  return {
    db: h.ctx.db,
    secretKey: h.ctx.config.secretKey,
    internalHosts: h.ctx.config.jiraInternalHosts,
    publicUrl: h.ctx.config.publicUrl,
    limits: () => h.ctx.edition?.limits() ?? communityLimits(),
    clientOptions: { timeoutMs: 1_000 },
    ...overrides,
  };
}

/**
 * Makes the queued `jira` jobs of this kind due now and runs the queue until idle (a job those
 * jobs queue for now runs too). Returns how many jobs ran.
 */
export async function runJiraJobs(
  h: IngestHarness,
  deps: JiraJobDeps,
  kind: 'create' | 'sync',
): Promise<number> {
  await h.ctx.db
    .update(jobs)
    .set({ runAt: sql`now()` })
    .where(
      and(
        eq(jobs.queue, JIRA_QUEUE),
        eq(jobs.status, 'queued'),
        sql`${jobs.payload} ->> 'kind' = ${kind}`,
      ),
    );
  return runUntilIdle(h.ctx.db, jiraHandlers(deps), deps.logger ?? h.ctx.app.log);
}
