import { and, eq, sql } from 'drizzle-orm';
import type { Config } from '../src/config';
import type { Executor } from '../src/db/client';
import { jiraLinks, jobs } from '../src/db/schema';
import { JIRA_QUEUE } from '../src/jira/jobs';
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
