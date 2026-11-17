import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import type { APIRequestContext } from '@playwright/test';
import { expect } from './fixtures';
import { PAYMENTS_REPORT_FILE } from './seed-data';

/** The parts of a report the tests change; the rest goes back to the server as it was. */
export interface Report {
  project: { key: string };
  analysisDate: string;
  scm: { revision: string; branch: string | null };
  findings: { message: string }[];
  dependencies?: unknown[];
}

/** 6M: the seed's last report of Payments API's main branch (serve.ts writes it). */
export function paymentsReport(): Report {
  return JSON.parse(readFileSync(PAYMENTS_REPORT_FILE, 'utf8')) as Report;
}

/** The id of the project with this key, as the signed-in `session` sees it. */
export async function projectId(session: APIRequestContext, key: string): Promise<string> {
  const projects = (await (await session.get('/api/v0/projects?limit=100')).json()) as {
    items: { id: string; key: string }[];
  };
  const project = projects.items.find((p) => p.key === key);
  if (!project) throw new Error(`no project ${key}`);
  return project.id;
}

/**
 * 6M: `report` ingested into the project `projectKey` as a new analysis (a new revision, today's
 * date) with a project analysis token the signed-in `session` makes, uploaded through `upload` (a
 * context without the session) as the CLI would; resolves once the server has analysed it.
 */
export async function ingestAgain(
  session: APIRequestContext,
  upload: APIRequestContext,
  projectKey: string,
  report: Report,
): Promise<void> {
  const me = (await (await session.get('/api/v0/auth/me')).json()) as { csrfToken: string };
  const created = await session.post(
    `/api/v0/projects/${await projectId(session, projectKey)}/tokens`,
    {
      headers: { 'x-qualor-csrf': me.csrfToken },
      data: { name: 'e2e upload' },
    },
  );
  expect(created.status()).toBe(201);
  const { token } = (await created.json()) as { token: string };

  const fresh: Report = {
    ...report,
    project: { ...report.project, key: projectKey },
    analysisDate: new Date().toISOString(),
    scm: { ...report.scm, revision: randomBytes(20).toString('hex') },
  };
  const answer = await upload.post(
    `/api/v0/analyses?projectKey=${encodeURIComponent(projectKey)}`,
    {
      headers: {
        authorization: `Bearer ${token}`,
        'content-type': 'application/vnd.qualor.report+json',
        'content-encoding': 'gzip',
      },
      data: gzipSync(Buffer.from(JSON.stringify(fresh), 'utf8')),
    },
  );
  expect(answer.status()).toBe(202);
  const { analysisId } = (await answer.json()) as { analysisId: string };
  await expect
    .poll(
      async () => {
        const res = await upload.get(`/api/v0/analyses/${analysisId}`, {
          headers: { authorization: `Bearer ${token}` },
        });
        return ((await res.json()) as { status: string }).status;
      },
      { timeout: 60_000 },
    )
    .toBe('succeeded');
}
