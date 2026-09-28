import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { and, eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';
import { branches, issues } from '../src/db/schema';
import { gateHandlers } from '../src/gates/reevaluate';
import { runUntilIdle } from '../src/queue/worker';
import { markerOf } from '../src/scm/markdown';
import { enqueueDecoration } from '../src/scm/queue';
import { statusName } from '../src/scm/render';
import { gitlabShape } from './fake-gitlab';
import { createIngestHarness, type IngestHarness } from './ingest';
import { engine, file, finding } from './reports';
import {
  decorationDeps,
  mergeRequestReport,
  queuedDecorations,
  runDecorations,
  silentLogger,
} from './scm';

/**
 * scm.md §11, opt-in (`pnpm gitlab:real`): the decoration against a real GitLab CE in Docker
 * (gitlab-real-setup.ts), with a project access token of the recommended kind (the `api` scope,
 * the Developer role). It also checks what the fake cannot: that GitLab accepts Qualor's diff
 * positions and status transitions, that its answers carry every field of the recorded shapes,
 * that the component passes GitLab's CI lint, and how GitLab renders Qualor's comments.
 */
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const B_LINES = Array.from({ length: 30 }, (_, i) => `export const b${i} = ${i};`).join('\n');

let h: IngestHarness;
let gitlab: string;
let root: string;
let projectId: number;
let projectPath: string;
let iid: number;
let head: string;
let base: string;
let accessToken: string;

async function api<T = unknown>(
  method: string,
  route: string,
  body?: unknown,
  token = root,
): Promise<{ status: number; json: T }> {
  const res = await fetch(`${gitlab}/api/v4${route}`, {
    method,
    headers: {
      'private-token': token,
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  return { status: res.status, json: (text ? JSON.parse(text) : null) as T };
}

async function ok<T>(method: string, route: string, body?: unknown): Promise<T> {
  const res = await api<T>(method, route, body);
  if (res.status >= 300)
    throw new Error(`${method} ${route}: ${res.status} ${JSON.stringify(res.json)}`);
  return res.json;
}

/** Every top-level field of a recorded shape is in GitLab's real answer. */
function expectShape(name: string, real: unknown): void {
  const shape = gitlabShape<unknown>(name);
  const recorded = Object.keys((Array.isArray(shape) ? shape[0] : shape) as object);
  const missing = recorded.filter((k) => !(k in (real as Record<string, unknown>)));
  expect(missing, `fields of gitlab-shapes/${name}.json missing in GitLab's answer`).toEqual([]);
}

beforeAll(async () => {
  gitlab = inject('gitlabUrl');
  root = inject('gitlabRootToken');
  const suffix = Date.now().toString(36);
  const created = await ok<{ id: number; path_with_namespace: string }>('POST', '/projects', {
    name: `qualor-check-${suffix}`,
    default_branch: 'main',
  });
  projectId = created.id;
  projectPath = created.path_with_namespace;
  const first = await ok<{ id: string }>('POST', `/projects/${projectId}/repository/commits`, {
    branch: 'main',
    commit_message: 'first',
    actions: [
      { action: 'create', file_path: 'src/a.ts', content: 'export const a = 1;\n' },
      {
        action: 'create',
        file_path: 'templates/qualor.yml',
        content: readFileSync(path.join(repoRoot, 'templates', 'qualor.yml'), 'utf8'),
      },
    ],
  });
  base = first.id;
  const second = await ok<{ id: string }>('POST', `/projects/${projectId}/repository/commits`, {
    branch: 'feature/x',
    start_branch: 'main',
    commit_message: 'second',
    actions: [{ action: 'create', file_path: 'src/b.ts', content: `${B_LINES}\n` }],
  });
  head = second.id;
  // The token Qualor holds: a project access token, api scope, Developer role (scm.md §2.1).
  const token = await ok<{ token: string }>('POST', `/projects/${projectId}/access_tokens`, {
    name: 'qualor',
    scopes: ['api'],
    access_level: 30,
    expires_at: new Date(Date.now() + 2 * 86_400_000).toISOString().slice(0, 10),
  });
  accessToken = token.token;
  const mr = await ok<{ iid: number }>('POST', `/projects/${projectId}/merge_requests`, {
    source_branch: 'feature/x',
    target_branch: 'main',
    title: 'Add b @all',
  });
  iid = mr.iid;
  // GitLab prepares the merge request's diff in the background.
  for (let i = 0; i < 120; i++) {
    const got = await ok<{ diff_refs: { head_sha: string | null } | null }>(
      'GET',
      `/projects/${projectId}/merge_requests/${iid}`,
    );
    if (got.diff_refs?.head_sha === head) break;
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }
  h = await createIngestHarness({
    config: {
      // The port too: an entry without one allows only the scheme's default port (scm.md §2.1).
      scmInternalHosts: new Set([new URL(gitlab).host]),
      publicUrl: 'https://qualor.example.com',
    },
  });
}, 300_000);

afterAll(async () => {
  await h?.close();
});

describe('decoration against a real GitLab CE (scm.md §11)', () => {
  it('matches the recorded shapes and passes the component through GitLab CI lint', async () => {
    expectShape('user', (await api('GET', '/user', undefined, accessToken)).json);
    expectShape('project', await ok('GET', `/projects/${projectId}`));
    expectShape('merge_request', await ok('GET', `/projects/${projectId}/merge_requests/${iid}`));
    const diffs = await ok<unknown[]>('GET', `/projects/${projectId}/merge_requests/${iid}/diffs`);
    expectShape('merge_request_diffs', diffs[0]);
    const lint = await ok<{ valid: boolean; errors: string[] }>(
      'POST',
      `/projects/${projectId}/ci/lint`,
      {
        content:
          "include:\n  - local: templates/qualor.yml\n    inputs:\n      image-tag: '0.1.0'\n",
      },
    );
    expect(lint.errors).toEqual([]);
    expect(lint.valid).toBe(true);
  });

  it('decorates, resolves on a false positive, and renders comments without links, images or mentions', async () => {
    const { ctx, orgAdmin } = h;
    const created = await ctx.app.inject({
      method: 'POST',
      url: '/api/v0/scm-connections',
      headers: orgAdmin.headers,
      payload: {
        organizationId: h.organizationId,
        provider: 'gitlab',
        baseUrl: gitlab,
        token: accessToken,
      },
    });
    expect(created.statusCode, created.body).toBe(201);
    const project = await h.project('real/check');
    const mapped = await ctx.app.inject({
      method: 'PATCH',
      url: `/api/v0/projects/${project.id}`,
      headers: orgAdmin.headers,
      payload: {
        scmConnectionId: (created.json() as { id: string }).id,
        scmProjectRef: projectPath,
      },
    });
    expect(mapped.statusCode, mapped.body).toBe(200);
    await project.ingestOk(
      mergeRequestReport(iid, head, {
        projectKey: project.key,
        baseline: { revision: base, kind: 'merge_base', status: 'ok' },
        engines: [engine('ext-tool')],
        files: [file('src/b.ts', { lines: 30, newLines: 'all' })],
        findings: [
          finding({
            engineId: 'ext-tool',
            path: 'src/b.ts',
            line: 7,
            message:
              'Magic @all\n/merge ![x](http://evil.example/x.png) [y](http://evil.example) #1',
          }),
        ],
        gitlab: { projectId: String(projectId), mergeRequestEventType: 'detached' },
      }),
    );
    const deps = decorationDeps(h, {
      scm: { secretKey: ctx.config.secretKey, internalHosts: ctx.config.scmInternalHosts },
    });
    await runDecorations(h, deps);

    const statuses = await ok<{ name: string; status: string }[]>(
      'GET',
      `/projects/${projectId}/repository/commits/${head}/statuses`,
    );
    expect(statuses.filter((s) => s.name === statusName(project.key)).map((s) => s.status)).toEqual(
      ['failed'],
    );
    expectShape('commit_status', statuses[0]);
    const discussions = await ok<
      {
        id: string;
        notes: { body: string; resolved?: boolean; position?: { new_line: number } }[];
      }[]
    >('GET', `/projects/${projectId}/merge_requests/${iid}/discussions?per_page=100`);
    const own = (kind: 'summary' | 'issue') =>
      discussions.filter((d) => markerOf(d.notes[0]?.body ?? '')?.kind === kind);
    expect(own('summary')).toHaveLength(1);
    expect(own('issue')).toHaveLength(1);
    expect(own('issue')[0]?.notes[0]?.position?.new_line).toBe(7);
    expectShape('discussion', own('issue')[0]);
    expectShape('note', own('summary')[0]?.notes[0]);

    // GitLab's own renderer: no link, image, mention or reference comes out of the message.
    for (const body of [...own('summary'), ...own('issue')].map((d) => d.notes[0]?.body ?? '')) {
      const html = await ok<{ html: string }>('POST', '/markdown', {
        text: body,
        gfm: true,
        project: projectPath,
      });
      expect(html.html).not.toMatch(/<img|href="http:\/\/evil|data-reference-type|gl-emoji/);
    }
    const mr = await ok<{ state: string }>('GET', `/projects/${projectId}/merge_requests/${iid}`);
    expect(mr.state).toBe('opened');

    // Running it again changes nothing.
    await runDecorations(h, deps);
    const again = await ok<unknown[]>(
      'GET',
      `/projects/${projectId}/merge_requests/${iid}/discussions?per_page=100`,
    );
    expect(again).toHaveLength(discussions.length);

    // A false positive: re-evaluation, then the status turns to success and the thread resolves.
    const [mrBranch] = await ctx.db
      .select()
      .from(branches)
      .where(and(eq(branches.projectId, project.id), eq(branches.kind, 'merge_request')));
    const [issue] = await ctx.db
      .select()
      .from(issues)
      .where(and(eq(issues.branchId, mrBranch!.id), eq(issues.status, 'open')));
    const transition = await ctx.app.inject({
      method: 'POST',
      url: `/api/v0/issues/${issue!.id}/transition`,
      headers: orgAdmin.headers,
      payload: { to: 'false_positive', comment: 'intended' },
    });
    expect(transition.statusCode, transition.body).toBe(200);
    await runUntilIdle(ctx.db, gateHandlers({ db: ctx.db }), silentLogger);
    await runDecorations(h, deps);
    const after = await ok<{ name: string; status: string }[]>(
      'GET',
      `/projects/${projectId}/repository/commits/${head}/statuses`,
    );
    expect(after.filter((s) => s.name === statusName(project.key)).map((s) => s.status)).toContain(
      'success',
    );
    const resolved = await ok<{ notes: { body: string; resolved?: boolean }[] }[]>(
      'GET',
      `/projects/${projectId}/merge_requests/${iid}/discussions?per_page=100`,
    );
    const thread = resolved.find((d) => markerOf(d.notes[0]?.body ?? '')?.kind === 'issue');
    expect(thread?.notes[0]?.resolved).toBe(true);
    // The same status once more is not an error (scm.md §4.3), and nothing else changes.
    await enqueueDecoration(ctx.db, {
      analysisId: mrBranch!.lastAnalysisId!,
      branchId: mrBranch!.id,
      gitlab: null,
    });
    await runDecorations(h, deps);
    expect(await queuedDecorations(h)).toEqual([]);
    expect(ctx.logs.join('\n')).not.toContain(accessToken);
  }, 300_000);
});
