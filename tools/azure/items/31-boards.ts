import { createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { hex32, type Report } from '@qualor/shared';
import { z } from 'zod';
import type { AzureResponse } from '../client.js';
import { redact } from '../record.js';
import {
  BENCH_ORG,
  benchProject,
  benchScmUrl,
  check,
  needEnv,
  qualorIdentityId,
  rec,
  type Check,
} from './19-decoration.js';
import { QualorApi } from './21-review.js';
import { problemText } from './27-onboarding.js';
import { describeAnswer, escapeHtml, tagsOf, wiqlIds } from './30-boards-facts.js';
import {
  answerOf,
  ok,
  result,
  shape,
  waitFor,
  type ProbeContext,
  type ProbeItem,
} from './common.js';

const PATCH_JSON = 'application/json-patch+json';
const REPRO = 'Microsoft.VSTS.TCM.ReproSteps';
const REPORT_CONTENT_TYPE = 'application/vnd.qualor.report+json';
/** The bench Qualor's project of this item on Services (seed-qualor.mjs --boards; Server: `benchProject`): no repository, its own token. */
export const BOARDS_PROJECT_KEY = 'bench-boards';
/** The report's own analyzer and rule: an external engine, active in every built-in profile. */
export const ENGINE = 'probe31';
export const RULE = 'markup';
export const FILE = 'src/probe31.ts';
const FINDING_LINE = 3;
/** The finding's text: markup that must reach Azure as text (the description escapes it). */
export const MESSAGE =
  'Qualor probe item 31: <script>alert("31")</script> & <b>\'bold\'</b> <img src=x onerror=alert(31)>';
/** The parts of {@link MESSAGE} whose escaped form the description must hold. */
export const MARKUP = ['<script>', '</script>', '<b>', '<img src=x'];
/** The mapping's own tag: every work item of this item carries it, and the sweep finds them by it. */
export const TAG = 'probe31';
/** The tag the second PUT adds: a change, so the PUT pulls the connection's pass forward. */
export const STATE_TAG = 'probe31-state';
/** The type the item maps: a Bug of the Agile probe project, with Repro Steps. */
const TYPE_NAME = 'Bug';
const ANALYSIS_WAIT_MS = 3 * 60_000;
/** The brief: the link is created within 3 minutes. */
const CREATE_WAIT_MS = 3 * 60_000;
/** The brief: Qualor reads the new state within 3 minutes of the PUT. */
const STATE_WAIT_MS = 3 * 60_000;
/** Map, request, created, tags, reference line, Hyperlink, escaping, Repro Steps, state set, state read, dismiss. */
const ALL_CHECKS = 11;
/** The tags of Qualor's description (server/src/boards/content.ts) and the ones Azure wraps text in. */
const OWN_TAGS = new Set(['h3', 'pre', 'p', 'code', 'a', 'br', 'div', 'span']);

// ---------------------------------------------------------------------------------------------
// Pure helpers (unit-tested)

/**
 * The report this item uploads to the bench Qualor: main of `projectKey` with one finding of the
 * item's own rule, whose text is {@link MESSAGE}. The finding's hashes are fixed, so every run
 * finds the same open issue; the revision and the date are the run's.
 */
export function boardsReport(projectKey: string, stamp: string, analysisDate: Date): Report {
  const content = `// Qualor probe item 31\nexport const probe = '<b>bold</b>';\n`;
  return {
    schemaVersion: 1,
    scanner: { name: 'qualor-probe', version: '31' },
    project: { key: projectKey, name: 'Bench boards' },
    scm: {
      provider: 'none',
      revision: createHash('sha1').update(`qualor-probe-31:${stamp}`).digest('hex'),
      branch: 'main',
      mainBranch: 'main',
      mergeRequest: null,
      baseline: { revision: null, kind: 'none', status: 'first_analysis' },
      renames: [],
    },
    analysisDate: analysisDate.toISOString(),
    engines: [
      {
        id: ENGINE,
        kind: 'external',
        version: '1.0.0',
        status: 'ok',
        durationMs: 1,
        rules: [
          {
            id: RULE,
            name: 'Qualor probe item 31: markup in a finding',
            defaultSeverity: 'high',
            quality: 'security',
            kind: 'issue',
          },
        ],
      },
    ],
    files: [
      {
        path: FILE,
        language: 'typescript',
        kind: 'main',
        sha256: createHash('sha256').update(content).digest('hex'),
        lines: content.split('\n').length - 1,
      },
    ],
    findings: [
      {
        engineId: ENGINE,
        ruleId: RULE,
        message: MESSAGE,
        severity: 'high',
        location: { path: FILE, startLine: FINDING_LINE },
        lineHash: hex32(`qualor-probe-31:line:${FINDING_LINE}`),
        contextHash: hex32(`qualor-probe-31:context:${FINDING_LINE}`),
      },
    ],
    duplications: [],
    warnings: [],
  };
}

/** The body of `PUT /projects/:id/boards`: the type, the roots, `tags`, no automatic rule. */
export function mappingBody(
  connectionId: string,
  azureProject: { id: string; name: string },
  referenceName: string,
  tags: string[],
): Record<string, unknown> {
  return {
    connectionId,
    azureProject: { id: azureProject.id, name: azureProject.name },
    workItemType: { referenceName },
    areaPath: null,
    iterationPath: null,
    tags,
    autoCreate: { minSeverity: null, exploited: false },
  };
}

/** The text of the last `<p>` of an HTML field, tags removed and trimmed; null without one. */
export function lastParagraph(html: string): string | null {
  const paragraphs = [...html.matchAll(/<p\b[^>]*>([\s\S]*?)<\/p>/gi)];
  const last = paragraphs.at(-1)?.[1];
  return last === undefined ? null : last.replace(/<[^>]*>/g, '').trim();
}

/**
 * The reference line when it is the last paragraph (`Qualor reference: qualor-<32 hex>-<n>`; Azure
 * adds a space before `</p>`): the key, the link id in it (32 hex) and the generation.
 */
export function referenceOf(
  html: string,
): { key: string; linkHex: string; generation: number } | null {
  const m = /^Qualor reference: (qualor-([0-9a-f]{32})-(\d+))$/.exec(lastParagraph(html) ?? '');
  if (!m?.[1] || !m[2] || !m[3]) return null;
  return { key: m[1], linkHex: m[2], generation: Number(m[3]) };
}

/** The tags of an HTML field that neither Qualor's description nor Azure's wrapping uses. */
export function strayTags(html: string): string[] {
  const names = [...html.matchAll(/<\/?([a-zA-Z][a-zA-Z0-9-]*)/g)].map((m) =>
    (m[1] ?? '').toLowerCase(),
  );
  return [...new Set(names.filter((n) => !OWN_TAGS.has(n)))];
}

/** The parts of {@link MARKUP} whose escaped form an HTML field does not hold. */
export function unescapedMarkup(html: string): string[] {
  return MARKUP.filter((m) => !html.includes(escapeHtml(m)));
}

/** The URL of a Hyperlink relation that ends in `path`; undefined when there is none. */
export function hyperlinkTo(
  relations: readonly { rel: string; url: string }[] | null | undefined,
  path: string,
): string | undefined {
  return (relations ?? []).find((r) => r.rel === 'Hyperlink' && r.url.endsWith(path))?.url;
}

/**
 * The state to set: the first of the type's states in the InProgress category other than the
 * current one; else the first that is not current, Completed or Removed. Undefined when none is left.
 */
export function targetState(
  states: readonly { name: string; category?: string | undefined }[],
  current: string,
): string | undefined {
  const other = states.filter((s) => s.name.toLowerCase() !== current.toLowerCase());
  return (
    other.find((s) => s.category === 'InProgress') ??
    other.find((s) => s.category !== 'Completed' && s.category !== 'Removed')
  )?.name;
}

/** Whether `url` is the work item's web page: `<organisation or collection URL>/<project GUID>/_workitems/edit/<id>`. */
export function isWorkItemUrl(
  url: string | null | undefined,
  scmUrl: string,
  azureProjectId: string,
  workItemId: number,
): boolean {
  const want = `${scmUrl.replace(/\/+$/, '')}/${azureProjectId}/_workitems/edit/${workItemId}`;
  return typeof url === 'string' && url.toLowerCase() === want.toLowerCase();
}

// ---------------------------------------------------------------------------------------------
// Shapes

const NamedItems = z.object({ items: z.array(z.object({ id: z.string(), name: z.string() })) });
const TypeItems = z.object({
  items: z.array(
    z.object({ referenceName: z.string(), name: z.string(), supported: z.boolean() }).loose(),
  ),
});
const BoardsLinkSchema = z
  .object({
    id: z.string(),
    state: z.string(),
    workItemId: z.number().nullable(),
    url: z.string().nullable(),
    workItemState: z.object({ name: z.string(), category: z.string().nullable() }).nullable(),
    failure: z.object({ code: z.string(), message: z.string() }).nullable(),
  })
  .loose();
type BoardsLink = z.infer<typeof BoardsLinkSchema>;
const IssueSchema = z
  .object({
    id: z.string(),
    status: z.string(),
    message: z.string(),
    boards: BoardsLinkSchema.nullable(),
    boardsLinkable: z.boolean(),
  })
  .loose();
type Issue = z.infer<typeof IssueSchema>;
const MappingAnswer = z
  .object({
    mapping: z
      .object({
        azureProject: z.object({ id: z.string() }).loose(),
        workItemType: z.object({ referenceName: z.string(), name: z.string() }),
        tags: z.array(z.string()),
      })
      .loose()
      .nullable(),
  })
  .loose();
const LinksAnswer = z.object({
  items: z.array(
    z.object({ link: BoardsLinkSchema.nullable(), skipped: z.string().nullable() }).loose(),
  ),
});
const AnalysisSchema = z
  .object({
    status: z.string(),
    branch: z.object({ id: z.string(), name: z.string() }).loose().nullable(),
    error: z.object({ code: z.string(), message: z.string() }).loose().nullable(),
  })
  .loose();
const WorkItemSchema = z.object({
  id: z.number(),
  fields: z.record(z.string(), z.unknown()),
  relations: z.array(z.object({ rel: z.string(), url: z.string() }).loose()).nullish(),
});
const StatesSchema = z.object({
  value: z.array(z.object({ name: z.string(), category: z.string().optional() }).loose()),
});

const str = (v: unknown): string => (typeof v === 'string' ? v : '');
const fieldsOf = (res: AzureResponse): Record<string, unknown> =>
  (res.json as { fields?: Record<string, unknown> } | null)?.fields ?? {};
const seconds = (since: number): number => Math.round((Date.now() - since) / 1000);

// ---------------------------------------------------------------------------------------------
// The bench Qualor

/** Uploads a report with the project's analysis token, as a pipeline does; the analysis id. */
async function uploadReport(
  qualorUrl: string,
  token: string,
  projectKey: string,
  report: Report,
): Promise<string> {
  const res = await fetch(
    `${qualorUrl}/api/v0/analyses?projectKey=${encodeURIComponent(projectKey)}`,
    {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${token}`,
        'Content-Type': REPORT_CONTENT_TYPE,
        'Content-Encoding': 'gzip',
      },
      body: gzipSync(Buffer.from(JSON.stringify(report), 'utf8')),
      signal: AbortSignal.timeout(60_000),
    },
  );
  const text = await res.text();
  let json: unknown = null;
  try {
    json = JSON.parse(text) as unknown;
  } catch {
    // a proxy's page: the status says enough
  }
  if (res.status !== 202) {
    throw new Error(
      `the report upload answered HTTP ${res.status} ${problemText(json)} (run seed-qualor.mjs --boards: project ${projectKey} and its token)`,
    );
  }
  return shape(z.object({ analysisId: z.string() }).loose(), json, 'report upload').analysisId;
}

async function readIssue(api: QualorApi, id: string): Promise<Issue> {
  return shape(IssueSchema, (await api.call('GET', `/api/v0/issues/${id}`)).json, 'issue');
}

/** Dismisses a Boards link: 204, also for one dismissed before. */
async function dismissLink(api: QualorApi, id: string): Promise<void> {
  const res = await api.send('DELETE', `/api/v0/boards-links/${id}`);
  if (res.status !== 204) throw new Error(`dismiss: HTTP ${res.status} ${problemText(res.json)}`);
}

const linkText = (l: BoardsLink | null): string =>
  l === null
    ? 'no link'
    : `${l.state}${l.workItemId === null ? '' : ` work item ${l.workItemId}`}${
        l.failure ? `: ${l.failure.code} ${l.failure.message.slice(0, 300)}` : ''
      }`;

// ---------------------------------------------------------------------------------------------
// Azure DevOps

const witPath = (projectId: string, rest: string): string => `/${projectId}/_apis/wit${rest}`;

async function readWorkItem(ctx: ProbeContext, projectId: string, id: number) {
  const res = ok(
    await ctx.bot.request('GET', witPath(projectId, `/workitems/${id}?$expand=relations`)),
    `work item ${id}`,
  );
  return { res, item: shape(WorkItemSchema, res.json, 'work item') };
}

/**
 * Deletes a work item (Qualor's service principal made it; the probe's identity deletes it). A 404
 * is done; a refused delete falls back to the state Removed.
 */
async function deleteWorkItem(ctx: ProbeContext, projectId: string, id: number): Promise<void> {
  const del = await ctx.bot.request('DELETE', witPath(projectId, `/workitems/${id}`));
  if (del.status < 300 || del.status === 404) return;
  const removed = await ctx.bot.request(
    'PATCH',
    witPath(projectId, `/workitems/${id}`),
    [{ op: 'add', path: '/fields/System.State', value: 'Removed' }],
    { contentType: PATCH_JSON },
  );
  if (removed.status >= 300) {
    throw new Error(`delete answered HTTP ${del.status}; Removed answered HTTP ${removed.status}`);
  }
}

/** Deletes every work item of the project tagged {@link TAG} (this item's, of any run); their ids. */
async function sweep(ctx: ProbeContext, projectId: string): Promise<number[]> {
  const res = ok(
    await ctx.bot.request('POST', witPath(projectId, '/wiql'), {
      query: `SELECT [System.Id] FROM WorkItems WHERE [System.TeamProject] = @project AND [System.Tags] CONTAINS '${TAG}'`,
    }),
    `work items tagged ${TAG}`,
  );
  const ids = wiqlIds(res.json);
  for (const id of ids) await deleteWorkItem(ctx, projectId, id);
  return ids;
}

// ---------------------------------------------------------------------------------------------

export const item: ProbeItem = {
  id: 31,
  title:
    'Azure Boards end to end on Azure DevOps: the bench Qualor maps a project, creates a work item for an issue, reads its state, and the link is dismissed',
  async run(ctx) {
    // The bench Qualor's boards project and connection of the target (Server: bench-server-boards).
    const bench = benchProject(ctx.target, 'boards');
    const qualorUrl = needEnv('AZURE_PROBE_QUALOR_URL').replace(/\/+$/, '');
    const adminPassword = needEnv('AZURE_PROBE_QUALOR_ADMIN_PASSWORD');
    const scmUrl = benchScmUrl(ctx.target);
    const boardsToken = needEnv(bench.tokenEnv);
    const projectKey = bench.key;
    const checks: Check[] = [];
    const notes: string[] = [];
    const finish = () => done(ctx, checks, notes, projectKey);

    // The work item is Qualor's, made as its identity (the service principal; Server: the PAT's
    // owner): its names join the redaction table before anything is recorded.
    await qualorIdentityId(ctx);

    // ---- The bench Qualor: organisation `bench`, its Azure connection, the item's project.
    const api = new QualorApi(qualorUrl);
    await api.login(adminPassword);
    const org = (
      await api.items(
        '/api/v0/organizations',
        z.object({ id: z.string(), key: z.string() }).loose(),
      )
    ).find((o) => o.key === BENCH_ORG);
    if (!org) throw new Error('the bench Qualor has no organisation `bench` (run seed-qualor.mjs)');
    const connection = (
      await api.items(
        `/api/v0/scm-connections?organizationId=${org.id}`,
        z.object({ id: z.string(), provider: z.string(), baseUrl: z.string() }).loose(),
      )
    ).find((c) => c.provider === 'azure' && c.baseUrl.replace(/\/+$/, '') === scmUrl);
    if (!connection)
      throw new Error('the bench Qualor has no Azure DevOps connection (run seed-qualor.mjs)');
    const project = (
      await api.items(
        `/api/v0/projects?organizationId=${org.id}`,
        z.object({ id: z.string(), key: z.string() }).loose(),
      )
    ).find((p) => p.key === projectKey);
    if (!project) {
      throw new Error(
        `the bench Qualor has no project ${projectKey} (run seed-qualor.mjs --boards)`,
      );
    }

    // ---- The probe project and the Bug type, as Qualor's pickers list them.
    const boardsBase = `/api/v0/projects/${project.id}/boards`;
    const azureProjects = shape(
      NamedItems,
      (await api.call('GET', `${boardsBase}/projects?connection=${connection.id}`)).json,
      'Boards projects',
    ).items;
    const azureProject = azureProjects.find(
      (p) => p.name.toLowerCase() === ctx.project.toLowerCase(),
    );
    if (!azureProject) {
      throw new Error(
        `Qualor's project picker does not list the probe project (${azureProjects.length} listed)`,
      );
    }
    const types = shape(
      TypeItems,
      (
        await api.call(
          'GET',
          `${boardsBase}/work-item-types?connection=${connection.id}&azureProject=${azureProject.id}`,
        )
      ).json,
      'work item types',
    ).items;
    const bug = types.find((t) => t.name === TYPE_NAME);
    notes.push(
      `pickers: ${azureProjects.length} Azure project(s), the probe project among them; ${types.length} type(s), ${TYPE_NAME} ${bug ? (bug.supported ? 'supported' : 'NOT supported') : 'not listed'}`,
    );

    // ---- The open issue: this run's report of main, one finding with markup in its text.
    const analysisId = await uploadReport(
      qualorUrl,
      boardsToken,
      projectKey,
      boardsReport(projectKey, ctx.stamp, new Date()),
    );
    const analysed = await waitFor(
      async () => {
        const a = shape(
          AnalysisSchema,
          (await api.call('GET', `/api/v0/analyses/${analysisId}`)).json,
          'analysis',
        );
        return a.status === 'succeeded' || a.status === 'failed' ? a : undefined;
      },
      { timeoutMs: ANALYSIS_WAIT_MS, intervalMs: 3000 },
    );
    if (analysed?.status !== 'succeeded' || !analysed.branch) {
      checks.push(
        check(
          'Qualor analyses the report of main',
          false,
          analysed
            ? `${analysed.status}${analysed.error ? `: ${analysed.error.code} ${analysed.error.message.slice(0, 200)}` : ''}`
            : `not done within ${ANALYSIS_WAIT_MS / 60000} minutes`,
        ),
      );
      return finish();
    }
    const found = (
      await api.items(
        `/api/v0/issues?branchId=${analysed.branch.id}&status=open&engine=${ENGINE}`,
        IssueSchema,
      )
    ).find((i) => i.message === MESSAGE);
    if (!found) {
      checks.push(
        check('the report opens an issue on main', false, 'no open issue with the message'),
      );
      return finish();
    }
    const issueId = found.id;
    notes.push(
      `issue open on ${analysed.branch.name}; boardsLinkable before the mapping: ${found.boardsLinkable}`,
    );
    if (!bug?.supported) {
      checks.push(
        check(
          `the probe project's ${TYPE_NAME} can be mapped`,
          false,
          bug ? 'Qualor says it is not supported' : 'not listed',
        ),
      );
      return finish();
    }

    // ---- What an earlier run left: a live link (dismissed, so the request makes a new work
    // item) and work items tagged probe31.
    if (found.boards) {
      await dismissLink(api, found.boards.id);
      notes.push(`an earlier run's link (${found.boards.state}) dismissed first`);
    }
    const swept = await sweep(ctx, azureProject.id);
    if (swept.length > 0)
      notes.push(`${swept.length} earlier work item(s) tagged ${TAG} deleted first`);

    // Clean-up, registered before the calls it undoes (it runs newest first): the mapping goes
    // last, the tagged work items before it.
    ctx.cleanup.add('remove the Boards mapping of the bench project', async () => {
      const res = await api.send('DELETE', boardsBase);
      if (res.status !== 204 && res.status !== 404) {
        throw new Error(`HTTP ${res.status} ${problemText(res.json)}`);
      }
    });
    ctx.cleanup.add(`delete the work items tagged ${TAG}`, () => sweep(ctx, azureProject.id));
    ctx.verifications.push({
      label: 'the Boards mapping',
      check: async () => {
        const got = shape(MappingAnswer, (await api.call('GET', boardsBase)).json, 'mapping');
        return got.mapping === null
          ? { ok: true, text: 'the bench project has no Boards mapping' }
          : { ok: false, text: 'the bench project still has a Boards mapping' };
      },
    });

    // ---- 1. Map the bench project to the probe project, type Bug.
    const put = await api.send(
      'PUT',
      boardsBase,
      mappingBody(connection.id, azureProject, bug.referenceName, [TAG]),
    );
    const mapping = put.status === 200 ? MappingAnswer.safeParse(put.json).data?.mapping : null;
    checks.push(
      check(
        `the bench project is mapped to the probe project, type ${TYPE_NAME} (PUT …/boards)`,
        mapping?.workItemType.name === TYPE_NAME &&
          mapping.azureProject.id.toLowerCase() === azureProject.id.toLowerCase() &&
          mapping.tags.join() === TAG,
        put.status === 200
          ? `HTTP 200; type ${mapping?.workItemType.name ?? '?'}, tags ${mapping?.tags.join(', ') ?? '?'}`
          : `HTTP ${put.status} ${problemText(put.json)}`,
      ),
    );
    if (!mapping) return finish();

    // ---- 2. Request a work item for the issue; the create run makes it.
    let workItemId: number | undefined;
    ctx.cleanup.add('dismiss the link and delete its work item', async () => {
      const now = await readIssue(api, issueId);
      if (now.boards) {
        workItemId ??= now.boards.workItemId ?? undefined;
        await dismissLink(api, now.boards.id);
      }
      if (workItemId !== undefined) await deleteWorkItem(ctx, azureProject.id, workItemId);
    });
    const linkable = (await readIssue(api, issueId)).boardsLinkable;
    const posted = await api.send('POST', `${boardsBase}/links`, { issueIds: [issueId] });
    const answered = posted.status === 202 ? LinksAnswer.safeParse(posted.json).data : undefined;
    const link = answered?.items[0]?.link ?? null;
    checks.push(
      check(
        'a work item is requested for the open issue (POST …/boards/links answers 202 with a pending link)',
        posted.status === 202 && link?.state === 'pending',
        posted.status === 202
          ? link
            ? `link ${link.state}`
            : `skipped ${answered?.items[0]?.skipped ?? '?'}`
          : `HTTP ${posted.status} ${problemText(posted.json)}`,
      ),
    );
    notes.push(`boardsLinkable once mapped: ${linkable}`);
    if (!link) return finish();
    ctx.log(`link requested; waiting up to ${CREATE_WAIT_MS / 60000} min for the work item`);
    const requestedAt = Date.now();
    const settled = await waitFor(
      async () => {
        const now = await readIssue(api, issueId);
        return now.boards && now.boards.state !== 'pending' ? now : undefined;
      },
      { timeoutMs: CREATE_WAIT_MS, intervalMs: 5000 },
    );
    const createdLink = (settled ?? (await readIssue(api, issueId))).boards;
    if (typeof createdLink?.workItemId === 'number') workItemId = createdLink.workItemId;
    const madeId = workItemId;
    checks.push(
      check(
        'Qualor creates the work item within 3 minutes: the link is created, with the work item id and its web URL',
        createdLink?.state === 'created' &&
          madeId !== undefined &&
          isWorkItemUrl(createdLink.url, scmUrl, azureProject.id, madeId),
        `${linkText(createdLink)}${settled ? ` after ${seconds(requestedAt)} s` : ` after ${CREATE_WAIT_MS / 60000} minutes`}; url ${
          madeId !== undefined && isWorkItemUrl(createdLink?.url, scmUrl, azureProject.id, madeId)
            ? "is the work item's web page"
            : createdLink?.url
              ? 'is another address'
              : 'absent'
        }`,
      ),
    );
    if (createdLink?.state !== 'created' || madeId === undefined) return finish();
    ctx.verifications.push({
      label: `work item ${madeId}`,
      check: async () => {
        const res = await ctx.bot.request('GET', witPath(azureProject.id, `/workitems/${madeId}`));
        const state = str(fieldsOf(res)['System.State']);
        return res.status === 404 || (res.status === 200 && state === 'Removed')
          ? {
              ok: true,
              text: `work item ${madeId} is deleted (HTTP ${res.status}${state ? `, ${state}` : ''})`,
            }
          : {
              ok: false,
              text: `work item ${madeId} is still there (HTTP ${res.status}, ${state || 'no state'})`,
            };
      },
    });

    // ---- 3. The work item as Azure holds it.
    const read = await readWorkItem(ctx, azureProject.id, madeId);
    await rec(ctx, 'work-item', answerOf(read.res));
    const fields = read.item.fields;
    const description = str(fields['System.Description']);
    const tags = tagsOf(fields['System.Tags']);
    checks.push(
      check(
        "the tag qualor, and the mapping's tag",
        tags.includes('qualor') && tags.includes(TAG),
        `tags ${tags.join(', ') || 'none'}`,
      ),
    );
    const linkHex = link.id.replaceAll('-', '').toLowerCase();
    const ref = referenceOf(description);
    checks.push(
      check(
        "the description's last paragraph is the reference line of this link",
        ref?.linkHex === linkHex,
        ref
          ? `${ref.key} (${ref.linkHex === linkHex ? 'this link' : 'ANOTHER link'}, generation ${ref.generation})`
          : `last paragraph: ${(lastParagraph(description) ?? 'none').slice(0, 120)}`,
      ),
    );
    const issuePath = `/projects/${project.id}/issues/${issueId}`;
    const hyperlink = hyperlinkTo(read.item.relations, issuePath);
    checks.push(
      check(
        'a Hyperlink relation to the issue in Qualor',
        hyperlink !== undefined,
        hyperlink
          ? `to the issue page${hyperlink === `${qualorUrl}${issuePath}` ? ' on the bench Qualor' : ' on another origin (QUALOR_PUBLIC_URL differs from AZURE_PROBE_QUALOR_URL)'}`
          : `relations ${(read.item.relations ?? []).map((r) => r.rel).join(', ') || 'none'}: none to the issue (QUALOR_PUBLIC_URL unset?)`,
      ),
    );
    const stray = strayTags(description);
    const unescaped = unescapedMarkup(description);
    checks.push(
      check(
        "the finding's text is escaped: no markup of its own in the description",
        stray.length === 0 && unescaped.length === 0,
        `${stray.length > 0 ? `stray tags ${stray.join(', ')}` : 'no stray tag'}; ${
          unescaped.length > 0
            ? `not found escaped: ${unescaped.join(' ')}`
            : 'its markup reads back escaped'
        }`,
      ),
    );
    const repro = str(fields[REPRO]);
    const reproRef = referenceOf(repro);
    checks.push(
      check(
        `Repro Steps (a ${TYPE_NAME}) holds the description: the reference line, the text escaped`,
        reproRef?.linkHex === linkHex &&
          strayTags(repro).length === 0 &&
          unescapedMarkup(repro).length === 0,
        repro === ''
          ? 'Repro Steps is empty'
          : `reference ${reproRef ? (reproRef.linkHex === linkHex ? 'of this link' : 'of ANOTHER link') : 'absent'}; stray tags ${strayTags(repro).join(', ') || 'none'}; ${unescapedMarkup(repro).length > 0 ? 'markup not escaped' : 'markup escaped'}`,
      ),
    );
    notes.push(
      `title ${str(fields['System.Title']) === MESSAGE ? "is the finding's text as it is" : `differs from the finding's text (${str(fields['System.Title']).length} characters)`}; type ${str(fields['System.WorkItemType'])}, state ${str(fields['System.State'])}`,
    );

    // ---- 4. A state set in Azure; a mapping PUT pulls the pass forward; Qualor reads the state.
    const current = str(fields['System.State']);
    const statesRes = ok(
      await ctx.bot.request(
        'GET',
        witPath(
          azureProject.id,
          `/workitemtypes/${encodeURIComponent(str(fields['System.WorkItemType']) || TYPE_NAME)}/states`,
        ),
      ),
      'type states',
    );
    await rec(ctx, 'type-states', answerOf(statesRes));
    const target = targetState(shape(StatesSchema, statesRes.json, 'type states').value, current);
    if (!target) {
      checks.push(check('a state to set in Azure', false, `none besides ${current}`));
      return finish();
    }
    const patch = await ctx.bot.request(
      'PATCH',
      witPath(azureProject.id, `/workitems/${madeId}`),
      [{ op: 'add', path: '/fields/System.State', value: target }],
      { contentType: PATCH_JSON },
    );
    await rec(ctx, 'state-patch', answerOf(patch));
    const patched = str(fieldsOf(patch)['System.State']);
    checks.push(
      check(
        `Azure takes the state ${target} (from ${current})`,
        patch.status === 200 && patched === target,
        patch.status < 300
          ? `HTTP ${patch.status}, state ${patched}`
          : describeAnswer(patch.status, patch.json),
      ),
    );
    if (patch.status >= 300) return finish();
    const again = await api.send(
      'PUT',
      boardsBase,
      mappingBody(connection.id, azureProject, bug.referenceName, [TAG, STATE_TAG]),
    );
    ctx.log(`state ${target} set; waiting up to ${STATE_WAIT_MS / 60000} min for Qualor's pass`);
    const pulledAt = Date.now();
    const seen = await waitFor(
      async () => {
        const now = await readIssue(api, issueId);
        return now.boards?.workItemState?.name.toLowerCase() === target.toLowerCase()
          ? now
          : undefined;
      },
      { timeoutMs: STATE_WAIT_MS, intervalMs: 5000 },
    );
    const stateNow = (seen ?? (await readIssue(api, issueId))).boards?.workItemState ?? null;
    checks.push(
      check(
        `Qualor reads the state ${target} within 3 minutes of a mapping PUT that pulled its pass forward`,
        again.status === 200 && seen !== undefined,
        `PUT with tag ${STATE_TAG} added: HTTP ${again.status}${again.status === 200 ? '' : ` ${problemText(again.json)}`}; ${
          seen ? `read after ${seconds(pulledAt)} s` : `not within ${STATE_WAIT_MS / 60000} minutes`
        }; workItemState ${stateNow ? `${stateNow.name} (${stateNow.category ?? 'no category'})` : 'none'}`,
      ),
    );

    // ---- 5. Dismiss the link; the work item stays in Azure until the clean-up.
    const dismissed = await api.send('DELETE', `/api/v0/boards-links/${link.id}`);
    const afterDismiss = await readIssue(api, issueId);
    const still = await ctx.bot.request('GET', witPath(azureProject.id, `/workitems/${madeId}`));
    checks.push(
      check(
        'the link is dismissed: DELETE answers 204, the issue shows no link, the work item stays in Azure',
        dismissed.status === 204 && afterDismiss.boards === null && still.status === 200,
        `DELETE HTTP ${dismissed.status}; the issue shows ${linkText(afterDismiss.boards)}, boardsLinkable ${afterDismiss.boardsLinkable}; the work item answers HTTP ${still.status}`,
      ),
    );
    return finish();
  },
};

function done(ctx: ProbeContext, checks: Check[], notes: string[], projectKey: string) {
  for (const c of checks) ctx.log(`${c.pass ? 'yes' : 'NO '} ${c.what}: ${c.got}`);
  const pass = checks.length >= ALL_CHECKS && checks.every((c) => c.pass);
  const detail = [
    `Qualor project ${projectKey}, mapped to the probe project for the run`,
    ...checks.map((c) => `${c.pass ? 'yes' : 'NO'} - ${c.what}: ${c.got}`),
    ...notes.map((n) => `note: ${String(redact(n, ctx.redaction))}`),
  ].join('\n\n');
  return Promise.resolve(result(ctx, pass ? 'yes' : 'no', detail));
}
