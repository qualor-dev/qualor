import { z } from 'zod';
import type { AzureResponse } from '../client.js';
import { CONNECTION_DATA_VERSION } from './01-identity.js';
import { corpus } from './11-markdown-corpus.js';
import {
  answerOf,
  ConnectionDataSchema,
  InterruptedError,
  ok,
  result,
  shape,
  sleep,
  type ProbeContext,
  type ProbeItem,
} from './common.js';

const PATCH_JSON = 'application/json-patch+json';
const COMMENTS_VERSION = '7.0-preview.3';
const REPRO = 'Microsoft.VSTS.TCM.ReproSteps';
const LINK = 'https://qualor.example.invalid/issues/probe-30';
/** Longest corpus value written (in code points); the long cases are about length, not markup. */
const CASE_MAX = 200;
/** Sub-step e's description: 1.5 MiB of text, over a 1 MiB field limit and under the 8 MiB cap. */
const BIG_DESCRIPTION_BYTES = 1.5 * 1024 * 1024;
/** A work item id no organisation reaches. */
const NEVER_ID = 999_999_999;
/** A project GUID that does not exist. */
const NO_PROJECT = '00000000-0000-4000-8000-000000000030';
/** Strings longer than this are cut in recordings (an echoed 1.5 MiB description). */
const RECORD_STRING_MAX = 60_000;
const WIQL_POLL_MS = 2_000;
const WIQL_WAIT_MS = 120_000;
const BATCH_FIELDS = ['System.State', 'System.TeamProject', 'System.WorkItemType', 'System.Tags'];

export type Form = 'pre' | 'code' | 'plain';
export const FORMS: readonly Form[] = ['pre', 'code', 'plain'];
export type Case = { n: number; name: string; value: string };
type Op = { op: 'add' | 'replace' | 'test'; path: string; value: unknown };
type Project = { id: string; name: string };

// ---------------------------------------------------------------------------------------------
// Pure helpers (unit-tested)

/** The escaping Task 4 applies to every analyzer text: `& < > " '`. */
export function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * A classification node's `path` (`\Project\Area\A\B`) in the form the work item fields take
 * (`Project\A\B`): the leading backslash and the structure segment (`Area`, `Iteration`) go.
 */
export function fieldPath(nodePath: string): string {
  const parts = nodePath.replace(/^\\+/, '').split('\\');
  return [parts[0] ?? '', ...parts.slice(2)].join('\\');
}

/** Every `path` of a classification node tree, the root first, depth first. */
export function nodePaths(node: unknown): string[] {
  if (!node || typeof node !== 'object') return [];
  const n = node as { path?: unknown; children?: unknown };
  const own = typeof n.path === 'string' ? [n.path] : [];
  const kids = Array.isArray(n.children) ? n.children.flatMap((c) => nodePaths(c)) : [];
  return [...own, ...kids];
}

/** The status, `typeKey` and message of an answer (the message cut to 300 characters). */
export function errorFacts(
  status: number,
  json: unknown,
): { status: number; typeKey: string; message: string } {
  const body = json && typeof json === 'object' ? (json as Record<string, unknown>) : {};
  const typeKey = typeof body['typeKey'] === 'string' ? body['typeKey'] : 'none';
  const message =
    typeof body['message'] === 'string'
      ? body['message'].slice(0, 300)
      : typeof json === 'string'
        ? json.slice(0, 200)
        : '';
  return { status, typeKey, message };
}

/** The keys of an answer, two levels deep, at most 12 per object: the answer's shape in a line. */
export function shapeOf(json: unknown, depth = 2): string {
  if (Array.isArray(json)) {
    const first: unknown = json.find((v) => v !== null);
    return json.length === 0 ? '[]' : `[${shapeOf(first, depth)}]`;
  }
  if (json && typeof json === 'object') {
    if (depth <= 0) return '{…}';
    const entries = Object.entries(json);
    const keys = entries
      .slice(0, 12)
      .map(([k, v]) => (v && typeof v === 'object' ? `${k}:${shapeOf(v, depth - 1)}` : k));
    return `{${keys.join(',')}${entries.length > 12 ? ',…' : ''}}`;
  }
  return json === null ? 'null' : typeof json;
}

/** `HTTP 200 {shape}` for a success; `HTTP 400 typeKey: message` for a refusal. */
export function describeAnswer(status: number, json: unknown): string {
  if (status >= 200 && status < 300) return `HTTP ${status} ${shapeOf(json)}`;
  const f = errorFacts(status, json);
  return `HTTP ${status} ${f.typeKey}${f.message ? `: ${f.message}` : ''}`;
}

/** A copy of `value` with every string longer than `max` cut to its start and its length. */
export function trimLong(value: unknown, max: number): unknown {
  if (typeof value === 'string') {
    return value.length > max
      ? `${value.slice(0, 200)}… [cut by the probe: ${value.length} characters]`
      : value;
  }
  if (Array.isArray(value)) return value.map((v) => trimLong(v, max));
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, trimLong(v, max)]));
  }
  return value;
}

/** True for text XML 1.0 cannot hold: C0 controls but tab, LF and CR; lone surrogates; U+FFFE/F. */
export function xmlUnsafe(value: string): boolean {
  // eslint-disable-next-line no-control-regex
  return /[\u0000-\u0008\u000b\u000c\u000e-\u001f￾￿]|[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/.test(
    value,
  );
}

/** The item-11 corpus, numbered from 1, each value cut to `max` code points. */
export function corpusCases(userId: string, max = CASE_MAX): Case[] {
  return corpus(userId).map(([name, value], i) => ({
    n: i + 1,
    name,
    value: Array.from(value).slice(0, max).join(''),
  }));
}

const pad = (n: number): string => String(n).padStart(2, '0');

/** One case in one form, after a marker paragraph `QCASE-<nn>-<form>` that the read-back splits on. */
export function caseBlock(c: Case, form: Form): string {
  const marker = `<p>QCASE-${pad(c.n)}-${form}</p>`;
  const body = escapeHtml(c.value);
  if (form === 'pre') return `${marker}<pre>${body}</pre>`;
  if (form === 'code') return `${marker}<p><code>${body}</code></p>`;
  return `${marker}<p>${body}</p>`;
}

/** The cases in the given forms, case by case. */
export function renderingHtml(cases: readonly Case[], forms: readonly Form[]): string {
  return cases.flatMap((c) => forms.map((f) => caseBlock(c, f))).join('');
}

export type CaseFinding = {
  n: number;
  form: Form;
  link: boolean;
  mention: boolean;
  image: boolean;
  /** Any element besides the ones the probe wrote or a server wraps text in. */
  markup: boolean;
};

const PLAIN_TAGS = new Set(['p', 'pre', 'code', 'br', 'div', 'span']);

/** What each marked case of a stored or rendered field turned into. */
export function caseFindings(html: string): CaseFinding[] {
  const re = /QCASE-(\d+)-(pre|code|plain)/g;
  const marks = [...html.matchAll(re)];
  return marks.map((m, i) => {
    const start = (m.index ?? 0) + m[0].length;
    const end = marks[i + 1]?.index ?? html.length;
    const seg = html.slice(start, end);
    const tags = [...seg.matchAll(/<\/?([a-zA-Z][a-zA-Z0-9-]*)/g)].map((t) =>
      (t[1] ?? '').toLowerCase(),
    );
    return {
      n: Number(m[1]),
      form: m[2] as Form,
      link: /<a[\s>]/i.test(seg),
      mention: /<[^>]*data-vss-mention/i.test(seg),
      image: /<img[\s>/]/i.test(seg),
      markup: tags.some((t) => !PLAIN_TAGS.has(t)),
    };
  });
}

/** `cases with findings` as `n form:kind+kind`, or none. */
export function findingsLine(findings: readonly CaseFinding[]): string {
  const hits = findings
    .map((f) => {
      const kinds = [
        f.link ? 'link' : '',
        f.mention ? 'mention' : '',
        f.image ? 'image' : '',
        f.markup ? 'markup' : '',
      ].filter(Boolean);
      return kinds.length ? `${f.n} ${f.form}:${kinds.join('+')}` : '';
    })
    .filter(Boolean);
  return hits.length ? hits.join(', ') : 'none';
}

/**
 * The reconciliation query of Task 7: the `qualor` tag, the creator (`@Me`, a quoted identity, or
 * none for `null`) and the creation time.
 */
export function reconcileWiql(since: string, creator: string | null = '@Me'): string {
  const who =
    creator === null
      ? ''
      : ` AND [System.CreatedBy] = ${creator === '@Me' ? '@Me' : `'${creator.replace(/'/g, "''")}'`}`;
  return (
    "SELECT [System.Id] FROM WorkItems WHERE [System.TeamProject] = @project AND [System.Tags] CONTAINS 'qualor'" +
    `${who} AND [System.CreatedDate] >= '${since}' ORDER BY [System.Id] DESC`
  );
}

/** The ids of a WIQL answer. */
export function wiqlIds(json: unknown): number[] {
  const parsed = z
    .object({ workItems: z.array(z.object({ id: z.number() }).loose()) })
    .safeParse(json);
  return parsed.success ? parsed.data.workItems.map((w) => w.id) : [];
}

/** The work items of a batch answer by id, and how many entries were null. */
export function batchEntries(json: unknown): {
  items: Map<number, Record<string, unknown>>;
  nulls: number;
} {
  const items = new Map<number, Record<string, unknown>>();
  let nulls = 0;
  const value =
    json && typeof json === 'object' ? (json as Record<string, unknown>)['value'] : undefined;
  for (const v of Array.isArray(value) ? value : []) {
    if (v === null) nulls++;
    else if (v && typeof v === 'object' && typeof (v as { id?: unknown }).id === 'number') {
      const entry = v as { id: number; fields?: unknown };
      const fields =
        entry.fields && typeof entry.fields === 'object'
          ? (entry.fields as Record<string, unknown>)
          : {};
      items.set(entry.id, fields);
    }
  }
  return { items, nulls };
}

/** A `System.Tags` value as its tags (Azure joins them with `; ` and reorders them). */
export function tagsOf(value: unknown): string[] {
  return typeof value === 'string'
    ? value
        .split(';')
        .map((t) => t.trim())
        .filter((t) => t.length > 0)
    : [];
}

/**
 * A tag of exactly `n` characters made of `seed-` repeats, ending in a letter. The dashes keep it
 * from looking like a secret to the recorder (no 52-character alphanumeric run).
 */
export function tagOfLength(n: number, seed: string): string {
  const text = `${seed}-`.repeat(Math.ceil(n / (seed.length + 1)) + 1);
  return `${text.slice(0, n - 1)}z`;
}

/** The names of the types a `workitemtypecategories` answer lists under `Microsoft.HiddenCategory`. */
export function hiddenTypes(json: unknown): string[] | null {
  const parsed = z
    .object({
      value: z.array(
        z
          .object({
            referenceName: z.string(),
            workItemTypes: z.array(z.object({ name: z.string() }).loose()),
          })
          .loose(),
      ),
    })
    .safeParse(json);
  if (!parsed.success) return null;
  const hidden = parsed.data.value.find((c) => c.referenceName === 'Microsoft.HiddenCategory');
  return hidden ? hidden.workItemTypes.map((t) => t.name) : null;
}

// ---------------------------------------------------------------------------------------------
// The calls

const ProjectsSchema = z.object({
  count: z.number(),
  value: z.array(z.object({ id: z.string(), name: z.string() }).loose()),
});

const NodeSchema = z
  .object({ id: z.number(), name: z.string(), path: z.string().optional() })
  .loose();

type Tracked = { id: number; project: Project };

type Env = {
  ctx: ProbeContext;
  /** `pat` or `sp`: the main identity, in every recording's name (both runs keep theirs). */
  who: 'pat' | 'sp';
  agile: Project;
  basic: Project;
  scrum: Project;
  userId: string;
  /** f's two work items: the first stays live, the second is deleted by g. */
  reconcile?: { live: Tracked; second: Tracked };
  /** h's Agile Bug, reused by i, j and k. */
  bug?: Tracked;
};

const wit = (p: Project, rest: string): string => `/${p.id}/_apis/wit${rest}`;

function rec(env: Env, call: string, value: unknown): Promise<string> {
  return env.ctx.record(`${env.who}-${call}`, trimLong(value, RECORD_STRING_MAX));
}

const describe = (res: AzureResponse): string => describeAnswer(res.status, res.json);

function idOf(res: AzureResponse): number | undefined {
  const id =
    res.json && typeof res.json === 'object' ? (res.json as { id?: unknown }).id : undefined;
  return typeof id === 'number' && id > 0 ? id : undefined;
}

function fieldsOf(res: AzureResponse): Record<string, unknown> {
  const f =
    res.json && typeof res.json === 'object'
      ? (res.json as { fields?: unknown }).fields
      : undefined;
  return f && typeof f === 'object' ? (f as Record<string, unknown>) : {};
}

const str = (v: unknown): string => (typeof v === 'string' ? v : JSON.stringify(v ?? null));

/**
 * Deletes a work item at clean-up: on its current project, then at organisation level (a moved
 * item); 404 on both is gone. A refused delete falls back to the state Removed.
 */
function track(env: Env, id: number, project: Project): Tracked {
  const t: Tracked = { id, project };
  const { ctx } = env;
  ctx.cleanup.add(`delete work item ${id}`, async () => {
    let refused: number | undefined;
    for (const p of [`/${t.project.id}/_apis/wit/workitems/${id}`, `/_apis/wit/workitems/${id}`]) {
      const del = await ctx.bot.request('DELETE', p);
      if (del.status < 300) return;
      if (del.status !== 404) {
        refused = del.status;
        break;
      }
    }
    if (refused === undefined) return;
    const removed = await ctx.bot.request(
      'PATCH',
      `/_apis/wit/workitems/${id}`,
      [{ op: 'add', path: '/fields/System.State', value: 'Removed' }],
      { contentType: PATCH_JSON },
    );
    if (removed.status >= 300) {
      throw new Error(`delete answered HTTP ${refused}; Removed answered HTTP ${removed.status}`);
    }
  });
  return t;
}

/** A create; a work item it makes (an id over 0) is deleted at clean-up whatever comes next. */
async function create(
  env: Env,
  project: Project,
  type: string,
  ops: Op[],
  opts: { query?: string; contentType?: string } = {},
): Promise<{ res: AzureResponse; tracked?: Tracked }> {
  const res = await env.ctx.bot.request(
    'POST',
    wit(project, `/workitems/$${encodeURIComponent(type)}${opts.query ?? ''}`),
    ops,
    { contentType: opts.contentType ?? PATCH_JSON },
  );
  const id = res.status < 300 ? idOf(res) : undefined;
  return id === undefined ? { res } : { res, tracked: track(env, id, project) };
}

const update = (env: Env, t: Tracked, ops: Op[], query = ''): Promise<AzureResponse> =>
  env.ctx.bot.request('PATCH', wit(t.project, `/workitems/${t.id}${query}`), ops, {
    contentType: PATCH_JSON,
  });

const title = (env: Env, label: string): Op => ({
  op: 'add',
  path: '/fields/System.Title',
  value: `Qualor probe item 30 ${label} (${env.ctx.stamp})`,
});
const field = (name: string, value: unknown): Op => ({ op: 'add', path: `/fields/${name}`, value });
const history = (value: string): Op => field('System.History', value);
const hyperlink: Op = { op: 'add', path: '/relations/-', value: { rel: 'Hyperlink', url: LINK } };

/** A plain work item for a sub-step whose usual one is missing (the step that made it failed). */
async function plainItem(env: Env, project: Project, type: string, label: string) {
  const made = await create(env, project, type, [title(env, label)]);
  ok(made.res, `create ${type} for ${label}`);
  if (!made.tracked) throw new Error(`create ${type} for ${label} answered no id`);
  return made.tracked;
}

async function wiql(env: Env, p: Project, query: string, params = ''): Promise<AzureResponse> {
  return env.ctx.bot.request('POST', wit(p, `/wiql${params}`), { query });
}

// ---------------------------------------------------------------------------------------------
// The sub-steps

type Note = (line: string) => void;

/** a. (§7.6) projects and their paging; classification nodes; the path form a create takes. */
async function stepA(env: Env, note: Note, projects: AzureResponse): Promise<void> {
  const { ctx, agile } = env;
  const listed = shape(ProjectsSchema, projects.json, 'projects');
  note(
    `projects $top=100: ${describe(projects)}; count ${listed.count}, ${listed.value.length} listed; ` +
      `x-ms-continuationtoken ${projects.headers['x-ms-continuationtoken'] ? 'present' : 'absent'}`,
  );
  const page1 = await ctx.bot.request('GET', '/_apis/projects?$top=1');
  const token = page1.headers['x-ms-continuationtoken'];
  await rec(env, 'a-projects-top1', { ...answerOf(page1), continuationToken: token ?? null });
  const page1Ids = shape(ProjectsSchema, page1.json, 'projects $top=1').value.map((p) => p.id);
  let page2Line = 'no second page asked (no token)';
  if (token) {
    const page2 = await ctx.bot.request(
      'GET',
      `/_apis/projects?$top=1&continuationToken=${encodeURIComponent(token)}`,
    );
    await rec(env, 'a-projects-page2', {
      ...answerOf(page2),
      continuationToken: page2.headers['x-ms-continuationtoken'] ?? null,
    });
    const ids = ProjectsSchema.safeParse(page2.json);
    page2Line = `continuationToken=<token> gives ${describe(page2)}, ${
      ids.success
        ? ids.data.value.some((p) => page1Ids.includes(p.id))
          ? 'the same project again'
          : 'another project'
        : 'no list'
    }`;
  }
  const skip = await ctx.bot.request('GET', '/_apis/projects?$top=1&$skip=1');
  const skipIds = ProjectsSchema.safeParse(skip.json);
  note(
    `projects $top=1: ${page1Ids.length} listed, x-ms-continuationtoken ${token ? `present (${token.length} characters)` : 'absent'}; ${page2Line}; ` +
      `$skip=1 gives ${describe(skip)}, ${skipIds.success ? `${skipIds.data.value.length} listed${skipIds.data.value.some((p) => page1Ids.includes(p.id)) ? ' (the first page again)' : ''}` : 'no list'}`,
  );

  const nodes = await ctx.bot.request('GET', wit(agile, '/classificationnodes?$depth=10'));
  await rec(env, 'a-nodes', answerOf(nodes));
  note(`classificationnodes?$depth=10: ${describe(nodes)}`);
  const areas = ok(
    await ctx.bot.request('GET', wit(agile, '/classificationnodes/areas?$depth=10')),
    'areas',
  );
  await rec(env, 'a-areas', answerOf(areas));
  const areaNode = shape(NodeSchema, areas.json, 'area root');
  const areaRoot = { id: areaNode.id, path: areaNode.path ?? `\\${agile.name}\\Area` };
  const iterations = ok(
    await ctx.bot.request('GET', wit(agile, '/classificationnodes/iterations?$depth=10')),
    'iterations',
  );
  await rec(env, 'a-iterations', answerOf(iterations));
  shape(NodeSchema, iterations.json, 'iteration root');
  const iterationPaths = nodePaths(iterations.json);
  note(
    `areas: ${describe(areas)}; root path ${areaRoot.path} (field form ${fieldPath(areaRoot.path)}); ` +
      `iterations: ${iterationPaths.length} nodes, paths ${iterationPaths.slice(0, 4).join(', ')} ` +
      `(field forms ${iterationPaths
        .slice(0, 4)
        .map((p) => fieldPath(p))
        .join(', ')})`,
  );

  const childName = `probe30-${ctx.stamp}`;
  const child = await ctx.bot.request('POST', wit(agile, '/classificationnodes/areas'), {
    name: childName,
  });
  await rec(env, 'a-area-create', answerOf(child));
  let areaNodePath = areaRoot.path;
  if (child.status < 300) {
    ctx.cleanup.add(`delete area ${childName}`, async () => {
      const del = await ctx.bot.request(
        'DELETE',
        wit(
          agile,
          `/classificationnodes/areas/${encodeURIComponent(childName)}?$reclassifyId=${areaRoot.id}`,
        ),
      );
      if (del.status < 300 || del.status === 404) return;
      throw new Error(`delete area answered ${describe(del)}`);
    });
    areaNodePath =
      shape(NodeSchema, child.json, 'new area').path ?? `${areaRoot.path}\\${childName}`;
    note(`child area create: ${describe(child)}; path ${areaNodePath}`);
  } else {
    note(`child area create: ${describe(child)}; the creates below use the root area`);
  }

  const iterationNode = iterationPaths[1] ?? iterationPaths[0] ?? `\\${agile.name}\\Iteration`;
  const areaField = fieldPath(areaNodePath);
  const iterationField = fieldPath(iterationNode);
  const made = await create(env, agile, 'Issue', [
    title(env, 'area path'),
    field('System.AreaPath', areaField),
    field('System.IterationPath', iterationField),
  ]);
  await rec(env, 'a-create', answerOf(made.res));
  const f = fieldsOf(made.res);
  note(
    `create Issue with System.AreaPath "${areaField}" and System.IterationPath "${iterationField}": ${describe(made.res)}` +
      (made.res.status < 300
        ? `; stored AreaPath "${str(f['System.AreaPath'])}", IterationPath "${str(f['System.IterationPath'])}", AreaId ${str(f['System.AreaId'])}`
        : ''),
  );
  const raw = await create(env, agile, 'Issue', [
    title(env, 'node path'),
    field('System.AreaPath', areaNodePath),
  ]);
  await rec(env, 'a-create-node-path', answerOf(raw.res));
  note(
    `create Issue with the node path "${areaNodePath}" as System.AreaPath: ${describe(raw.res)}`,
  );
}

/** b. (§7.7) the hidden category's types and the categories' shape, on each process. */
async function stepB(env: Env, note: Note): Promise<void> {
  for (const [label, p] of [
    ['agile', env.agile],
    ['basic', env.basic],
    ['scrum', env.scrum],
  ] as const) {
    const res = await env.ctx.bot.request('GET', wit(p, '/workitemtypecategories'));
    await rec(env, `b-categories-${label}`, answerOf(res));
    const hidden = hiddenTypes(res.json);
    note(
      `${label} workitemtypecategories: ${describe(res)}; Microsoft.HiddenCategory ${
        hidden ? `lists ${hidden.join(', ') || 'nothing'}` : 'absent'
      }`,
    );
  }
}

/** c. (§7.13) a JSON Patch body sent as `application/json`. */
async function stepC(env: Env, note: Note): Promise<void> {
  const made = await create(env, env.agile, 'Bug', [title(env, 'json content type')], {
    contentType: 'application/json',
  });
  await rec(env, 'c-json-content-type', answerOf(made.res));
  note(
    `create sent as application/json: ${describe(made.res)}${made.tracked ? `; it MADE work item ${made.tracked.id}` : ''}`,
  );
}

/** d. (§7.12) `validateOnly=true` with the full body, an unknown type and an unknown area path. */
async function stepD(env: Env, note: Note): Promise<void> {
  const { agile } = env;
  const titleOp = title(env, 'validateOnly');
  const full = (area: string): Op[] => [
    titleOp,
    field('System.Description', '<p>Qualor probe: description.</p>'),
    field(REPRO, '<p>Qualor probe: repro steps.</p>'),
    field('System.Tags', 'qualor; probe30'),
    field('System.AreaPath', area),
    field('System.IterationPath', agile.name),
    hyperlink,
  ];
  const v = await create(env, agile, 'Bug', full(agile.name), { query: '?validateOnly=true' });
  await rec(env, 'd-validate', answerOf(v.res));
  const rawId =
    v.res.json && typeof v.res.json === 'object' ? (v.res.json as { id?: unknown }).id : undefined;
  const found = wiqlIds(
    (
      await wiql(
        env,
        agile,
        `SELECT [System.Id] FROM WorkItems WHERE [System.TeamProject] = @project AND [System.Title] = '${String(titleOp.value)}'`,
      )
    ).json,
  );
  note(
    `validateOnly=true, full body: ${describe(v.res)}; answer id ${JSON.stringify(rawId ?? null)}, ` +
      `rev ${str(v.res.json && typeof v.res.json === 'object' ? (v.res.json as { rev?: unknown }).rev : undefined)}; ` +
      `WIQL by its title finds ${found.length} work item(s)${v.tracked ? ` (work item ${v.tracked.id} MADE)` : ''}`,
  );
  const noType = await create(env, agile, 'NoSuchType30', full(agile.name), {
    query: '?validateOnly=true',
  });
  await rec(env, 'd-validate-no-type', answerOf(noType.res));
  note(`validateOnly=true, type NoSuchType30: ${describe(noType.res)}`);
  const noArea = await create(env, agile, 'Bug', full(`${agile.name}\\no-such-area-30`), {
    query: '?validateOnly=true',
  });
  await rec(env, 'd-validate-no-area', answerOf(noArea.res));
  note(`validateOnly=true, area path <project>\\no-such-area-30: ${describe(noArea.res)}`);
}

/** e. (§7.9/§7.8) a missing required field, a long title, a big description, an unknown project. */
async function stepE(env: Env, note: Note): Promise<void> {
  const { agile } = env;
  const noTitle = await create(env, agile, 'Bug', [
    field('System.Description', '<p>Qualor probe item 30: no title.</p>'),
  ]);
  await rec(env, 'e-no-title', answerOf(noTitle.res));
  note(`create without System.Title: ${describe(noTitle.res)}`);

  const longTitle = `Qualor probe item 30 long title (${env.ctx.stamp}) `.padEnd(300, 'x');
  const long = await create(env, agile, 'Bug', [field('System.Title', longTitle)]);
  await rec(env, 'e-long-title', answerOf(long.res));
  note(
    `create with a ${longTitle.length}-character title: ${describe(long.res)}` +
      (long.res.status < 300
        ? `; stored title ${str(fieldsOf(long.res)['System.Title']).length} characters`
        : ''),
  );

  const filler = 'Qualor probe item 30 filler text. ';
  const big = `<p>${filler.repeat(Math.ceil(BIG_DESCRIPTION_BYTES / filler.length))}</p>`;
  const huge = await create(env, agile, 'Bug', [
    title(env, 'big description'),
    field('System.Description', big),
  ]);
  await rec(env, 'e-big-description', answerOf(huge.res));
  const stored = fieldsOf(huge.res)['System.Description'];
  note(
    `create with a ${(Buffer.byteLength(big) / 1024 / 1024).toFixed(2)} MiB description (${big.length} characters): ${describe(huge.res)}` +
      (huge.res.status < 300
        ? `; stored ${typeof stored === 'string' ? `${stored.length} characters` : 'no description'}`
        : ''),
  );

  const noProject = await create(env, { id: NO_PROJECT, name: 'none' }, 'Bug', [
    title(env, 'no project'),
  ]);
  await rec(env, 'e-no-project', answerOf(noProject.res));
  note(`create in a project GUID that does not exist: ${describe(noProject.res)}`);
}

/** f. (§7.3) WIQL reconciliation: lag, `@Me`, time precision, `$top`. */
async function stepF(env: Env, note: Note): Promise<void> {
  const { ctx, agile } = env;
  const began = Date.now();
  const since = new Date(began - 60_000).toISOString();
  const tags = field('System.Tags', 'qualor; probe30');
  const first = await create(env, agile, 'Issue', [title(env, 'reconcile 1'), tags]);
  await rec(env, 'f-create', answerOf(first.res));
  ok(first.res, 'reconcile create 1');
  const second = await create(env, agile, 'Issue', [title(env, 'reconcile 2'), tags]);
  ok(second.res, 'reconcile create 2');
  const answered = Date.now();
  if (!first.tracked || !second.tracked) throw new Error('a reconcile create answered no id');
  env.reconcile = { live: first.tracked, second: second.tracked };
  const ids = [first.tracked.id, second.tracked.id];
  const creator = fieldsOf(first.res)['System.CreatedBy'];

  const precise = reconcileWiql(since);
  let last: AzureResponse | undefined;
  let listedAfter: number | undefined;
  let polls = 0;
  while (Date.now() - answered <= WIQL_WAIT_MS) {
    polls++;
    last = await wiql(env, agile, precise, '?timePrecision=true');
    if (last.status >= 300) break;
    const got = wiqlIds(last.json);
    if (ids.every((id) => got.includes(id))) {
      listedAfter = Date.now() - answered;
      break;
    }
    await sleep(WIQL_POLL_MS);
  }
  if (last) await rec(env, 'f-wiql-precise', answerOf(last));
  note(
    `WIQL tag + CreatedBy = @Me + CreatedDate >= <ISO 1 min before> with timePrecision=true: ${last ? describe(last) : 'not sent'}; ` +
      (listedAfter !== undefined
        ? `both ids listed ${(listedAfter / 1000).toFixed(1)} s after the second create answered (${polls} queries)`
        : `both ids NOT listed within ${WIQL_WAIT_MS / 1000} s (${polls} queries; last listed ${last ? wiqlIds(last.json).length : 0})`),
  );

  const without = await wiql(env, agile, reconcileWiql(since, null), '?timePrecision=true');
  await rec(env, 'f-wiql-no-creator', answerOf(without));
  const withoutIds = wiqlIds(without.json);
  note(
    `the same without the CreatedBy clause: ${describe(without)}; lists both: ${ids.every((id) => withoutIds.includes(id)) ? 'yes' : 'no'}; ` +
      `so @Me ${listedAfter !== undefined ? 'matches this identity' : withoutIds.length > 0 ? 'does NOT match this identity' : 'cannot be judged (nothing listed)'}`,
  );
  if (listedAfter === undefined && creator && typeof creator === 'object') {
    const c = creator as { displayName?: unknown; uniqueName?: unknown };
    const who = `${str(c.displayName)} <${str(c.uniqueName)}>`;
    const byName = await wiql(env, agile, reconcileWiql(since, who), '?timePrecision=true');
    await rec(env, 'f-wiql-by-identity', answerOf(byName));
    const got = wiqlIds(byName.json);
    note(
      `CreatedBy = '<displayName> <uniqueName>' instead of @Me: ${describe(byName)}; lists both: ${ids.every((id) => got.includes(id)) ? 'yes' : 'no'}`,
    );
  }

  const listsBoth = (res: AzureResponse): string => {
    if (res.status >= 300) return 'refused';
    const got = wiqlIds(res.json);
    const n = ids.filter((id) => got.includes(id)).length;
    return n === 2 ? 'lists both' : n === 0 ? 'lists neither' : 'lists one';
  };
  const plain = await wiql(env, agile, precise);
  await rec(env, 'f-wiql-plain-time', answerOf(plain));
  note(
    `the same query (a time in the date) without timePrecision: ${describe(plain)}; ${listsBoth(plain)}`,
  );
  const aheadIso = new Date(Date.now() + 3_600_000).toISOString();
  const aheadPrecise = await wiql(env, agile, reconcileWiql(aheadIso), '?timePrecision=true');
  await rec(env, 'f-wiql-ahead-precise', answerOf(aheadPrecise));
  note(
    `CreatedDate >= now + 1 h (${aheadIso}) with timePrecision=true: ${describe(aheadPrecise)}; ${listsBoth(aheadPrecise)}`,
  );
  const aheadPlain = await wiql(env, agile, reconcileWiql(aheadIso));
  await rec(env, 'f-wiql-ahead-plain', answerOf(aheadPlain));
  note(
    `CreatedDate >= now + 1 h without timePrecision: ${describe(aheadPlain)}; ${listsBoth(aheadPlain)}`,
  );
  const day = aheadIso.slice(0, 10);
  const dateOnly = await wiql(env, agile, reconcileWiql(day));
  await rec(env, 'f-wiql-date-only', answerOf(dateOnly));
  note(
    `CreatedDate >= '${day}' (the UTC day of now + 1 h, no time) without timePrecision: ${describe(dateOnly)}; ${listsBoth(dateOnly)}`,
  );
  const top = await wiql(env, agile, precise, '?timePrecision=true&$top=1');
  await rec(env, 'f-wiql-top', answerOf(top));
  note(`the first query with $top=1: ${describe(top)}; ${wiqlIds(top.json).length} id(s) listed`);
  ctx.log(`f done: ${ids.join(', ')}`);
}

/** g. (§7.4/§7.5) workitemsbatch on both routes: deleted and unknown ids, omit, a moved item. */
async function stepG(env: Env, note: Note): Promise<void> {
  const { ctx, agile, basic } = env;
  const pair = env.reconcile ?? {
    live: await plainItem(env, agile, 'Issue', 'batch live'),
    second: await plainItem(env, agile, 'Issue', 'batch deleted'),
  };
  const { live } = pair;
  const gone = pair.second;
  const del = await ctx.bot.request('DELETE', wit(gone.project, `/workitems/${gone.id}`));
  await rec(env, 'g-delete', answerOf(del));
  note(`DELETE work item ${gone.id}: ${describe(del)}`);
  const ids = [live.id, gone.id, NEVER_ID];
  const body = (extra: Record<string, unknown>) => ({ ids, fields: BATCH_FIELDS, ...extra });
  const read = (res: AzureResponse): string => {
    if (res.status >= 300) return describe(res);
    const { items, nulls } = batchEntries(res.json);
    const f = items.get(live.id);
    return (
      `${describe(res)}; ids answered ${[...items.keys()].join(', ') || 'none'}, ${nulls} null entr${nulls === 1 ? 'y' : 'ies'}` +
      (f
        ? `; live: TeamProject "${str(f['System.TeamProject'])}", type ${str(f['System.WorkItemType'])}, state ${str(f['System.State'])}`
        : '')
    );
  };
  const routes = [
    ['org', '/_apis/wit/workitemsbatch'],
    ['project', wit(agile, '/workitemsbatch')],
  ] as const;
  for (const [label, path] of routes) {
    const res = await ctx.bot.request('POST', path, body({ errorPolicy: 'omit' }));
    await rec(env, `g-batch-${label}`, answerOf(res));
    note(`${label}-level batch (live, deleted, never existed; errorPolicy omit): ${read(res)}`);
    const strict = await ctx.bot.request('POST', path, body({}));
    await rec(env, `g-batch-${label}-no-policy`, answerOf(strict));
    note(`${label}-level batch, same ids, no errorPolicy: ${read(strict)}`);
  }
  const both = await ctx.bot.request('POST', '/_apis/wit/workitemsbatch', {
    ids: [live.id],
    fields: BATCH_FIELDS,
    $expand: 'relations',
  });
  await rec(env, 'g-batch-fields-expand', answerOf(both));
  note(`batch with fields and $expand together: ${describe(both)}`);

  const moveOps: Op[] = [
    field('System.TeamProject', basic.name),
    field('System.AreaPath', basic.name),
    field('System.IterationPath', basic.name),
  ];
  let move = await update(env, live, moveOps);
  await rec(env, 'g-move', answerOf(move));
  note(`move to probe-basic (TeamProject, AreaPath, IterationPath): ${describe(move)}`);
  if (move.status >= 300) {
    move = await update(env, live, [...moveOps, field('System.State', 'To Do')]);
    await rec(env, 'g-move-state', answerOf(move));
    note(`move again with System.State "To Do": ${describe(move)}`);
  }
  if (move.status >= 300) return;
  live.project = basic;
  const mf = fieldsOf(move);
  note(
    `moved: TeamProject "${str(mf['System.TeamProject'])}", type ${str(mf['System.WorkItemType'])}, state ${str(mf['System.State'])}, id ${str(idOf(move))}`,
  );
  for (const [label, path] of [
    ['org', '/_apis/wit/workitemsbatch'],
    ['agile', wit(agile, '/workitemsbatch')],
    ['basic', wit(basic, '/workitemsbatch')],
  ] as const) {
    const res = await ctx.bot.request('POST', path, {
      ids: [live.id],
      fields: BATCH_FIELDS,
      errorPolicy: 'omit',
    });
    await rec(env, `g-batch-moved-${label}`, answerOf(res));
    note(`batch of the moved item on the ${label} route: ${read(res)}`);
  }
}

/** h. (§7.1) the corpus, escaped, in `<pre>`, `<code>` and plain, in fields and notes. */
async function stepH(env: Env, note: Note): Promise<void> {
  const { ctx, agile } = env;
  const all = corpusCases(env.userId);
  const ops = (cases: Case[]): Op[] => {
    const html = renderingHtml(cases, FORMS);
    return [
      title(env, 'rendering'),
      field('System.Description', html),
      field(REPRO, html),
      field('System.Tags', 'qualor; probe30'),
      hyperlink,
    ];
  };
  let made = await create(env, agile, 'Bug', ops(all));
  let used = all;
  if (made.res.status >= 300) {
    await rec(env, 'h-create-all-refused', answerOf(made.res));
    used = all.filter((c) => !xmlUnsafe(c.value));
    note(
      `create with all ${all.length} cases: ${describe(made.res)}; again without the XML-unsafe cases ${all
        .filter((c) => xmlUnsafe(c.value))
        .map((c) => c.n)
        .join(', ')}`,
    );
    made = await create(env, agile, 'Bug', ops(used));
  }
  await rec(env, 'h-create', answerOf(made.res));
  ok(made.res, 'rendering create');
  if (!made.tracked) throw new Error('the rendering create answered no id');
  const bug = made.tracked;
  env.bug = bug;
  note(
    `create Agile Bug ${bug.id} with ${used.length} cases x 3 forms in Description and Repro Steps: ${describe(made.res)}`,
  );

  for (const form of FORMS) {
    const res = await update(env, bug, [history(renderingHtml(used, [form]))]);
    await rec(env, `h-history-${form}`, answerOf(res));
    note(`History PATCH, every case in ${form}: ${describe(res)}`);
  }
  for (const c of all.filter((x) => !used.includes(x))) {
    const res = await update(env, bug, [history(caseBlock(c, 'pre'))]);
    note(`History PATCH of case ${c.n} (${c.name}) alone in pre: ${describe(res)}`);
  }
  const quiet = await update(
    env,
    bug,
    [history('<p>Qualor probe item 30: a note with suppressNotifications.</p>')],
    '?suppressNotifications=true',
  );
  await rec(env, 'h-history-suppress', answerOf(quiet));
  note(`History PATCH with suppressNotifications=true: ${describe(quiet)}`);

  const comments = ok(
    await ctx.bot.request(
      'GET',
      wit(agile, `/workItems/${bug.id}/comments?$expand=renderedText`),
      undefined,
      { apiVersion: COMMENTS_VERSION },
    ),
    'comments',
  );
  await rec(env, 'h-comments', answerOf(comments));
  const list = shape(
    z.object({
      comments: z.array(
        z
          .object({
            text: z.string(),
            renderedText: z.string().nullish(),
            mentions: z.array(z.unknown()).nullish(),
          })
          .loose(),
      ),
    }),
    comments.json,
    'comments',
  ).comments;
  const read = ok(
    await ctx.bot.request('GET', wit(agile, `/workitems/${bug.id}?$expand=relations`)),
    'read back',
  );
  await rec(env, 'h-read', answerOf(read));
  const f = fieldsOf(read);
  const relations =
    z
      .object({ relations: z.array(z.object({ rel: z.string() }).loose()).nullish() })
      .parse(read.json).relations ?? [];
  const stored = (name: string): CaseFinding[] => caseFindings(str(f[name]));
  const texts = list.map((c) => c.text).join('');
  const rendered = list.map((c) => c.renderedText ?? '').join('');
  note(
    `read back: CommentCount ${str(f['System.CommentCount'])}, ${list.length} comments, mentions listed ${list.reduce((n, c) => n + (c.mentions?.length ?? 0), 0)}, ` +
      `relations ${relations.map((r) => r.rel).join(', ') || 'none'} (${relations.length > 1 ? 'NEW relations appeared' : 'no new relation'}); ` +
      `renderedText ${rendered.length > 0 ? `${rendered.length} characters` : 'empty'}`,
  );
  const sets: [string, CaseFinding[]][] = [
    ['System.Description', stored('System.Description')],
    ['Repro Steps', stored(REPRO)],
    ['History text', caseFindings(texts)],
    ['History renderedText', caseFindings(rendered)],
  ];
  for (const [label, findings] of sets) {
    note(
      `${label}: ${findings.length} case blocks found; cases with a link, mention, image or other markup: ${findingsLine(findings)}`,
    );
  }
  const hit = new Set(
    sets.flatMap(([, fs]) =>
      fs.filter((x) => x.link || x.mention || x.image || x.markup).map((x) => x.n),
    ),
  );
  for (const c of used.filter((x) => hit.has(x.n))) {
    note(`case ${c.n} (${c.name}) rendered as more than text somewhere (see the lines above)`);
  }
  note(
    `${used.length - [...hit].filter((n) => used.some((c) => c.n === n)).length} of ${used.length} cases stayed inert text in every form and field`,
  );
}

/** j. (§7.15) tag lengths, and a comma inside a tag. */
async function stepJ(env: Env, note: Note): Promise<void> {
  const { ctx } = env;
  const bug = env.bug ?? (await plainItem(env, env.agile, 'Bug', 'tags'));
  const made: string[] = [];
  for (const n of [100, 101, 400]) {
    const tag = tagOfLength(n, `probe30-${n}`);
    const res = await update(env, bug, [field('System.Tags', `qualor; ${tag}`)]);
    await rec(env, `j-tag-${n}`, answerOf(res));
    const tags = tagsOf(fieldsOf(res)['System.Tags']);
    if (res.status < 300) made.push(...tags.filter((t) => t !== 'qualor'));
    note(
      `a ${n}-character tag: ${describe(res)}${res.status < 300 ? `; stored tag lengths ${tags.map((t) => t.length).join(', ')}` : ''}`,
    );
  }
  const comma = await update(env, bug, [field('System.Tags', 'qualor; probe30-a,b')]);
  await rec(env, 'j-tag-comma', answerOf(comma));
  const ctags = tagsOf(fieldsOf(comma)['System.Tags']);
  if (comma.status < 300) made.push(...ctags.filter((t) => t !== 'qualor'));
  const short = ctags.filter((t) => t.length < 20);
  note(
    `tags "qualor; probe30-a,b": ${describe(comma)}${comma.status < 300 ? `; short tags stored ${JSON.stringify(short)} (a comma ${short.includes('b') ? 'splits' : 'does not split'} a tag); ${ctags.length - short.length} long tags still there, so PATCH add on System.Tags ${ctags.length > 3 ? 'adds to the tags already there' : 'replaces them'}` : ''}`,
  );
  // Best effort: unused tags also expire on their own; a refusal only goes to the console.
  ctx.cleanup.add('delete the probe tags', async () => {
    for (const tag of new Set(made)) {
      const path = wit(env.agile, `/tags/${encodeURIComponent(tag)}`);
      let res = await ctx.bot.request('DELETE', path);
      if (res.status >= 300 && res.status !== 404) {
        res = await ctx.bot.request('DELETE', path, undefined, { apiVersion: '7.0-preview.1' });
      }
      if (res.status >= 300 && res.status !== 404) {
        ctx.log(`delete tag of ${tag.length} characters: ${describe(res)}`);
      }
    }
  });
}

/** i. (§7.11) a note on a Closed item, and `test /rev` after another change. */
async function stepI(env: Env, note: Note): Promise<void> {
  const bug = env.bug ?? (await plainItem(env, env.agile, 'Bug', 'closed note'));
  let close = await update(env, bug, [field('System.State', 'Closed')]);
  await rec(env, 'i-close', answerOf(close));
  note(`New to Closed in one PATCH: ${describe(close)}`);
  if (close.status >= 300) {
    const resolved = await update(env, bug, [field('System.State', 'Resolved')]);
    note(`to Resolved first: ${describe(resolved)}`);
    close = await update(env, bug, [field('System.State', 'Closed')]);
    note(`then to Closed: ${describe(close)}`);
  }
  const closed = await update(env, bug, [
    history('<p>Qualor probe item 30: a note on a closed item.</p>'),
  ]);
  await rec(env, 'i-history-closed', answerOf(closed));
  note(`History PATCH while ${str(fieldsOf(close)['System.State'])}: ${describe(closed)}`);
  const oldRev =
    closed.json && typeof closed.json === 'object'
      ? (closed.json as { rev?: unknown }).rev
      : undefined;
  const change = await update(env, bug, [title(env, 'rendering, retitled')]);
  note(`another change (title): ${describe(change)}`);
  const stale = await update(env, bug, [
    { op: 'test', path: '/rev', value: oldRev },
    history('<p>Qualor probe item 30: a note racing a change.</p>'),
  ]);
  await rec(env, 'i-test-rev-stale', answerOf(stale));
  note(`History PATCH with test /rev ${str(oldRev)} (stale): ${describe(stale)}`);
  const newRev =
    change.json && typeof change.json === 'object'
      ? (change.json as { rev?: unknown }).rev
      : undefined;
  const fresh = await update(env, bug, [
    { op: 'test', path: '/rev', value: newRev },
    history('<p>Qualor probe item 30: a note on the current revision.</p>'),
  ]);
  await rec(env, 'i-test-rev-current', answerOf(fresh));
  note(`History PATCH with test /rev ${str(newRev)} (current): ${describe(fresh)}`);
}

/** k. (§7.10) the Agile Bug's states, and Removed. */
async function stepK(env: Env, note: Note): Promise<void> {
  const { ctx } = env;
  const StatesSchema = z.object({
    value: z.array(z.object({ name: z.string(), category: z.string().optional() }).loose()),
  });
  const lists: Record<string, string[]> = {};
  for (const [label, p] of [
    ['agile', env.agile],
    ['scrum', env.scrum],
  ] as const) {
    const res = await ctx.bot.request('GET', wit(p, '/workitemtypes/Bug/states'));
    await rec(env, `k-states-${label}`, answerOf(res));
    const states = shape(StatesSchema, res.json, `${label} Bug states`).value;
    lists[label] = states.map((s) => s.name);
    note(
      `${label} Bug states: ${describe(res)}; ${states.map((s) => `${s.name}:${s.category ?? '?'}`).join(', ')}`,
    );
  }
  const bug = env.bug ?? (await plainItem(env, env.agile, 'Bug', 'removed'));
  const listed = lists['agile']?.includes('Removed') ?? false;
  const removed = await update(env, bug, [field('System.State', 'Removed')]);
  await rec(env, 'k-removed', answerOf(removed));
  note(
    `Removed ${listed ? 'is' : 'is NOT'} in the Agile Bug's list; PATCH System.State Removed: ${describe(removed)}`,
  );
  const now = ok(await ctx.bot.request('GET', wit(bug.project, `/workitems/${bug.id}`)), 'state');
  const state = str(fieldsOf(now)['System.State']);
  note(
    `the item's state now: ${state}, ${lists['agile']?.includes(state) ? 'in' : 'NOT in'} the type's list; ` +
      'a state outside the list cannot be set through REST; one removed by a process change was not probed (inherited process)',
  );
}

// ---------------------------------------------------------------------------------------------

async function setup(ctx: ProbeContext): Promise<{ env: Env; projects: AzureResponse }> {
  const projects = ok(await ctx.bot.request('GET', '/_apis/projects?$top=100'), 'projects');
  const listed = shape(ProjectsSchema, projects.json, 'projects').value;
  const find = (name: string): Project => {
    const p = listed.find((x) => x.name.toLowerCase() === name.toLowerCase());
    if (!p) throw new Error(`no project ${name} among the ${listed.length} listed`);
    return { id: p.id, name: p.name };
  };
  const who = ok(
    await ctx.user.request('GET', '/_apis/connectionData', undefined, {
      apiVersion: CONNECTION_DATA_VERSION,
    }),
    'connectionData (user)',
  );
  const env: Env = {
    ctx,
    who: ctx.bot === ctx.pat ? 'pat' : 'sp',
    agile: find(ctx.project),
    basic: find('probe-basic'),
    scrum: find('probe-scrum'),
    userId: shape(ConnectionDataSchema, who.json, 'connectionData').authenticatedUser.id,
  };
  await rec(env, 'a-projects', {
    ...answerOf(projects),
    continuationToken: projects.headers['x-ms-continuationtoken'] ?? null,
  });
  return { env, projects };
}

/**
 * Item 30 (sub-plan 8, Task 1): what Azure Boards support relies on, on Services, for the identity
 * `--auth` chose. Every sub-step records its answer and the next one runs whatever it found; every
 * work item and area node it makes is deleted at clean-up. Recordings carry `pat` or `sp` in their
 * names, so both runs keep theirs.
 */
export const item: ProbeItem = {
  id: 30,
  title:
    'Boards: projects, paths, hidden types, create errors, WIQL, batch, rendering, tags, states',
  async run(ctx) {
    const { env, projects } = await setup(ctx);
    const steps: [string, (note: Note) => Promise<void>][] = [
      ['a', (note) => stepA(env, note, projects)],
      ['b', (note) => stepB(env, note)],
      ['c', (note) => stepC(env, note)],
      ['d', (note) => stepD(env, note)],
      ['e', (note) => stepE(env, note)],
      ['f', (note) => stepF(env, note)],
      ['g', (note) => stepG(env, note)],
      ['h', (note) => stepH(env, note)],
      ['j', (note) => stepJ(env, note)],
      ['i', (note) => stepI(env, note)],
      ['k', (note) => stepK(env, note)],
    ];
    const lines: string[] = [
      `identity: ${env.who === 'pat' ? 'the PAT' : 'the service principal'}`,
    ];
    let answered = 0;
    for (const [key, run] of steps) {
      const note: Note = (line) => {
        lines.push(`${key}. ${line}`);
        ctx.log(`${key}. ${line}`);
      };
      try {
        await run(note);
        answered++;
      } catch (err) {
        if (err instanceof InterruptedError) throw err;
        note(`NO ANSWER: ${(err as Error).name}: ${(err as Error).message}`);
      }
    }
    const answer = answered === steps.length ? 'yes' : answered > 0 ? 'partly' : 'no';
    return result(ctx, answer, lines.join('\n'));
  },
};
