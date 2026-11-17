import { randomUUID } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { outboundRequest } from '../http/outbound';
import {
  JiraClient,
  type CreateMetaField,
  type CreateMetaIssueType,
  type CreatedIssue,
} from './client';
import { runConnectionTest } from './connection';
import {
  codeIssueContent,
  fixedComment,
  foundAgainComment,
  reconciliationLabel,
  vulnerabilityContent,
  type JiraContent,
} from './content';
import { forbiddenMarkup } from './live-render';
import { advisoryUrl } from './markup';
import { normalJiraUrl } from './url';

/**
 * 0.16 Jira, spec §9: the opt-in check against a real Jira. Never part of `pnpm test` or CI (the
 * unit project excludes `*.live.test.ts`, and the `jira-live` project exists only when the command
 * line names it): `pnpm jira:live`, with the variables below. It settles what the fake
 * (server/test/fake-jira.ts) could only guess; every answer is written to
 * `.tmp/jira-live/<date>/<connection>/` for comparison with server/test/jira-shapes/ (see its
 * README), with the token and the email removed. Look at the printed issue URLs afterwards: nothing
 * of the injected text may show as a link, an image, a macro or bold.
 *
 * Variables (QUALOR_LIVE_JIRA_*):
 * - SITE_URL, TOKEN, PROJECT (a Jira project key): required; without them the check skips.
 * - DEPLOYMENT: `cloud` (default) or `data_center`. EMAIL: Cloud's account email (basic auth); Data
 *   Center uses TOKEN as a personal access token (bearer).
 * - API_URL (Cloud): `https://api.atlassian.com/ex/jira/<cloudId>`, the second pass through the
 *   gateway, with API_TOKEN (a scoped token; TOKEN when absent) and the same EMAIL.
 * - ISSUE_TYPE: the issue type's name (default Task, else the first that is not a sub-task).
 * - CLEANUP=1: delete every issue it created at the end (needs the permission). Without it the
 *   issues stay, labelled `qualor-live`, so you can look at them.
 */
const SITE_URL = process.env.QUALOR_LIVE_JIRA_SITE_URL ?? '';
const TOKEN = process.env.QUALOR_LIVE_JIRA_TOKEN ?? '';
const PROJECT = process.env.QUALOR_LIVE_JIRA_PROJECT ?? '';
const DEPLOYMENT =
  process.env.QUALOR_LIVE_JIRA_DEPLOYMENT === 'data_center' ? 'data_center' : 'cloud';
const EMAIL = process.env.QUALOR_LIVE_JIRA_EMAIL ?? '';
const API_URL = process.env.QUALOR_LIVE_JIRA_API_URL ?? '';
const API_TOKEN = process.env.QUALOR_LIVE_JIRA_API_TOKEN ?? '';
const ISSUE_TYPE = process.env.QUALOR_LIVE_JIRA_ISSUE_TYPE ?? '';
const CLEANUP = process.env.QUALOR_LIVE_JIRA_CLEANUP === '1';

const configured = SITE_URL !== '' && TOKEN !== '' && PROJECT !== '';
const ZWSP = '​';
const PUBLIC_URL = 'https://qualor.example';
const MISSING_ID = '999999999999';
const DAY = new Date().toISOString().slice(0, 10);
const OUT = path.resolve(process.cwd(), '.tmp', 'jira-live', DAY);

// The markup-injection inputs of spec §11.1 and the review notes.
const MESSAGE =
  'See [here|https://evil.example] {html}<b>x</b>{html} !https://evil.example/p.png! *bold* https://evil.example/bare';
const ADVISORY =
  'https://evil.example/a?c={color:red}x{color}&h={html}<img/src=x/onerror=alert(1)>{html}&i=!x!';
const RULE_NAME = 'Avoid {noformat} blocks';
const BRANCH = 'a\\b';
const PROJECT_NAME = 'mailto:a@evil.example www.evil.example a@evil.example';
const PACKAGE = 'pk|g]x';

interface Connection {
  name: string;
  deployment: 'cloud' | 'data_center';
  apiBase: string;
  authorization: string;
  secrets: string[];
  client: JiraClient;
}

function connectionOf(name: string, apiBase: string, token: string): Connection {
  const base = normalJiraUrl(apiBase);
  const data = DEPLOYMENT === 'data_center';
  const pair = `${EMAIL}:${token}`;
  const basic = Buffer.from(pair).toString('base64');
  return {
    name,
    deployment: DEPLOYMENT,
    apiBase: base,
    authorization: data ? `Bearer ${token}` : `Basic ${basic}`,
    secrets: data ? [token] : [token, EMAIL, pair, basic],
    client: new JiraClient({
      deployment: DEPLOYMENT,
      apiBase: base,
      auth: data ? { kind: 'bearer', token } : { kind: 'basic', email: EMAIL, token },
      allowInternalHosts: data,
    }),
  };
}

const connections: Connection[] = [];
if (configured) {
  connections.push(
    connectionOf(DEPLOYMENT === 'cloud' ? 'cloud-basic' : 'dc-pat', SITE_URL, TOKEN),
  );
  if (API_URL !== '' && DEPLOYMENT === 'cloud') {
    connections.push(connectionOf('cloud-scoped', API_URL, API_TOKEN === '' ? TOKEN : API_TOKEN));
  }
}

interface Raw {
  status: number;
  body: unknown;
}

/** A request outside the client, for the answers it does not keep (never throws on a status). */
async function raw(
  c: Connection,
  method: 'GET' | 'POST' | 'DELETE',
  p: string,
  body?: unknown,
): Promise<Raw> {
  const result = await outboundRequest(
    {
      url: `${c.apiBase}${p}`,
      method,
      headers: {
        authorization: c.authorization,
        accept: 'application/json',
        'user-agent': 'Qualor-live-check',
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    },
    {
      allowInternalHosts: c.deployment === 'data_center',
      timeoutMs: 30_000,
      maxResponseBytes: 8 * 1024 * 1024,
      overflow: 'fail',
      names: { noun: 'Jira', target: 'Jira' },
    },
  );
  if (result.kind === 'failed') throw new Error(`${method} ${p.split('?')[0]}: ${result.reason}`);
  const text = result.body.toString('utf8');
  try {
    return { status: result.status, body: text === '' ? null : (JSON.parse(text) as unknown) };
  } catch {
    return { status: result.status, body: text.slice(0, 2_000) };
  }
}

/** The answer as text with the credentials, and every email address Jira shows, removed. */
function scrub(c: Connection, value: unknown): string {
  let text = JSON.stringify(value, null, 2) ?? 'null';
  for (const secret of c.secrets) if (secret !== '') text = text.replaceAll(secret, '«redacted»');
  return text.replace(/("emailAddress"\s*:\s*)"[^"]*"/g, '$1"«redacted»"');
}

const decodeEntities = (s: string): string =>
  s
    .replace(/&#(\d+);/g, (_, n: string) => String.fromCodePoint(Number(n)))
    .replace(/&#x([0-9a-f]+);/gi, (_, n: string) => String.fromCodePoint(parseInt(n, 16)))
    .replaceAll('&lt;', '<')
    .replaceAll('&gt;', '>')
    .replaceAll('&quot;', '"')
    .replaceAll('&nbsp;', ' ')
    .replaceAll('&amp;', '&');

const plainText = (html: string): string =>
  decodeEntities(html.replace(/<br\s*\/?>/gi, '\n').replace(/<[^>]*>/g, '')).replaceAll(ZWSP, '');

async function eventually<T>(
  read: () => Promise<T>,
  done: (value: T) => boolean,
  timeoutMs = 120_000,
): Promise<{ value: T; seconds: number }> {
  const start = Date.now();
  for (;;) {
    const value = await read();
    if (done(value) || Date.now() - start > timeoutMs) {
      return { value, seconds: Math.round((Date.now() - start) / 100) / 10 };
    }
    await new Promise((resolve) => setTimeout(resolve, 3_000));
  }
}

describe.skipIf(!configured).each(connections)('live Jira: $name', (c) => {
  const label = `qualor-live-${randomUUID().slice(0, 8)}`;
  const summary: Record<string, unknown> = { connection: c.name, deployment: c.deployment, label };
  const findings: string[] = [];
  const created: { id: string; key: string }[] = [];
  const state = {
    issueType: null as CreateMetaIssueType | null,
    labelsOn: true,
    single: null as CreatedIssue | null,
    bulk: [] as CreatedIssue[],
    deletedProbe: null as string | null,
    labels: [] as string[],
  };
  const dir = path.join(OUT, c.name);

  function record(name: string, value: unknown): void {
    mkdirSync(path.join(dir, 'shapes'), { recursive: true });
    writeFileSync(path.join(dir, 'shapes', `${name}.json`), `${scrub(c, value)}\n`);
  }

  function note(text: string): void {
    findings.push(text);
    console.log(`[${c.name}] ${text}`);
  }

  const browse = (key: string): string => `${normalJiraUrl(SITE_URL)}/browse/${key}`;

  const fieldsOf = (content: JiraContent, tag: string): Record<string, unknown> => ({
    project: { key: PROJECT },
    issuetype: { id: state.issueType?.id ?? '' },
    summary: content.summary,
    description: content.description,
    ...(state.labelsOn ? { labels: ['qualor', 'qualor-live', label, tag] } : {}),
  });

  /** Reads the issue's (or comment's) rendered HTML and checks what spec §11.1 forbids. */
  function checkRendered(what: string, html: string, links: string[], literals: string[]): void {
    const anchors = [...html.matchAll(/<a\b[^>]*>/gi)].map((m) => m[0]);
    const hrefs = anchors.map((a) => decodeEntities(/href="([^"]*)"/i.exec(a)?.[1] ?? '(no href)'));
    for (const href of hrefs) {
      const allowed = links.some((l) => href === l || (l.endsWith('/') && href.startsWith(l)));
      if (!allowed) note(`${what}: an unexpected link, href ${href}`);
      expect.soft(allowed, `${what}: link ${href}`).toBe(true);
    }
    for (const name of forbiddenMarkup(html)) {
      note(`${what}: renders ${name}`);
      expect.soft(name, `${what}: renders ${name}`).toBeUndefined();
    }
    const plain = plainText(html);
    for (const literal of literals) {
      const there = plain.includes(literal);
      if (!there) note(`${what}: the text ${JSON.stringify(literal)} is not shown literally`);
      expect.soft(there, `${what}: shows ${JSON.stringify(literal)}`).toBe(true);
    }
  }

  async function renderedDescription(issue: { id: string; key: string }): Promise<string> {
    const answer = await raw(
      c,
      'GET',
      `/rest/api/2/issue/${issue.id}?fields=description&expand=renderedFields`,
    );
    record(`rendered-description-${issue.key}`, answer.body);
    expect(answer.status).toBe(200);
    const rendered = (answer.body as { renderedFields?: { description?: unknown } }).renderedFields
      ?.description;
    expect(typeof rendered, 'renderedFields.description').toBe('string');
    return rendered as string;
  }

  it('connection test: myself and the visible projects', async () => {
    const result = await runConnectionTest(c.client);
    expect(result.problem).toBeNull();
    expect(result.ok).toBe(true);
    summary.connectionTest = {
      user: result.user?.displayName,
      projectsVisible: result.projectsVisible,
    };
    expect(result.projectsVisible).toBeGreaterThan(0);
    record('myself', (await raw(c, 'GET', '/rest/api/2/myself')).body);
    const listing = await raw(
      c,
      'GET',
      c.deployment === 'cloud' ? '/rest/api/2/project/search?maxResults=5' : '/rest/api/2/project',
    );
    record(c.deployment === 'cloud' ? 'project-search' : 'project', listing.body);
    const picked = await c.client.searchProjects(PROJECT);
    expect(
      picked.map((p) => p.key),
      'the project is visible',
    ).toContain(PROJECT);
  });

  it('createmeta: issue types and fields, and which envelope the site uses', async () => {
    const base = `/rest/api/2/issue/createmeta/${encodeURIComponent(PROJECT)}/issuetypes`;
    const types = await c.client.issueTypes(PROJECT);
    expect(types.length).toBeGreaterThan(0);
    state.issueType =
      types.find((t) => (ISSUE_TYPE === '' ? t.name === 'Task' : t.name === ISSUE_TYPE)) ??
      types[0] ??
      null;
    expect(state.issueType).not.toBeNull();
    const typeId = state.issueType?.id ?? '';
    const typesRaw = await raw(c, 'GET', `${base}?startAt=0&maxResults=50`);
    const fieldsRaw = await raw(
      c,
      'GET',
      `${base}/${encodeURIComponent(typeId)}?startAt=0&maxResults=50`,
    );
    const envelope = (a: Raw): string[] =>
      typeof a.body === 'object' && a.body !== null ? Object.keys(a.body) : [];
    summary.createmetaEnvelope = {
      issueTypes: { status: typesRaw.status, keys: envelope(typesRaw) },
      fields: { status: fieldsRaw.status, keys: envelope(fieldsRaw) },
    };
    note(`createmeta envelope: ${JSON.stringify(summary.createmetaEnvelope)}`);
    const side = c.deployment === 'cloud' ? 'cloud' : 'dc';
    record(`createmeta-issuetypes.${side}`, typesRaw.body);
    record(`createmeta-fields.${side}`, fieldsRaw.body);
    const fields: CreateMetaField[] = await c.client.issueTypeFields(PROJECT, typeId);
    expect(fields.length).toBeGreaterThan(0);
    state.labelsOn = fields.some((f) => f.fieldId === 'labels');
    if (!state.labelsOn)
      note('the create screen has no labels field: issues are created without labels');
    const required = fields.filter((f) => f.required && !f.hasDefaultValue).map((f) => f.fieldId);
    summary.requiredFieldsWithoutDefault = required;
    note(`type "${state.issueType?.name}" requires, without a default: ${required.join(', ')}`);
  });

  it('create one issue (code issue, every injected input in it)', async () => {
    const content = codeIssueContent(
      {
        issueId: randomUUID(),
        projectId: randomUUID(),
        projectName: PROJECT_NAME,
        projectKey: 'y',
        branchName: BRANCH,
        path: 'www.evil.example/x.ts',
        line: 3,
        ruleKey: 'live:1',
        ruleName: RULE_NAME,
        severity: 'high',
        quality: 'security',
        message: MESSAGE,
        firstSeenAt: new Date(),
        closedAt: null,
        lastSeenAt: null,
      },
      PUBLIC_URL,
    );
    const issue = await c.client.createIssue(fieldsOf(content, 'single'));
    state.single = issue;
    created.push(issue);
    summary.single = { ...issue, url: browse(issue.key) };
    console.log(`[${c.name}] created ${browse(issue.key)}  (look at the description by eye)`);
    const html = await renderedDescription(issue);
    checkRendered(
      `description of ${issue.key}`,
      html,
      [`${PUBLIC_URL}/`],
      [MESSAGE, RULE_NAME, PROJECT_NAME, 'www.evil.example/x.ts'],
    );
    // What Jira shows for `a\b`: a backslash, or a line break?
    const plain = plainText(html);
    const branchLine = /Branch: ([^\n]*)\n?([^\n]*)/.exec(plain);
    summary.backslashRendering = {
      branchLine: branchLine?.[0] ?? null,
      backslashShown: plain.includes('a\\b'),
    };
    note(`a\\b renders as ${JSON.stringify(branchLine?.[0] ?? null)}`);
  });

  it('bulk create of 2 (vulnerabilities, with the advisory URL and a package with | and ])', async () => {
    const base = {
      projectId: randomUUID(),
      projectName: 'live',
      installedVersions: ['1.0.0'],
      fixedVersion: '1.0.1',
      severity: 'high' as const,
      foundIn: ['main'],
      exploited: null,
      epss: null,
    };
    const one = vulnerabilityContent(
      {
        ...base,
        packageName: PACKAGE,
        vulnerabilityId: 'CVE-2026-0001',
        title: '*bold* [x|y]',
        primaryUrl: ADVISORY,
      },
      PUBLIC_URL,
    );
    const two = vulnerabilityContent(
      {
        ...base,
        packageName: 'p2',
        vulnerabilityId: 'GHSA-aaaa-bbbb-cccc',
        title: '{noformat}',
        primaryUrl: null,
      },
      PUBLIC_URL,
    );
    const outcome = await c.client.createIssues([fieldsOf(one, 'bulk1'), fieldsOf(two, 'bulk2')]);
    expect(outcome).toHaveLength(2);
    for (const o of outcome) {
      expect('created' in o, 'each element created').toBe(true);
      if ('created' in o) {
        state.bulk.push(o.created);
        created.push(o.created);
        console.log(`[${c.name}] created ${browse(o.created.key)}`);
      }
    }
    summary.bulk = state.bulk.map((i) => ({ ...i, url: browse(i.key) }));
    const [first, second] = state.bulk;
    if (first) {
      const link = advisoryUrl(ADVISORY) ?? '';
      checkRendered(
        `description of ${first.key}`,
        await renderedDescription(first),
        [`${PUBLIC_URL}/`, link],
        [PACKAGE],
      );
    }
    if (second) {
      checkRendered(
        `description of ${second.key}`,
        await renderedDescription(second),
        [`${PUBLIC_URL}/`],
        ['{noformat}'],
      );
    }
  });

  it('records the refusals: a bulk with one refused element, and a single refused create', async () => {
    const good = fieldsOf({ summary: 'Qualor live check (throwaway)', description: 'x' }, 'probe');
    const bad = { ...good, issuetype: { id: '0' } };
    const partial = await raw(c, 'POST', '/rest/api/2/issue/bulk', {
      issueUpdates: [{ fields: good }, { fields: bad }],
    });
    record('bulk-partial', partial.body);
    summary.bulkPartial = { status: partial.status };
    note(`bulk with one refused element answers ${partial.status}`);
    const made = (partial.body as { issues?: { id?: string; key?: string }[] }).issues ?? [];
    for (const i of made) {
      if (typeof i.id === 'string' && typeof i.key === 'string') {
        created.push({ id: i.id, key: i.key });
        state.deletedProbe = i.id;
      }
    }
    const refused = await raw(c, 'POST', '/rest/api/2/issue', { fields: bad });
    record('error', refused.body);
    summary.singleRefused = { status: refused.status };
    note(`a single refused create answers ${refused.status}`);
  });

  it('status read by id, with a deleted and a made-up id beside the real ones', async () => {
    const real = [state.single, ...state.bulk].filter((i): i is CreatedIssue => i !== null);
    let deleted = false;
    if (state.deletedProbe !== null) {
      const answer = await raw(c, 'DELETE', `/rest/api/2/issue/${state.deletedProbe}`);
      deleted = answer.status === 204;
      summary.deleteProbe = { id: state.deletedProbe, status: answer.status };
      note(`deleting a throwaway issue answers ${answer.status}`);
    }
    const ids = [
      ...real.map((i) => i.id),
      MISSING_ID,
      ...(deleted && state.deletedProbe ? [state.deletedProbe] : []),
    ];
    const jql = `id in (${ids.join(',')})`;
    const request =
      c.deployment === 'cloud'
        ? raw(c, 'POST', '/rest/api/2/search/jql', {
            jql,
            fields: ['status', 'labels'],
            maxResults: 100,
          })
        : raw(c, 'POST', '/rest/api/2/search', {
            jql,
            fields: ['status', 'labels'],
            maxResults: 100,
            validateQuery: 'warn',
          });
    const batch = await request;
    record(
      c.deployment === 'cloud' ? 'search-ids-with-missing.cloud' : 'search-ids-with-missing.dc',
      batch.body,
    );
    const body = batch.body as { issues?: unknown[]; warningMessages?: unknown };
    summary.batchWithMissingId = {
      status: batch.status,
      issuesReturned: body.issues?.length ?? null,
      warningMessages: body.warningMessages ?? null,
    };
    note(
      `one query with ${ids.length} ids incl. an unknown one: ${batch.status}, ` +
        `${body.issues?.length ?? 'no'} issues, warnings ${JSON.stringify(body.warningMessages ?? null)}`,
    );
    const wantedMissing = [
      MISSING_ID,
      ...(deleted && state.deletedProbe ? [state.deletedProbe] : []),
    ];
    const { value, seconds } = await eventually(
      () => c.client.searchByIds(ids),
      (v) => v.found.size === real.length && wantedMissing.every((m) => v.missing.includes(m)),
    );
    summary.searchByIds = {
      seconds,
      found: [...value.found.entries()].map(([id, s]) => ({
        id,
        key: s.key,
        status: s.statusName,
        category: s.statusCategory,
      })),
      missing: value.missing,
    };
    note(
      `searchByIds settled after ${seconds}s: found ${value.found.size}, missing ${value.missing.join(',')}`,
    );
    expect(value.found.size).toBe(real.length);
    for (const m of wantedMissing) expect(value.missing).toContain(m);
  });

  it('comments (fixed, found again) render without links, images or macros', async () => {
    const issue = state.single;
    expect(issue).not.toBeNull();
    if (issue === null) return;
    const facts = {
      projectName: PROJECT_NAME,
      day: DAY,
      link: `${PUBLIC_URL}/projects/x/issues/y`,
    };
    await c.client.addComment(
      issue.id,
      fixedComment({ ...facts, kind: 'code', branchName: BRANCH, ruleKey: RULE_NAME }),
    );
    await c.client.addComment(
      issue.id,
      foundAgainComment({
        ...facts,
        kind: 'vulnerability',
        vulnerabilityId: 'CVE-2026-0001',
        packageName: PACKAGE,
        foundIn: ['a\\b', 'mailto:a@evil.example'],
      }),
    );
    const list = await raw(c, 'GET', `/rest/api/2/issue/${issue.id}/comment?expand=renderedBody`);
    record('comment-list', list.body);
    expect(list.status).toBe(200);
    const comments = (list.body as { comments?: { renderedBody?: string }[] }).comments ?? [];
    expect(comments).toHaveLength(2);
    for (const [i, comment] of comments.entries()) {
      checkRendered(
        `comment ${i + 1} of ${issue.key}`,
        comment.renderedBody ?? '',
        [`${PUBLIC_URL}/`],
        [i === 0 ? BRANCH : PACKAGE],
      );
    }
  });

  it('reconciliation: the issues are found by their label (seconds until the search sees them)', async () => {
    if (!state.labelsOn) return;
    const { value, seconds } = await eventually(
      () => c.client.searchByLabels([label]),
      (v) => v.has(label),
    );
    summary.searchByLabel = { seconds, found: value.has(label) };
    note(`searchByLabels found the issues after ${seconds}s`);
    expect(value.has(label)).toBe(true);
    // The Qualor label of a link: one issue each, as the job creates them.
    const unique = reconciliationLabel(randomUUID(), 1);
    const content = { summary: 'Qualor live check (label)', description: 'x' };
    const issue = await c.client.createIssue({
      ...fieldsOf(content, 'label'),
      labels: ['qualor', 'qualor-live', unique],
    });
    created.push(issue);
    const found = await eventually(
      () => c.client.searchByLabels([unique]),
      (v) => v.has(unique),
    );
    summary.searchByReconciliationLabel = {
      seconds: found.seconds,
      found: found.value.has(unique),
    };
    note(`searchByLabels found a reconciliation label after ${found.seconds}s`);
    expect(found.value.get(unique)?.id).toBe(issue.id);
  });

  afterAll(async () => {
    const results: { key: string; deleteStatus: number | string }[] = [];
    if (CLEANUP) {
      for (const issue of created) {
        try {
          const answer = await raw(c, 'DELETE', `/rest/api/2/issue/${issue.id}`);
          results.push({ key: issue.key, deleteStatus: answer.status });
        } catch {
          results.push({ key: issue.key, deleteStatus: 'failed' });
        }
      }
    }
    summary.created = created.map((i) => i.key);
    summary.cleanup = CLEANUP ? results : 'off (QUALOR_LIVE_JIRA_CLEANUP=1 deletes the issues)';
    summary.findings = findings;
    mkdirSync(dir, { recursive: true });
    writeFileSync(path.join(dir, 'summary.json'), `${scrub(c, summary)}\n`);
    console.log(
      `[${c.name}] answers in ${path.relative(process.cwd(), dir)}; ` +
        (CLEANUP
          ? `deleted: ${results.filter((r) => r.deleteStatus === 204).length} of ${created.length}; the others carry the label qualor-live`
          : `${created.length} issues left, labelled qualor-live`),
    );
  });
});

const SKIP_MESSAGE =
  'jira-live skipped: set QUALOR_LIVE_JIRA_SITE_URL, QUALOR_LIVE_JIRA_TOKEN and QUALOR_LIVE_JIRA_PROJECT ' +
  '(and QUALOR_LIVE_JIRA_EMAIL for Cloud); see the header of server/src/jira/live.live.test.ts';
it.skipIf(configured)(SKIP_MESSAGE, () => {
  // Never runs: vitest lists it as skipped, with the message as its name.
});
