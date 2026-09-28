import { randomUUID } from 'node:crypto';
import { SYSTEM_PROMPTS } from '@qualor/shared';
import { eq, inArray, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { branches, issueChanges, issues, jobs, llmRequests } from '../src/db/schema';
import { runHousekeeping } from '../src/housekeeping/run';
import { llmHandlers, reconcileStuckLlmRequests, type LlmJobDeps } from '../src/llm/job';
import { AI_FIX_MARKER } from '../src/llm/render';
import { AI_FIX_QUEUE } from '../src/llm/post';
import { LLM_QUEUE } from '../src/llm/service';
import { runUntilIdle } from '../src/queue/worker';
import { scmHandlers, type DecorationDeps } from '../src/scm/decorate';
import { SCM_QUEUE } from '../src/scm/queue';
import { parseInternalHosts } from '../src/scm/url';
import { addMember, ADMIN_PASSWORD, createUser, login, type Session } from './app';
import { createFakeGitHub, type FakeGitHub } from './fake-github';
import { createFakeGitLab, type FakeGitLab } from './fake-gitlab';
import {
  anthropicAnswer,
  createFakeLlm,
  openAiAnswer,
  type FakeLlm,
  type LlmResponder,
  type RecordedLlmRequest,
} from './fake-llm';
import { githubDeps, mappedGitHubProject, pullRequestReport } from './github';
import { createIngestHarness, type IngestHarness } from './ingest';
import { llmJobDeps } from './llm';
import {
  FORGED_NONCE,
  HOSTILE_ANSWERS,
  HOSTILE_FINDINGS,
  KEY_PLACEHOLDER,
  SYSTEM_PLACEHOLDER,
} from './llm-injection';
import { FIXED_TEXT, FORBIDDEN_ANYWHERE, outsideCodeSpans } from './markdown-check';
import { engine, file, finding, reportWith } from './reports';
import { decorationDeps, mappedProject, mergeRequestReport, PUBLIC_URL } from './scm';

/**
 * Plan 3B, Task 18: the AI assistant end to end against the fake LLM (both provider shapes), the
 * fake GitLab and the fake GitHub; the prompt-injection corpus; and a search for every secret the
 * test seeds, in every place Qualor writes to or answers from.
 */

const HEAD = 'a'.repeat(40);
const BASE = 'b'.repeat(40);
// Assembled at run time, so the repository's own Gitleaks check finds no fake secret here.
const GITHUB_TOKEN = ['gh', 'p_', 'Qx7Lm2'.repeat(6)].join('');
const DB_PASSWORD = ['Pw9v', 'Tq2L', 'mx8R', 'k4Zs'].join('');
/** Text of the snippet that reaches the model and, with prompt storage off, nothing else. */
const CANARY = `prompt-canary-${randomUUID()}`;
/** Line 1 holds two secrets (redacted before sending), line 2 the finding, line 3 the canary. */
const LINES = [
  `const t = "${GITHUB_TOKEN}"; // Server=db;Database=app;Password=${DB_PASSWORD};`,
  'if (a == 1) {}',
  `export {}; // ${CANARY}`,
];
/** Line 1 is context; lines 2 and 3 are added. */
const DIFF = `@@ -1,1 +1,3 @@\n ${LINES[0]}\n+${LINES[1]}\n+${LINES[2]}`;
/** C0/C1 controls but `\n`, bidi controls, separators and invisible characters. */
const UNSAFE = FORBIDDEN_ANYWHERE;

/** `value` as it might be written anywhere: plain, JSON, URL, hex and base64 at every alignment. */
function encodings(value: string): string[] {
  const out = new Set<string>([
    value,
    JSON.stringify(value).slice(1, -1),
    encodeURIComponent(value),
    Buffer.from(value).toString('hex'),
    Buffer.from(value).toString('hex').toUpperCase(),
  ]);
  for (const pad of [0, 1, 2]) {
    const b64 = Buffer.from('\0'.repeat(pad) + value).toString('base64');
    // The characters that depend only on `value`, whatever precedes or follows it.
    const middle = b64.slice(pad === 0 ? 0 : 4, b64.length - 4);
    out.add(middle);
    out.add(middle.replace(/\+/g, '-').replace(/\//g, '_'));
  }
  return [...out];
}

function expectAbsent(haystack: string, needles: string[], where: string): void {
  for (const needle of needles) {
    expect(haystack.includes(needle), `${where} holds ${JSON.stringify(needle)}`).toBe(false);
  }
}

/** The system and user messages of a request, in either shape. */
function promptOf(request: RecordedLlmRequest): { system: string; user: string } {
  const json = request.json as {
    system?: string;
    messages: { role: string; content: string }[];
  };
  const system =
    request.path === '/v1/messages'
      ? (json.system ?? '')
      : (json.messages.find((m) => m.role === 'system')?.content ?? '');
  return { system, user: json.messages.find((m) => m.role === 'user')?.content ?? '' };
}

/** A model that obeys: `text` with the key it was called with and its system prompt filled in. */
function obedient(text: string): LlmResponder {
  return (request) => {
    const header = request.headers['x-api-key'] ?? request.headers.authorization ?? '';
    const key = String(header).replace(/^Bearer /, '');
    const inJson = (s: string) => JSON.stringify(s).slice(1, -1);
    const filled = text
      .split(KEY_PLACEHOLDER)
      .join(inJson(key))
      .split(SYSTEM_PLACEHOLDER)
      .join(inJson(promptOf(request).system));
    return {
      status: 200,
      body: request.path === '/v1/messages' ? anthropicAnswer(filled) : openAiAnswer(filled),
    };
  };
}

/** Every string of a stored answer. */
function stringsOf(value: unknown): string[] {
  if (typeof value === 'string') return [value];
  if (Array.isArray(value)) return value.flatMap(stringsOf);
  if (value !== null && typeof value === 'object') return Object.values(value).flatMap(stringsOf);
  return [];
}

describe('the AI assistant end to end (plan 3B, Task 18)', () => {
  let llm: FakeLlm;
  let gitlab: FakeGitLab;
  let github: FakeGitHub;
  let h: IngestHarness;
  let admin: Session;
  /** Every API answer the test received (headers and body), but those below. */
  const responses: string[] = [];
  /** The settings' answers: they name the base URL to the instance admin by design (llm.md §16). */
  const settingsResponses: string[] = [];
  /** The issue routes' answers: they show the uploaded snippet to members by design. */
  const issueResponses: string[] = [];
  const gitlabId = 700;
  const repoId = 9_700;
  let mainIssue = '';
  let githubIssue = '';
  const hostileIssues: string[] = [];
  const settingsKinds: string[] = [];

  const call = async (
    method: 'GET' | 'POST' | 'PUT',
    url: string,
    payload?: object,
    headers: Record<string, string> = h.orgAdmin.headers,
  ) => {
    const res = await h.ctx.app.inject({
      method,
      url: `/api/v0${url}`,
      headers,
      ...(payload === undefined ? {} : { payload }),
    });
    const sink = url.startsWith('/system/llm')
      ? settingsResponses
      : /^\/issues\/[^/]+\/transition$/.test(url)
        ? issueResponses
        : responses;
    sink.push(JSON.stringify(res.headers), res.body);
    return res;
  };
  const row = async (id: string) =>
    (await h.ctx.db.select().from(llmRequests).where(eq(llmRequests.id, id)))[0]!;
  const issueRow = async (id: string) =>
    (await h.ctx.db.select().from(issues).where(eq(issues.id, id)))[0]!;

  /** The settings, written as an instance admin does: the key goes the real way. */
  async function configure(kind: 'openai' | 'anthropic', over: object = {}): Promise<void> {
    const res = await call(
      'PUT',
      '/system/llm',
      {
        provider: {
          kind,
          baseUrl: kind === 'openai' ? llm.openAiBaseUrl : llm.anthropicBaseUrl,
          model: 'fake-model',
          apiKey: llm.apiKey,
          timeoutSeconds: 5,
        },
        organizations: {
          [h.organizationId]: {
            enabled: true,
            features: { explain: true, triage: true, fix: true },
            excludedProjectIds: [],
          },
        },
        excludePaths: [],
        budgets: {
          explainPerDay: 200,
          triagePerDay: 100,
          fixPerDay: 25,
          tokensPerDay: 1_000_000,
          costPerDayUsd: null,
          perUserPerHour: 1_000,
        },
        pricing: null,
        storePrompts: false,
        promptRetentionDays: 7,
        ...over,
      },
      admin.headers,
    );
    expect(res.statusCode, res.body).toBe(200);
    settingsKinds.push(kind);
  }

  /** Runs the `llm` queue as its worker does, logging into the app's log. */
  async function runLlm(over: Partial<LlmJobDeps> = {}): Promise<void> {
    await h.ctx.db
      .update(jobs)
      .set({ runAt: sql`now()` })
      .where(eq(jobs.queue, LLM_QUEUE));
    await runUntilIdle(h.ctx.db, llmHandlers(llmJobDeps(h, over)), h.ctx.app.log);
  }

  /** Runs the `scm` worker's queues (decorations and AI fix posts), logging into the app's log. */
  async function runScm(deps: DecorationDeps): Promise<void> {
    await h.ctx.db
      .update(jobs)
      .set({ runAt: sql`now()` })
      .where(inArray(jobs.queue, [SCM_QUEUE, AI_FIX_QUEUE]));
    await runUntilIdle(h.ctx.db, scmHandlers(deps), h.ctx.app.log);
  }

  /** Asks, runs the worker, and reads the request back through the API. */
  async function ask(
    issueId: string,
    feature: 'explain' | 'triage' | 'fix',
    options: { refresh?: boolean; deps?: Partial<LlmJobDeps> } = {},
  ) {
    const res = await call('POST', `/issues/${issueId}/ai/${feature}`, {
      refresh: options.refresh ?? true,
    });
    expect(res.statusCode, res.body).toBe(202);
    const id = res.json<{ id: string }>().id;
    await runLlm(options.deps);
    const read = await call('GET', `/ai-requests/${id}`);
    expect(read.statusCode, read.body).toBe(200);
    return read.json<{
      id: string;
      status: string;
      error: { code: string; detail: string | null } | null;
      result: unknown;
    }>();
  }

  const aiFixThreads = () =>
    gitlab
      .discussions(gitlabId, 7)
      .filter((d) => d.notes[0]!.body.startsWith('<!-- qualor:ai-fix '));

  beforeAll(async () => {
    llm = await createFakeLlm();
    gitlab = await createFakeGitLab();
    github = await createFakeGitHub();
    h = await createIngestHarness({
      config: {
        publicUrl: PUBLIC_URL,
        scmInternalHosts: parseInternalHosts(
          `${new URL(gitlab.url).host},${new URL(github.url).host}`,
        ),
        llmInternalHosts: parseInternalHosts(llm.host),
      },
    });
    admin = await login(h.ctx, 'admin', ADMIN_PASSWORD);

    // A GitLab merge request !7 with the secrets on the line above the finding.
    gitlab.addProject({ id: gitlabId, path: 'acme/e2e' });
    gitlab.addMergeRequest(gitlabId, {
      iid: 7,
      title: 'Fix',
      state: 'opened',
      sourceBranch: 'feature/x',
      targetBranch: 'main',
      headSha: HEAD,
      baseSha: BASE,
      startSha: BASE,
      diffs: [{ oldPath: 'src/a.ts', newPath: 'src/a.ts', diff: DIFF }],
    });
    const glProject = await mappedProject(h, gitlab, 'acme/e2e', gitlabId);
    await glProject.ingestOk(
      mergeRequestReport(7, HEAD, {
        projectKey: glProject.key,
        gitlab: { projectId: String(gitlabId) },
        engines: [engine('eslint')],
        files: [file('src/a.ts', { lines: 3, newLines: [[2, 3]] })],
        findings: [
          finding({
            ruleId: 'eqeqeq',
            path: 'src/a.ts',
            line: 2,
            snippet: { startLine: 1, lines: LINES },
          }),
        ],
      }),
    );
    // The same change in a GitHub pull request #7, a second project.
    github.addRepository({ id: repoId, owner: 'acme', name: 'e2e-gh', installationId: 777 });
    github.addPull(repoId, {
      number: 7,
      title: 'Fix',
      state: 'open',
      headSha: HEAD,
      baseSha: BASE,
      files: [{ filename: 'src/a.ts', patch: DIFF }],
    });
    const ghProject = await mappedGitHubProject(h, github, 'acme/e2e-gh', 'acme/e2e-gh');
    await ghProject.ingestOk(
      pullRequestReport(7, HEAD, {
        projectKey: ghProject.key,
        github: { repositoryId: String(repoId), checkout: 'head' },
        engines: [engine('eslint')],
        files: [file('src/a.ts', { lines: 3, newLines: [[2, 3]] })],
        findings: [
          finding({
            ruleId: 'eqeqeq',
            path: 'src/a.ts',
            line: 2,
            snippet: { startLine: 1, lines: LINES },
          }),
        ],
      }),
    );
    // One issue per hostile finding, each in its own file.
    const hostile = await h.project('acme/e2e-hostile');
    await hostile.ingestOk(
      reportWith({
        projectKey: hostile.key,
        engines: [engine('eslint')],
        files: HOSTILE_FINDINGS.map((_, i) => file(`src/h${i}.ts`, { lines: 2 })),
        findings: HOSTILE_FINDINGS.map((f, i) =>
          finding({
            ruleId: 'eqeqeq',
            path: `src/h${i}.ts`,
            line: f.lines.length,
            message: f.message,
            snippet: { startLine: 1, lines: f.lines },
          }),
        ),
      }),
    );
    const byProject = async (projectId: string) =>
      h.ctx.db.select().from(issues).where(eq(issues.projectId, projectId));
    mainIssue = (await byProject(glProject.id))[0]!.id;
    githubIssue = (await byProject(ghProject.id))[0]!.id;
    const hostileRows = await byProject(hostile.id);
    for (const [i] of HOSTILE_FINDINGS.entries()) {
      hostileIssues.push(hostileRows.find((r) => r.path === `src/h${i}.ts`)!.id);
    }
    // The decorations of the analyses (the summary notes, the check run) are not under test.
    await runScm(decorationDeps(h));
    await runScm(githubDeps(h));
  });
  afterAll(async () => {
    await h.close();
    await Promise.all([llm.close(), gitlab.close(), github.close()]);
  });

  it('explains, triages and suggests a fix in both provider shapes, and caches a repeated question', async () => {
    let fixId = '';
    for (const kind of ['openai', 'anthropic'] as const) {
      await configure(kind);
      for (const feature of ['explain', 'triage', 'fix'] as const) {
        const before = llm.requests.length;
        const answer = await ask(mainIssue, feature, { refresh: false });
        expect(answer, JSON.stringify(answer)).toMatchObject({
          status: 'succeeded',
          error: null,
          result: { kind: feature },
        });
        expect(llm.requests).toHaveLength(before + 1);
        expect(llm.requests.at(-1)!.path).toBe(
          kind === 'openai' ? '/v1/chat/completions' : '/v1/messages',
        );
        if (feature === 'fix') {
          expect(answer.result).toMatchObject({
            status: 'fixed',
            startLine: 2,
            endLine: 2,
            replacement: ['if (a === 1) {}'],
          });
          fixId = answer.id;
        }
      }
      // The same question again: the cached answer (200), and nothing sent.
      const before = llm.requests.length;
      const again = await call('POST', `/issues/${mainIssue}/ai/explain`, { refresh: false });
      expect(again.statusCode, again.body).toBe(200);
      expect(again.json()).toMatchObject({ status: 'succeeded', result: { kind: 'explain' } });
      await runLlm();
      expect(llm.requests).toHaveLength(before);
    }
    // The secrets of line 1 were redacted before anything was sent; line 3 was sent.
    for (const request of llm.requests) {
      expectAbsent(request.body, [GITHUB_TOKEN, DB_PASSWORD], 'a request to the model');
      expect(request.body).toContain('«redacted»');
      expect(request.body).toContain(CANARY);
    }

    // Posting the anthropic fix: one GitLab suggestion on the analysed head.
    const posted = await call('POST', `/ai-requests/${fixId}/post`, {});
    expect(posted.statusCode, posted.body).toBe(202);
    await runScm(decorationDeps(h));
    expect(aiFixThreads()).toHaveLength(1);
    const note = aiFixThreads()[0]!.notes[0]!;
    expect(note.body).toContain('```suggestion:-0+0\nif (a === 1) {}\n```');
    expect(note.position).toMatchObject({ new_path: 'src/a.ts', new_line: 2, head_sha: HEAD });
    expect((await row(fixId)).post).toMatchObject({ status: 'posted' });
  });

  it('posts a fix to the GitHub pull request of a second project, once', async () => {
    // Not the cached fix of the GitLab twin (same organisation, rule, fingerprint and code).
    const fix = await ask(githubIssue, 'fix', { refresh: false });
    expect(fix.status).toBe('succeeded');
    const posted = await call('POST', `/ai-requests/${fix.id}/post`, {});
    expect(posted.statusCode, posted.body).toBe(202);
    await runScm(githubDeps(h));
    const mine = github.reviewComments.filter((c) => c.repoId === repoId);
    expect(mine).toHaveLength(1);
    expect(mine[0]).toMatchObject({ path: 'src/a.ts', line: 2, side: 'RIGHT', commitId: HEAD });
    expect(mine[0]!.body).toContain('```suggestion\nif (a === 1) {}\n```');
    // A second click posts nothing more.
    const again = await call('POST', `/ai-requests/${fix.id}/post`, {});
    expect([again.statusCode, again.json().detail]).toEqual([409, 'already_posted']);
    await runScm(githubDeps(h));
    expect(github.reviewComments.filter((c) => c.repoId === repoId)).toHaveLength(1);
  });

  it('changes an issue only when a person accepts a triage, and records where it came from', async () => {
    llm.say(
      JSON.stringify({
        verdict: 'likely_false_positive',
        confidence: 'high',
        reasons: ['a is always a number here.'],
      }),
    );
    const triage = await ask(githubIssue, 'triage', { refresh: false });
    expect(triage).toMatchObject({
      status: 'succeeded',
      result: { verdict: 'likely_false_positive' },
    });
    expect((await issueRow(githubIssue)).status).toBe('open');
    const res = await call('POST', `/issues/${githubIssue}/transition`, {
      to: 'false_positive',
      comment: 'Checked by hand.',
      suggestionId: triage.id,
    });
    expect(res.statusCode, res.body).toBe(200);
    expect((await issueRow(githubIssue)).status).toBe('false_positive');
    const [change] = await h.ctx.db
      .select()
      .from(issueChanges)
      .where(eq(issueChanges.issueId, githubIssue));
    expect(change!.comment).toContain(`AI triage suggestion ${triage.id} (likely_false_positive`);
    expect(change!.comment).toContain("the decision is ingest-admin's");
  });

  it('keeps hostile findings inside the data, and what an obedient model answers inert', async () => {
    await configure('openai');
    for (const [i, f] of HOSTILE_FINDINGS.entries()) {
      const issueId = hostileIssues[i]!;
      llm.enqueue(obedient(f.obey.explain));
      const explain = await ask(issueId, 'explain');
      // The input side: one opening and one closing marker line with the request's nonce, the
      // hostile text only inside the data line, the fixed system prompt.
      const sent = llm.requests.at(-1)!;
      const { system, user } = promptOf(sent);
      expect(system, f.name).toBe(SYSTEM_PROMPTS.explain);
      const lines = user.split(/\r?\n|\r|\u2028|\u2029|\u0085/);
      expect(lines, f.name).toHaveLength(5);
      const nonce = /^<<<QUALOR-DATA-([0-9a-f]{32})$/.exec(lines[1]!)?.[1];
      expect(nonce, f.name).toBeDefined();
      expect(nonce).not.toBe(FORGED_NONCE);
      expect(lines[3]).toBe(`QUALOR-DATA-${nonce}>>>`);
      expect(
        lines.filter((l) => l.includes('QUALOR-DATA')),
        f.name,
      ).toHaveLength(2);
      expect(lines[0]).toContain(`nonce ${nonce}`);
      const data = JSON.parse(lines[2]!) as { issue: { message: string } };
      expect(data.issue.message, f.name).toContain(f.probe);
      for (const [n, line] of lines.entries()) {
        if (n !== 2) expect(line, f.name).not.toContain(f.probe);
      }
      // The output side.
      expect(explain.status, `${f.name}: ${JSON.stringify(explain)}`).toBe(
        f.expect.explain === 'stored' ? 'succeeded' : 'failed',
      );
      for (const feature of ['triage', 'fix'] as const) {
        const text = f.obey[feature];
        if (text === undefined) continue;
        llm.enqueue(obedient(text));
        const answer = await ask(issueId, feature);
        expect(answer.status, `${f.name} ${feature}: ${JSON.stringify(answer)}`).toBe(
          f.expect[feature] === 'stored' ? 'succeeded' : 'failed',
        );
        if (answer.status === 'failed') {
          expect(answer.error?.code).toMatch(/^(MALFORMED_OUTPUT|OUTPUT_REFUSED)$/);
        }
      }
      // Nothing an answer says changes the issue.
      expect((await issueRow(issueId)).status, f.name).toBe('open');
      expect(
        await h.ctx.db.select().from(issueChanges).where(eq(issueChanges.issueId, issueId)),
      ).toEqual([]);
    }
    // Every stored answer is plain, safe text without the key (echoed by the obedient model).
    const hostileRows = await h.ctx.db
      .select()
      .from(llmRequests)
      .where(inArray(llmRequests.issueId, hostileIssues));
    for (const r of hostileRows.filter((x) => x.status === 'succeeded')) {
      for (const s of stringsOf(r.result)) {
        expect(s, JSON.stringify(s)).not.toMatch(UNSAFE);
        expect(s).not.toContain(llm.apiKey);
      }
    }
    const exfiltrated = hostileRows.find(
      (x) => x.issueId === hostileIssues.at(-1) && x.feature === 'explain',
    );
    expect(stringsOf(exfiltrated?.result).join('\n')).toContain('«redacted»');
  });

  it('sends nothing when the data holds the nonce drawn (a forged one)', async () => {
    const forged = HOSTILE_FINDINGS.findIndex((f) => f.message.includes(FORGED_NONCE));
    const before = llm.requests.length;
    const res = await call('POST', `/issues/${hostileIssues[forged]!}/ai/explain`, {
      refresh: true,
    });
    expect(res.statusCode, res.body).toBe(202);
    await runLlm({ nonce: () => FORGED_NONCE });
    expect(llm.requests).toHaveLength(before);
    expect(await reconcileStuckLlmRequests(h.ctx.db)).toBe(1);
    expect(await row(res.json<{ id: string }>().id)).toMatchObject({
      status: 'failed',
      errorCode: 'REQUEST_ABANDONED',
      result: null,
    });
  });

  it('refuses hostile answers, stores the rest as plain text, and posts only inert text', async () => {
    for (const a of HOSTILE_ANSWERS) {
      llm.say(a.text);
      const answer = await ask(mainIssue, a.feature);
      const label = `${a.feature} ${a.text}: ${JSON.stringify(answer)}`;
      if (a.expect === 'refused') {
        expect(answer.status, label).toBe('failed');
        expect(answer.error?.code, label).toMatch(/^(MALFORMED_OUTPUT|OUTPUT_REFUSED)$/);
        expect(answer.result).toBeNull();
        continue;
      }
      expect(answer.status, label).toBe('succeeded');
      for (const s of stringsOf(answer.result)) expect(s, JSON.stringify(s)).not.toMatch(UNSAFE);
      if (a.feature !== 'fix') continue;
      // The stored fix, posted: outside the suggestion fence only Qualor's text and code spans.
      const threads = aiFixThreads().length;
      const posted = await call('POST', `/ai-requests/${answer.id}/post`, {});
      expect(posted.statusCode, posted.body).toBe(202);
      await runScm(decorationDeps(h));
      expect(aiFixThreads()).toHaveLength(threads + 1);
      const body = aiFixThreads().at(-1)!.notes[0]!.body;
      expect(body).not.toMatch(UNSAFE);
      const lines = body.split('\n');
      expect(lines[0]).toMatch(AI_FIX_MARKER);
      const open = lines.findIndex((l) => l.startsWith('```suggestion'));
      const close = lines.indexOf('```', open + 1);
      expect(lines.slice(open + 1, close)).toEqual(['if (a === 1) {}']);
      const outside = [...lines.slice(1, open), ...lines.slice(close + 1)];
      const ownLink = `[View the issue in Qualor](${PUBLIC_URL}/projects/`;
      let links = 0;
      for (const line of outside) {
        expect(line, line).not.toMatch(/^\s*\//);
        let markdown = outsideCodeSpans(line);
        if (markdown.startsWith(ownLink)) {
          // The only link: Qualor's own, to the issue.
          expect(markdown).toMatch(/^\[View the issue in Qualor\]\([a-z0-9:/.-]+\)$/);
          links++;
          markdown = '';
        }
        expect(markdown, line).toMatch(FIXED_TEXT);
        expect(markdown, line).not.toMatch(/<\S/);
      }
      expect(links).toBe(1);
      expect(body).toContain('` [x](http://evil) /merge @all <img src=x> `');
    }
    expect((await issueRow(mainIssue)).status).toBe('open');
    expect(
      await h.ctx.db.select().from(issueChanges).where(eq(issueChanges.issueId, mainIssue)),
    ).toEqual([]);
  });

  it('keeps an issue and its twins on other branches apart: triage accepted and fixes posted each on its own (C1)', async () => {
    await configure('openai');
    const twinsId = 701;
    gitlab.addProject({ id: twinsId, path: 'acme/twins' });
    for (const iid of [8, 9]) {
      gitlab.addMergeRequest(twinsId, {
        iid,
        title: `Twin ${iid}`,
        state: 'opened',
        sourceBranch: `feature/twin-${iid}`,
        targetBranch: 'main',
        headSha: HEAD,
        baseSha: BASE,
        startSha: BASE,
        diffs: [{ oldPath: 'src/a.ts', newPath: 'src/a.ts', diff: DIFF }],
      });
    }
    const project = await mappedProject(h, gitlab, 'acme/twins', twinsId);
    const parts = {
      projectKey: project.key,
      engines: [engine('eslint')],
      files: [file('src/a.ts', { lines: 3, newLines: [[2, 3]] as [number, number][] })],
      findings: [
        finding({
          ruleId: 'eqeqeq',
          path: 'src/a.ts',
          line: 2,
          snippet: { startLine: 1, lines: LINES },
        }),
      ],
    };
    // The same finding on main and in merge requests !8 and !9.
    await project.ingestOk(reportWith({ ...parts, branch: 'main', revision: BASE }));
    for (const iid of [8, 9]) {
      await project.ingestOk(
        mergeRequestReport(iid, HEAD, {
          ...parts,
          branch: `feature/twin-${iid}`,
          gitlab: { projectId: String(twinsId) },
        }),
      );
    }
    await runScm(decorationDeps(h));
    const twins = await h.ctx.db
      .select({ id: issues.id, fingerprint: issues.fingerprint, branch: branches.name })
      .from(issues)
      .innerJoin(branches, eq(branches.id, issues.branchId))
      .where(eq(issues.projectId, project.id));
    expect(twins).toHaveLength(3);
    expect(new Set(twins.map((t) => t.fingerprint)).size).toBe(1);
    const onMain = twins.find((t) => t.branch === 'main')!.id;
    const onEight = twins.find((t) => t.branch === '8')!.id;
    const onNine = twins.find((t) => t.branch === '9')!.id;

    // A fix for each merge request, each posted to its own.
    const fixes = new Map<number, string>();
    for (const [iid, issueId] of [
      [8, onEight],
      [9, onNine],
    ] as const) {
      const before = llm.requests.length;
      const fix = await ask(issueId, 'fix', { refresh: false });
      expect(fix.status).toBe('succeeded');
      expect(llm.requests).toHaveLength(before + 1);
      expect((await row(fix.id)).issueId).toBe(issueId);
      fixes.set(iid, fix.id);
    }
    expect(fixes.get(8)).not.toBe(fixes.get(9));
    for (const iid of [8, 9]) {
      const posted = await call('POST', `/ai-requests/${fixes.get(iid)!}/post`, {});
      expect(posted.statusCode, posted.body).toBe(202);
    }
    await runScm(decorationDeps(h));
    for (const [iid, issueId] of [
      [8, onEight],
      [9, onNine],
    ] as const) {
      const threads = gitlab
        .discussions(twinsId, iid)
        .filter((d) => d.notes[0]!.body.startsWith('<!-- qualor:ai-fix '));
      expect(threads, `!${iid}`).toHaveLength(1);
      expect(threads[0]!.notes[0]!.body.split('\n', 1)[0]).toBe(
        `<!-- qualor:ai-fix ${issueId} ${fixes.get(iid)!} -->`,
      );
      expect((await row(fixes.get(iid)!)).post).toMatchObject({ status: 'posted' });
    }

    // A triage for the issue on main and for its twin in !8, each accepted on its own issue.
    const triages = new Map<string, string>();
    for (const issueId of [onMain, onEight]) {
      const triage = await ask(issueId, 'triage', { refresh: false });
      expect(triage.status).toBe('succeeded');
      expect((await row(triage.id)).issueId).toBe(issueId);
      triages.set(issueId, triage.id);
    }
    expect(triages.get(onMain)).not.toBe(triages.get(onEight));
    // Another issue's suggestion is refused.
    const crossed = await call('POST', `/issues/${onEight}/transition`, {
      to: 'false_positive',
      comment: 'Checked by hand.',
      suggestionId: triages.get(onMain),
    });
    expect([crossed.statusCode, crossed.body]).toEqual([
      422,
      expect.stringContaining('suggestionId'),
    ]);
    for (const issueId of [onMain, onEight]) {
      const res = await call('POST', `/issues/${issueId}/transition`, {
        to: 'false_positive',
        comment: 'Checked by hand.',
        suggestionId: triages.get(issueId),
      });
      expect(res.statusCode, res.body).toBe(200);
      const [change] = await h.ctx.db
        .select()
        .from(issueChanges)
        .where(eq(issueChanges.issueId, issueId));
      expect(change!.comment).toContain(`AI triage suggestion ${triages.get(issueId)!} (`);
    }
  });

  it('leaks no secret, key, base URL or prompt anywhere', async () => {
    // Nothing is in flight: the search sees everything written.
    expect(
      await h.ctx.db
        .select()
        .from(llmRequests)
        .where(inArray(llmRequests.status, ['queued', 'running'])),
    ).toEqual([]);
    expect(settingsKinds).toContain('anthropic');
    const secrets = [llm.apiKey, GITHUB_TOKEN, DB_PASSWORD, gitlab.token].flatMap(encodings);
    const logs = h.ctx.logs.join('\n');
    const answers = responses.join('\n');
    // Every row of every table as text. The report and the snippet the CI job uploaded are the
    // input and hold the seeded secrets by design; they are searched separately below.
    const tables = await h.ctx.db.execute<{ tablename: string }>(
      sql`SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename`,
    );
    const rows: { table: string; text: string }[] = [];
    for (const { tablename } of tables.rows) {
      const drop =
        tablename === 'issues' ? `- 'snippet'` : tablename === 'analysis_reports' ? `- 'body'` : '';
      const result = await h.ctx.db.execute<{ t: string }>(
        sql.raw(`SELECT (to_jsonb(x) ${drop})::text AS t FROM "${tablename}" x`),
      );
      rows.push(...result.rows.map((r) => ({ table: tablename, text: r.t })));
    }
    expect(rows.some((r) => r.table === 'llm_requests')).toBe(true);
    expect(rows.some((r) => r.table === 'jobs')).toBe(true);
    const database = rows.map((r) => `${r.table} ${r.text}`).join('\n');
    // The search itself works: the uploaded snippet holds the token, and the model got the canary.
    const [snippet] = await h.ctx.db
      .execute<{ t: string }>(sql`SELECT snippet::text AS t FROM issues WHERE id = ${mainIssue}`)
      .then((r) => r.rows);
    expect(snippet!.t).toContain(GITHUB_TOKEN);
    expect(llm.requests.some((r) => r.body.includes(CANARY))).toBe(true);

    // The key, every seeded secret, in any encoding.
    expectAbsent(logs, secrets, 'the log');
    expectAbsent(answers, secrets, 'an API answer');
    expectAbsent(settingsResponses.join('\n'), secrets, 'a settings answer');
    // The issue's own answer shows the uploaded snippet (the input); never the key or a token.
    expect(issueResponses.join('\n')).toContain(GITHUB_TOKEN);
    expectAbsent(
      issueResponses.join('\n'),
      [llm.apiKey, gitlab.token].flatMap(encodings),
      'an issue answer',
    );
    expectAbsent(database, secrets, 'the database');
    expectAbsent(JSON.stringify(github.requests), secrets, 'a request to GitHub');
    const toGitLab = gitlab.requests.map((r) => ({ ...r, headers: { ...r.headers } }));
    for (const r of toGitLab) delete r.headers['private-token'];
    expectAbsent(JSON.stringify(toGitLab), secrets, 'a request to GitLab');
    // The key only in the model's key header; no seeded secret in anything sent to it.
    for (const request of llm.requests) {
      expectAbsent(request.body, secrets, 'a request body to the model');
      const { authorization, 'x-api-key': apiKey, ...other } = request.headers;
      expectAbsent(JSON.stringify(other), secrets, 'a request header to the model');
      expect(request.path === '/v1/messages' ? apiKey : authorization).toBe(
        request.path === '/v1/messages' ? llm.apiKey : `Bearer ${llm.apiKey}`,
      );
    }
    // The key's plaintext is nowhere in the settings row; its envelope is.
    expect(database).toMatch(/instance_settings .*"apiKeyEnc"/);

    // The base URL beyond its host: only the admin's settings name it.
    const beyondHost = [llm.openAiBaseUrl];
    expectAbsent(logs, beyondHost, 'the log');
    expectAbsent(answers, beyondHost, 'an API answer');
    expectAbsent(
      rows
        .filter((r) => r.table !== 'instance_settings')
        .map((r) => r.text)
        .join('\n'),
      beyondHost,
      'the database',
    );
    expectAbsent(JSON.stringify([gitlab.requests, github.requests]), beyondHost, 'the SCM');
    expect(
      new Set(
        (await h.ctx.db.select({ host: llmRequests.providerHost }).from(llmRequests)).map(
          (r) => r.host,
        ),
      ),
    ).toEqual(new Set([llm.host]));

    // Prompt storage is off: the prompt reached the model and nothing else.
    // The canary of the snippet, every nonce drawn and the fixed text of the user message.
    const nonces = llm.requests.map(
      (r) => /<<<QUALOR-DATA-([0-9a-f]{32})\n/.exec(promptOf(r).user)?.[1] ?? 'missing',
    );
    expect(nonces).not.toContain('missing');
    const prompt = [CANARY, ...nonces, 'between the two marker lines carrying the nonce'];
    expectAbsent(logs, prompt, 'the log');
    expectAbsent(answers, prompt, 'an API answer');
    expectAbsent(database, prompt, 'the database');
    expectAbsent(JSON.stringify([gitlab.requests, github.requests]), prompt, 'the SCM');
    expect(
      await h.ctx.db
        .select({ id: llmRequests.id })
        .from(llmRequests)
        .where(sql`${llmRequests.prompt} IS NOT NULL`),
    ).toEqual([]);
  });

  it('stores a prompt only when asked, redacted, and retention clears it, then the row', async () => {
    await configure('openai', { storePrompts: true });
    const stored = await ask(mainIssue, 'explain');
    expect(stored.status).toBe('succeeded');
    const prompt = JSON.stringify((await row(stored.id)).prompt);
    expect(prompt).toContain(CANARY);
    expectAbsent(prompt, [GITHUB_TOKEN, DB_PASSWORD].flatMap(encodings), 'a stored prompt');
    // Older than promptRetentionDays (7): the prompt goes, the row stays.
    await h.ctx.db
      .update(llmRequests)
      .set({ createdAt: sql`now() - interval '8 days'` })
      .where(eq(llmRequests.id, stored.id));
    const first = await runHousekeeping(h.ctx.db);
    expect(first.llmPromptsCleared).toBe(1);
    expect(await row(stored.id)).toMatchObject({ prompt: null, status: 'succeeded' });
    // Older than the requests' retention (90 days): the row goes too.
    await h.ctx.db
      .update(llmRequests)
      .set({ createdAt: sql`now() - interval '91 days'` })
      .where(eq(llmRequests.id, stored.id));
    const second = await runHousekeeping(h.ctx.db);
    expect(second.llmRequests).toBe(1);
    expect(await h.ctx.db.select().from(llmRequests).where(eq(llmRequests.id, stored.id))).toEqual(
      [],
    );
    await configure('openai');
  });

  it('is off for an organisation the settings do not name, and sends nothing', async () => {
    const org = await call(
      'POST',
      '/organizations',
      { key: 'e2e-other', name: 'Other' },
      admin.headers,
    );
    expect(org.statusCode, org.body).toBe(201);
    const organizationId = org.json<{ id: string }>().id;
    const u = await createUser(h.ctx, { username: 'e2e-other-admin' });
    await addMember(h.ctx, organizationId, u.id, 'admin');
    const session = await login(h.ctx, u.username, u.password);
    const project = await h.project('e2e-other/app', { organizationId, session });
    await project.ingestOk(
      reportWith({
        projectKey: project.key,
        engines: [engine('eslint')],
        files: [file('src/a.ts', { lines: 3 })],
        findings: [finding({ ruleId: 'eqeqeq', line: 2, snippet: { startLine: 1, lines: LINES } })],
      }),
    );
    const [issue] = await h.ctx.db.select().from(issues).where(eq(issues.projectId, project.id));
    const before = llm.requests.length;
    for (const feature of ['explain', 'triage', 'fix']) {
      const res = await call(
        'POST',
        `/issues/${issue!.id}/ai/${feature}`,
        { refresh: false },
        session.headers,
      );
      expect([res.statusCode, res.json().code]).toEqual([409, 'AI_DISABLED']);
    }
    await runLlm();
    expect(llm.requests).toHaveLength(before);
    const view = await call(
      'GET',
      `/organizations/${organizationId}/ai`,
      undefined,
      session.headers,
    );
    expect(view.json()).toMatchObject({ enabled: false });
  });
});
