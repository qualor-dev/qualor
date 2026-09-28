import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import {
  FakeServer,
  me,
  ORG_ID,
  page,
  problem,
  provideFakeServer,
  settle,
} from '../../testing/fake-server';
import { SessionStore } from '../auth/session';
import { AI_POLL_INTERVAL, AiPanel } from './ai-panel';

const ISSUE = { id: 'i1', projectId: 'p1', branchId: 'b1', status: 'open' } as const;
const ORG_AI = {
  enabled: true,
  features: { explain: true, triage: true, fix: true },
  provider: { kind: 'openai', host: 'ollama:11434', model: 'qwen2.5-coder' },
  dataSent: ['rule', 'message', 'path', 'language', 'snippet'],
  usage: { explain: 0, triage: 0, fix: 0, tokens: 0, costUsd: null },
  budgets: {
    explainPerDay: 200,
    triagePerDay: 100,
    fixPerDay: 25,
    tokensPerDay: 1_000_000,
    costPerDayUsd: null,
    perUserPerHour: 30,
  },
};
const request = (over: object) => ({
  id: 'r1',
  issueId: 'i1',
  feature: 'explain',
  status: 'queued',
  model: 'qwen2.5-coder',
  promptVersion: 'explain.v1',
  createdAt: '2026-09-26T10:00:00.000Z',
  finishedAt: null,
  error: null,
  result: null,
  post: null,
  ...over,
});
const FIX = request({
  id: 'f1',
  feature: 'fix',
  status: 'succeeded',
  result: {
    kind: 'fix',
    status: 'fixed',
    startLine: 2,
    endLine: 2,
    original: ['if (a == 1) {}'],
    replacement: ['if (a === 1) {}'],
    explanation: 'Strict.',
  },
});

/** The issue's branch: merge request !42 on GitLab. */
const MERGE_REQUEST = {
  id: 'b1',
  projectId: 'p1',
  kind: 'merge_request',
  name: '42',
  isMain: false,
  mrSourceBranch: 'feature/refunds',
  mrTargetBranch: 'main',
  mrTitle: 'Refund limits',
  mrUrl: 'https://gitlab.example/acme/payments/-/merge_requests/42',
  lastAnalysisId: null,
  lastAnalyzedAt: null,
  gateStatus: null,
  measures: {},
};
/** Short, so that polls and their back-off run within a test. */
const POLL_MS = 10;
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

function setup(
  orgAi: object = ORG_AI,
  project: object = { scmConnectionId: 'c1' },
  pollMs = POLL_MS,
): FakeServer {
  const server = new FakeServer();
  // The panel finds the issue's organisation from its project (the one in the header may differ).
  server.on('GET', '/api/v0/projects/p1', {
    body: { id: 'p1', organizationId: ORG_ID, ...project },
  });
  server.on('GET', '/api/v0/projects/p1/branches', {
    body: page([{ ...MERGE_REQUEST, id: 'main', kind: 'branch', isMain: true }, MERGE_REQUEST]),
  });
  server.on('GET', `/api/v0/organizations/${ORG_ID}/ai`, { body: orgAi });
  server.on('GET', '/api/v0/issues/i1/ai', { body: { explain: null, triage: null, fix: null } });
  TestBed.configureTestingModule({
    providers: [
      provideRouter([{ path: '**', children: [] }]),
      provideFakeServer(server),
      { provide: AI_POLL_INTERVAL, useValue: pollMs },
    ],
  });
  TestBed.inject(SessionStore).set(me());
  return server;
}
async function render() {
  const fixture = TestBed.createComponent(AiPanel);
  fixture.componentRef.setInput('issue', ISSUE);
  fixture.componentRef.setInput('canAsk', true);
  fixture.componentRef.setInput('canTriage', true);
  await settle(fixture);
  return { fixture, root: fixture.nativeElement as HTMLElement };
}
const button = (root: HTMLElement, text: string) =>
  [...root.querySelectorAll('button')].find((b) => b.textContent?.trim() === text)!;

describe('AiPanel (llm.md §18)', () => {
  it('is absent when the organisation is not enabled', async () => {
    const server = setup({ ...ORG_AI, enabled: false, provider: null });
    const { root } = await render();
    expect(root.textContent?.trim()).toBe('');
    // Nothing more is asked of the server, let alone of the model.
    expect(server.requestsTo('GET', '/api/v0/issues/i1/ai')).toHaveLength(0);
    expect(server.requests.filter((r) => r.method === 'POST')).toHaveLength(0);
  });

  it('says what is sent where before anything is asked', async () => {
    const server = setup();
    const { root } = await render();
    expect(root.textContent).toContain(
      'the rule, the message, the file path, the language and the code around the issue',
    );
    expect(root.textContent).toContain('ollama:11434');
    expect(server.requests.filter((r) => r.method === 'POST')).toHaveLength(0);
  });

  it('offers only the features the organisation has on', async () => {
    setup({ ...ORG_AI, features: { explain: true, triage: false, fix: false } });
    const { root } = await render();
    expect(button(root, 'Explain')).toBeDefined();
    expect(button(root, 'Suggest triage')).toBeUndefined();
    expect(button(root, 'Suggest a fix')).toBeUndefined();
  });

  it('asks, polls and shows the explanation as text, hostile markup included', async () => {
    // Slow enough to see the request in flight first.
    const server = setup(ORG_AI, undefined, 300);
    server.on('POST', '/api/v0/issues/i1/ai/explain', { status: 202, body: request({}) });
    server.on('GET', '/api/v0/ai-requests/r1', {
      body: request({
        status: 'succeeded',
        finishedAt: '2026-09-26T10:00:05.000Z',
        result: {
          kind: 'explain',
          summary: '<img src=x onerror=alert(1)> [link](http://evil)',
          explanation: 'Line one\nLine two',
          howToFix: '',
        },
      }),
    });
    const { fixture, root } = await render();
    button(root, 'Explain').click();
    await settle(fixture);
    expect(root.querySelector('[role="status"]')?.textContent).toContain('Asking the model');
    await wait(400);
    await settle(fixture);
    expect(root.querySelector('[role="status"]')?.textContent).toContain('The answer is ready.');
    expect(root.querySelector('img')).toBeNull();
    expect(root.querySelector('a[href="http://evil"]')).toBeNull();
    expect(root.textContent).toContain('<img src=x onerror=alert(1)> [link](http://evil)');
    expect(root.textContent).toContain('AI-generated, may be wrong');
    expect(root.querySelector('.ai-text')?.tagName).toBe('P');
  });

  it('offers to mark a likely false positive and emits the suggestion id', async () => {
    const server = setup();
    server.on('GET', '/api/v0/issues/i1/ai', {
      body: {
        explain: null,
        triage: request({
          id: 't1',
          feature: 'triage',
          status: 'succeeded',
          result: {
            kind: 'triage',
            verdict: 'likely_false_positive',
            confidence: 'high',
            reasons: ['a is a number'],
          },
        }),
        fix: null,
      },
    });
    const { fixture, root } = await render();
    let accepted: string | null = null;
    fixture.componentInstance.acceptTriage.subscribe((id: string) => (accepted = id));
    expect(root.textContent).toContain('Likely a false positive');
    expect(root.textContent).toContain('high confidence');
    button(root, 'Mark as false positive…').click();
    expect(accepted).toBe('t1');
    // The panel changes nothing itself: the person makes the transition.
    expect(server.requests.filter((r) => r.method === 'POST')).toHaveLength(0);
  });

  it('shows a fix before and after, and posts it only after confirming', async () => {
    const server = setup();
    server.on('GET', '/api/v0/issues/i1/ai', { body: { explain: null, triage: null, fix: FIX } });
    server.on('POST', '/api/v0/ai-requests/f1/post', {
      status: 409,
      body: { ...problem(409, 'AI_POST_NOT_POSSIBLE'), detail: 'not_merge_request' },
    });
    const { fixture, root } = await render();
    expect(root.querySelector('#ai-fix-before')?.textContent).toContain('if (a == 1) {}');
    expect(root.querySelector('#ai-fix-after')?.textContent).toContain('if (a === 1) {}');
    expect(root.querySelector('#ai-fix-before')?.tagName).toBe('PRE');
    button(root, 'Post to merge request').click();
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/ai-requests/f1/post')).toHaveLength(0);
    // The confirmation names the merge request.
    expect(root.textContent).toContain('merge request !42 “Refund limits”');
    button(root, 'Confirm: post as a suggestion').click();
    await settle(fixture);
    expect(root.textContent).toContain('This issue is not on a merge request.');
  });

  it('cancels a post, and shows why a post failed', async () => {
    const server = setup();
    server.on('GET', '/api/v0/issues/i1/ai', {
      body: {
        explain: null,
        triage: null,
        fix: { ...FIX, post: { status: 'failed', reason: 'not_head', url: null, at: '' } },
      },
    });
    const { fixture, root } = await render();
    expect(root.textContent).toContain(
      'Not posted: the merge request has a newer commit; analyse it and ask again',
    );
    button(root, 'Post to merge request').click();
    await settle(fixture);
    button(root, 'Cancel').click();
    await settle(fixture);
    expect(button(root, 'Confirm: post as a suggestion')).toBeUndefined();
    expect(server.requestsTo('POST', '/api/v0/ai-requests/f1/post')).toHaveLength(0);
  });

  it.each([
    ['https://gitlab.example/g/p/-/merge_requests/1#note_1', true],
    ['javascript:alert(1)', false],
  ])('links a posted suggestion only by its http(s) address (%s)', async (url, linked) => {
    const server = setup();
    server.on('GET', '/api/v0/issues/i1/ai', {
      body: {
        explain: null,
        triage: null,
        fix: { ...FIX, post: { status: 'posted', reason: null, url, at: '' } },
      },
    });
    const { root } = await render();
    expect(root.textContent).toContain('Posted');
    const link = root.querySelector<HTMLAnchorElement>('a');
    if (linked) {
      expect(link?.href).toBe(url);
      expect(link?.rel).toBe('noopener noreferrer');
      expect(link?.target).toBe('_blank');
    } else {
      expect(link).toBeNull();
    }
    expect(button(root, 'Post to merge request')).toBeUndefined();
  });

  it('names a used-up budget', async () => {
    const server = setup();
    server.on('POST', '/api/v0/issues/i1/ai/fix', {
      status: 429,
      headers: { 'retry-after': '3600' },
      body: problem(429, 'AI_QUOTA_EXCEEDED'),
    });
    const { fixture, root } = await render();
    button(root, 'Suggest a fix').click();
    await settle(fixture);
    expect(root.querySelector('[role="alert"]')?.textContent).toContain(
      "The organisation's AI budget for today is used up.",
    );
  });

  it('names an issue that is never sent', async () => {
    const server = setup();
    server.on('POST', '/api/v0/issues/i1/ai/explain', {
      status: 409,
      body: { ...problem(409, 'AI_NOT_ELIGIBLE'), detail: 'secret_rule' },
    });
    const { fixture, root } = await render();
    button(root, 'Explain').click();
    await settle(fixture);
    expect(root.querySelector('[role="alert"]')?.textContent).toContain(
      'Findings of secret rules are never sent.',
    );
  });

  it('shows a failed request in its own words', async () => {
    const server = setup();
    server.on('GET', '/api/v0/issues/i1/ai', {
      body: {
        explain: request({
          status: 'failed',
          error: { code: 'PROVIDER_TIMEOUT', detail: null },
        }),
        triage: null,
        fix: null,
      },
    });
    const { root } = await render();
    expect(root.querySelector('[role="alert"]')?.textContent).toContain(
      'The model did not answer in time',
    );
    expect(server.requests.filter((r) => r.method === 'POST')).toHaveLength(0);
  });

  it('names a GitHub pull request as one', async () => {
    const server = setup();
    server.on('GET', '/api/v0/issues/i1/ai', { body: { explain: null, triage: null, fix: FIX } });
    server.on('GET', '/api/v0/projects/p1/branches', {
      body: page([
        { ...MERGE_REQUEST, mrTitle: null, mrUrl: 'https://github.com/acme/payments/pull/42' },
      ]),
    });
    const { fixture, root } = await render();
    button(root, 'Post to merge request').click();
    await settle(fixture);
    expect(root.textContent).toContain('pull request #42?');
  });

  it('offers no post when the issue is not on a merge request', async () => {
    const server = setup();
    server.on('GET', '/api/v0/issues/i1/ai', { body: { explain: null, triage: null, fix: FIX } });
    server.on('GET', '/api/v0/projects/p1/branches', {
      body: page([{ ...MERGE_REQUEST, kind: 'branch', mrTitle: null, mrUrl: null }]),
    });
    const { root } = await render();
    expect(root.querySelector('#ai-fix-after')).not.toBeNull();
    expect(button(root, 'Post to merge request')).toBeUndefined();
  });

  it('offers no post, and reads no branch, when the project is not mapped', async () => {
    const server = setup(ORG_AI, { scmConnectionId: null });
    server.on('GET', '/api/v0/issues/i1/ai', { body: { explain: null, triage: null, fix: FIX } });
    const { root } = await render();
    expect(root.querySelector('#ai-fix-after')).not.toBeNull();
    expect(button(root, 'Post to merge request')).toBeUndefined();
    expect(server.requestsTo('GET', '/api/v0/projects/p1/branches')).toHaveLength(0);
  });

  it('offers neither a post nor a false positive for an answer about another issue', async () => {
    const server = setup();
    server.on('GET', '/api/v0/issues/i1/ai', {
      body: {
        explain: null,
        triage: request({
          id: 't1',
          issueId: 'i2',
          feature: 'triage',
          status: 'succeeded',
          result: {
            kind: 'triage',
            verdict: 'likely_false_positive',
            confidence: 'high',
            reasons: ['a is a number'],
          },
        }),
        fix: { ...FIX, issueId: 'i2' },
      },
    });
    const { root } = await render();
    expect(root.textContent).toContain('Likely a false positive');
    expect(button(root, 'Mark as false positive…')).toBeUndefined();
    expect(button(root, 'Post to merge request')).toBeUndefined();
  });

  it('shows a viewer the answers others asked for, without a button that would be refused', async () => {
    const server = setup();
    server.on('GET', '/api/v0/issues/i1/ai', {
      body: {
        explain: request({
          status: 'succeeded',
          result: {
            kind: 'explain',
            summary: 'Loose equality.',
            explanation: 'Coerces.',
            howToFix: null,
          },
        }),
        triage: request({
          id: 't1',
          feature: 'triage',
          status: 'succeeded',
          result: {
            kind: 'triage',
            verdict: 'likely_false_positive',
            confidence: 'high',
            reasons: ['a is a number'],
          },
        }),
        fix: FIX,
      },
    });
    const fixture = TestBed.createComponent(AiPanel);
    fixture.componentRef.setInput('issue', ISSUE);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(root.textContent).toContain('Loose equality.');
    expect(root.textContent).toContain('Likely a false positive');
    expect(root.querySelectorAll('button')).toHaveLength(0);
    expect(root.textContent).not.toContain('Asking sends');
  });

  it('offers a viewer no feature to ask for, beside an answer', async () => {
    const server = setup();
    server.on('GET', '/api/v0/issues/i1/ai', {
      body: {
        explain: request({
          status: 'succeeded',
          result: {
            kind: 'explain',
            summary: 'Loose equality.',
            explanation: 'Coerces.',
            howToFix: null,
          },
        }),
        triage: null,
        fix: null,
      },
    });
    const fixture = TestBed.createComponent(AiPanel);
    fixture.componentRef.setInput('issue', ISSUE);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(root.textContent).toContain('Loose equality.');
    expect(button(root, 'Suggest triage')).toBeUndefined();
    expect(button(root, 'Suggest a fix')).toBeUndefined();
  });

  it('is absent for a viewer when nobody asked anything yet', async () => {
    setup();
    const fixture = TestBed.createComponent(AiPanel);
    fixture.componentRef.setInput('issue', ISSUE);
    await settle(fixture);
    expect((fixture.nativeElement as HTMLElement).querySelector('section')).toBeNull();
  });

  it('offers no false positive to someone who may ask but not triage', async () => {
    const server = setup();
    server.on('GET', '/api/v0/issues/i1/ai', {
      body: {
        explain: null,
        triage: request({
          id: 't1',
          feature: 'triage',
          status: 'succeeded',
          result: {
            kind: 'triage',
            verdict: 'likely_false_positive',
            confidence: 'high',
            reasons: ['a is a number'],
          },
        }),
        fix: null,
      },
    });
    const fixture = TestBed.createComponent(AiPanel);
    fixture.componentRef.setInput('issue', ISSUE);
    fixture.componentRef.setInput('canAsk', true);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(button(root, 'Explain')).toBeDefined();
    expect(button(root, 'Mark as false positive…')).toBeUndefined();
  });

  it('reads a request again after a failed poll', async () => {
    const server = setup();
    server.on('POST', '/api/v0/issues/i1/ai/explain', { status: 202, body: request({}) });
    let polls = 0;
    server.on('GET', '/api/v0/ai-requests/r1', () =>
      ++polls === 1
        ? { status: 503, body: problem(503, 'UNAVAILABLE') }
        : {
            body: request({
              status: 'succeeded',
              finishedAt: '2026-09-26T10:00:05.000Z',
              result: { kind: 'explain', summary: 'Sum.', explanation: 'Why.', howToFix: '' },
            }),
          },
    );
    const { fixture, root } = await render();
    button(root, 'Explain').click();
    await settle(fixture);
    await wait(POLL_MS * 8);
    await settle(fixture);
    expect(polls).toBe(2);
    expect(root.textContent).toContain('Why.');
    expect(root.querySelector('[role="alert"]')).toBeNull();
  });

  it('stops after repeated poll failures, and the person can ask again', async () => {
    const server = setup();
    server.on('POST', '/api/v0/issues/i1/ai/explain', { status: 202, body: request({}) });
    server.on('GET', '/api/v0/ai-requests/r1', {
      status: 500,
      body: problem(500, 'INTERNAL'),
    });
    const { fixture, root } = await render();
    button(root, 'Explain').click();
    await settle(fixture);
    // Back-off: 1, 2, 4 and 8 intervals.
    await wait(POLL_MS * 25);
    await settle(fixture);
    const polls = server.requestsTo('GET', '/api/v0/ai-requests/r1').length;
    expect(polls).toBe(4);
    expect(root.querySelector('[role="alert"]')?.textContent).toContain(
      'The answer could not be read; ask again.',
    );
    expect(root.querySelector('[role="status"]')?.textContent).not.toContain('Asking the model');
    expect(button(root, 'Explain').getAttribute('aria-disabled')).toBeNull();
    await wait(POLL_MS * 20);
    expect(server.requestsTo('GET', '/api/v0/ai-requests/r1')).toHaveLength(polls);
  });

  it('keeps the other features usable while one is being answered', async () => {
    const server = setup();
    server.on('POST', '/api/v0/issues/i1/ai/explain', { status: 202, body: request({}) });
    server.on('GET', '/api/v0/ai-requests/r1', { body: request({}) });
    server.on('POST', '/api/v0/issues/i1/ai/triage', {
      status: 202,
      body: request({ id: 't1', feature: 'triage' }),
    });
    server.on('GET', '/api/v0/ai-requests/t1', { body: request({ id: 't1', feature: 'triage' }) });
    const { fixture, root } = await render();
    button(root, 'Explain').click();
    await settle(fixture);
    const triage = button(root, 'Suggest triage');
    expect(triage.getAttribute('aria-disabled')).toBeNull();
    triage.click();
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/issues/i1/ai/triage')).toHaveLength(1);
    fixture.destroy();
  });

  it('follows only the features the organisation has on', async () => {
    const server = setup({ ...ORG_AI, features: { explain: true, triage: false, fix: false } });
    server.on('GET', '/api/v0/issues/i1/ai', {
      body: { explain: null, triage: request({ id: 't1', feature: 'triage' }), fix: null },
    });
    server.on('GET', '/api/v0/ai-requests/t1', { body: request({ id: 't1', feature: 'triage' }) });
    const { fixture, root } = await render();
    await wait(POLL_MS * 5);
    await settle(fixture);
    expect(server.requestsTo('GET', '/api/v0/ai-requests/t1')).toHaveLength(0);
    expect(root.querySelector('[role="status"]')?.textContent).not.toContain('Asking the model');
  });
});
