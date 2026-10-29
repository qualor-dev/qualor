import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import {
  FakeServer,
  me,
  MEMBER_PROJECT_PERMISSIONS,
  ORG_ID,
  page,
  problem,
  provideFakeServer,
  settle,
  VIEWER_PROJECT_PERMISSIONS,
} from '../../testing/fake-server';
import { SessionStore } from '../auth/session';
import { CurrentProject } from '../project/current-project';
import { safeHelpUri } from '../shared/links';
import { type IssueDetail, IssuePage, readSnippet } from './issue.page';

/** The project, with a maintainer's permissions on it (rbac-audit.md §16). */
/** The issue's project: a member's, not excluded from AI (the AI panel reads it). */
const PROJECT = {
  id: 'p1',
  organizationId: ORG_ID,
  permissions: [...MEMBER_PROJECT_PERMISSIONS],
  autoFix: { available: true, enabled: true, organizationEnabled: true, excludedFromAi: false },
};

/** Issue ids are UUIDs (anything else is "not found" without a request). */
const ID = '0190a6c2-0000-7000-8000-0000000000a1';
const OTHER = '0190a6c2-0000-7000-8000-0000000000b2';
const DESCRIPTION = 'Compare with `===`.\n\n<script>alert("rule")</script> **never** `==`.';

function detail(overrides: Partial<IssueDetail> = {}): IssueDetail {
  return {
    id: ID,
    projectId: 'p1',
    branchId: 'b1',
    rule: {
      key: 'eslint:eqeqeq',
      name: 'Require === and !==',
      engine: 'eslint',
      descriptionMd: DESCRIPTION,
      helpUri: 'javascript:alert(1)',
      defaultSeverity: 'medium',
      quality: 'reliability',
      kind: 'issue',
      tags: [],
      cwe: [],
    },
    severity: 'high',
    severityOverridden: false,
    quality: 'reliability',
    kind: 'issue',
    status: 'open',
    message: 'Avoid <b>bold</b>',
    path: 'src/refunds/limits.ts',
    startLine: 44,
    startColumn: null,
    endLine: null,
    endColumn: null,
    inNewCode: true,
    duplicateOfIssueId: null,
    confidence: null,
    firstSeenAt: '2026-09-15T09:00:00.000Z',
    resolvedAt: null,
    closedAt: null,
    createdAt: '2026-09-15T09:00:00.000Z',
    updatedAt: '2026-09-15T09:00:00.000Z',
    fingerprint: 'f',
    snippet: { startLine: 43, lines: ['const a = 1;', 'if (a == "1") {'] },
    secondaryLocations: [],
    firstSeenAnalysisId: null,
    lastSeenAnalysisId: null,
    resolvedBy: null,
    aiReview: null,
    ...overrides,
  };
}

describe('IssuePage', () => {
  let server: FakeServer;

  beforeEach(() => {
    server = new FakeServer();
    server.on('GET', `/api/v0/issues/${ID}`, { body: detail() });
    server.on('GET', `/api/v0/issues/${ID}/changelog`, {
      body: page([
        {
          id: 'c1',
          user: { id: 'u', username: 'admin' },
          analysisId: null,
          field: 'status',
          oldValue: 'open',
          newValue: 'false_positive',
          comment: 'On purpose.',
          createdAt: '2026-09-16T10:00:00.000Z',
        },
      ]),
    });
    server.on('GET', '/api/v0/projects/p1', { body: PROJECT });
    TestBed.configureTestingModule({
      imports: [IssuePage],
      providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
    });
    TestBed.inject(SessionStore).set(me());
  });

  async function render() {
    const fixture = TestBed.createComponent(IssuePage);
    fixture.componentRef.setInput('projectId', 'p1');
    fixture.componentRef.setInput('issueId', ID);
    await settle(fixture);
    return { fixture, root: fixture.nativeElement as HTMLElement };
  }

  const buttonIn = (root: HTMLElement, name: string) =>
    [...root.querySelectorAll('button')].find((b) => b.textContent?.trim() === name);

  it('tags a medium-confidence finding of the C# taint engine Possible, says why, and shows the confidence (R-9)', async () => {
    server.on('GET', `/api/v0/issues/${ID}`, { body: detail({ confidence: 'medium' }) });
    const { root } = await render();
    const tags = [...root.querySelectorAll('.issue-tags .badge')].map((b) => b.textContent?.trim());
    expect(tags).toContain('Possible');
    expect(root.querySelector('.issue-header')?.textContent).toContain(
      'goes through stored data, a lookup by a key or a call it could not narrow down',
    );
    const details = [...root.querySelectorAll('.details-list dt')].map((d) => [
      d.textContent?.trim(),
      d.nextElementSibling?.textContent?.trim(),
    ]);
    expect(details).toContainEqual(['Confidence', 'Possible']);
  });

  it('does not explain Possible with the taint engine’s words for a finding of the AI review', async () => {
    server.on('GET', `/api/v0/issues/${ID}`, {
      body: detail({
        confidence: 'medium',
        rule: { ...detail().rule, key: 'ai:logic', name: 'AI review: logic error', engine: 'ai' },
      }),
    });
    const { root } = await render();
    const tags = [...root.querySelectorAll('.issue-tags .badge')].map((b) => b.textContent?.trim());
    expect(tags).toContain('Possible');
    // That note is about stored data and lookups by a key: it says nothing of a model's doubt.
    expect(root.querySelector('.issue-header')?.textContent).not.toContain('stored data');
  });

  it('shows a high confidence in the details only, and nothing for a finding without one', async () => {
    server.on('GET', `/api/v0/issues/${ID}`, { body: detail({ confidence: 'high' }) });
    const high = (await render()).root;
    expect(
      [...high.querySelectorAll('.issue-tags .badge')].map((b) => b.textContent?.trim()),
    ).not.toContain('Possible');
    expect(
      [...high.querySelectorAll('.details-list dt')].map((d) => d.textContent?.trim()),
    ).toContain('Confidence');
    server.on('GET', `/api/v0/issues/${ID}`, { body: detail() });
    const none = (await render()).root;
    expect(
      [...none.querySelectorAll('.details-list dt')].map((d) => d.textContent?.trim()),
    ).not.toContain('Confidence');
  });

  it('shows messages and the Markdown description as text, and no unsafe link', async () => {
    const { root } = await render();
    expect(root.querySelector('h2')?.textContent).toBe('Avoid <b>bold</b>');
    expect(root.querySelector('h2 b')).toBeNull();
    const description = root.querySelector('[aria-labelledby="rule-heading"] .prose-text');
    expect(description?.textContent).toBe(DESCRIPTION);
    expect(root.querySelector('script')).toBeNull();
    expect(root.querySelector('a[target="_blank"]')).toBeNull();
    expect(root.querySelector('.snippet-line.hit')?.textContent).toBe('44if (a == "1") {');
    expect(root.querySelector('ol li')?.textContent).toContain('Status: Open → False positive');
    // Dates read the same for everyone: UTC, labelled.
    expect(root.querySelector('ol li')?.textContent).toContain('Sep 16, 2026, 10:00 AM UTC');
  });

  it('lists the details beside the story: severity, status, type, quality, rule, file, first seen, branch', async () => {
    server.on('GET', '/api/v0/projects/p1/branches', {
      body: page([
        {
          id: 'b1',
          projectId: 'p1',
          kind: 'branch',
          name: 'main',
          isMain: true,
          mrSourceBranch: null,
          mrTargetBranch: null,
          mrTitle: null,
          mrUrl: null,
          lastAnalysisId: null,
          lastAnalyzedAt: null,
          gateStatus: null,
          measures: {},
        },
      ]),
    });
    const { root } = await render();
    const details = root.querySelector('aside dl.details-list');
    const rows = [...(details?.querySelectorAll('dt') ?? [])].map((dt) => [
      dt.textContent?.trim(),
      dt.nextElementSibling?.textContent?.replace(/\s+/g, ' ').trim(),
    ]);
    expect(rows).toEqual([
      ['Severity', 'High'],
      ['Status', 'Open'],
      ['Type', 'Issue'],
      ['Software quality', 'Reliability'],
      ['Rule', 'eslint:eqeqeq'],
      ['File', 'src/refunds/limits.ts:44'],
      ['First seen', 'Sep 15, 2026, 9:00 AM UTC'],
      ['Branch', 'main'],
    ]);
    // The actions sit in the same column, under the details.
    expect(root.querySelector('aside #actions-heading')).not.toBeNull();
    // The code window names its file and the line.
    expect(root.querySelector('.code-head')?.textContent?.replace(/\s+/g, ' ').trim()).toBe(
      'src/refunds/limits.ts Line 44',
    );
  });

  it('leaves out the file and the code without a location, and the branch when its lookup fails', async () => {
    server.on('GET', `/api/v0/issues/${ID}`, {
      body: detail({ path: null, startLine: null, snippet: null }),
    });
    const { root } = await render();
    const terms = [...root.querySelectorAll('dl.details-list dt')].map((dt) =>
      dt.textContent?.trim(),
    );
    expect(terms).toEqual(['Severity', 'Status', 'Type', 'Software quality', 'Rule', 'First seen']);
    expect(root.querySelector('.code-window')).toBeNull();
  });

  it('keeps the line number whole: it sits in its own no-wrap span after the path', async () => {
    const { root } = await render();
    const code = root.querySelector('a.details-file code');
    expect(code?.textContent).toBe('src/refunds/limits.ts:44');
    const line = code?.querySelector('span.details-line');
    expect(line?.textContent).toBe(':44');
    expect(getComputedStyle(line!).whiteSpace).toBe('nowrap');
  });

  it('keeps the file name and the line number together, the directory may wrap', async () => {
    const { root } = await render();
    const code = root.querySelector('a.details-file code')!;
    const tail = code.querySelector('span.details-tail');
    expect(code.firstChild?.textContent).toBe('src/refunds/');
    expect(tail?.textContent).toBe('limits.ts:44');
    expect(getComputedStyle(tail!).display).toBe('inline-block');
    expect(root.querySelector('a.details-file')?.textContent?.trim()).toBe(
      'src/refunds/limits.ts:44',
    );
  });

  it('puts a path without a slash wholly in the tail', async () => {
    server.on('GET', `/api/v0/issues/${ID}`, {
      body: detail({ path: 'package-lock.json', startLine: 3, snippet: null }),
    });
    const { root } = await render();
    const code = root.querySelector('a.details-file code')!;
    expect(code.firstChild?.textContent ?? '').toBe('');
    expect(code.querySelector('span.details-tail')?.textContent).toBe('package-lock.json:3');
  });

  it('shows the merge request the issue is on in the project band, and lets go on destroy', async () => {
    server.on('GET', '/api/v0/projects/p1/branches', {
      body: page([
        {
          id: 'b1',
          projectId: 'p1',
          kind: 'merge_request',
          name: '42',
          isMain: false,
          mrSourceBranch: 'feature/x',
          mrTargetBranch: 'main',
          mrTitle: null,
          mrUrl: null,
          lastAnalysisId: null,
          lastAnalyzedAt: null,
          gateStatus: 'passed',
          measures: { issues: 3 },
        },
      ]),
    });
    const { fixture } = await render();
    const store = TestBed.inject(CurrentProject);
    expect(store.shownBranch()?.id).toBe('b1');
    expect(store.shownBranch()?.issues).toBe(3);
    fixture.destroy();
    expect(store.shownBranch()).toBeNull();
  });

  it('links the File entry to the file page at the line, also without a snippet', async () => {
    server.on('GET', `/api/v0/issues/${ID}`, {
      body: detail({ path: 'src/refunds/limits.ts', startLine: 44, snippet: null }),
    });
    const { root } = await render();
    expect(root.querySelector('.code-window')).toBeNull();
    const file = [...root.querySelectorAll('dl.details-list dt')].find(
      (dt) => dt.textContent?.trim() === 'File',
    );
    const link = file?.nextElementSibling?.querySelector('a');
    expect(link?.textContent?.trim()).toBe('src/refunds/limits.ts:44');
    expect(link?.getAttribute('href')).toBe(
      '/projects/p1/code/file?branch=b1&path=src%2Frefunds%2Flimits.ts#L44',
    );
  });

  it('links a location with a path and no line (a lockfile, 6M) to the file without a line', async () => {
    server.on('GET', `/api/v0/issues/${ID}`, {
      body: detail({ path: 'package-lock.json', startLine: null, snippet: null }),
    });
    const { root } = await render();
    const file = [...root.querySelectorAll('dl.details-list dt')].find(
      (dt) => dt.textContent?.trim() === 'File',
    );
    const link = file?.nextElementSibling?.querySelector('a');
    expect(link?.textContent?.trim()).toBe('package-lock.json');
    expect(link?.getAttribute('href')).toBe(
      '/projects/p1/code/file?branch=b1&path=package-lock.json',
    );
  });

  it('links an http(s) rule documentation in a new tab without an opener or referrer', async () => {
    server.on('GET', `/api/v0/issues/${ID}`, {
      body: detail({
        rule: { ...detail().rule, helpUri: 'https://eslint.org/docs/latest/rules/eqeqeq' },
      }),
    });
    const { root } = await render();
    const link = root.querySelector<HTMLAnchorElement>('a[target="_blank"]')!;
    expect(link.getAttribute('href')).toBe('https://eslint.org/docs/latest/rules/eqeqeq');
    expect(link.getAttribute('rel')).toBe('noopener noreferrer');
    expect(link.textContent?.trim()).toBe('Rule documentation');
  });

  describe('related locations', () => {
    async function renderWith(overrides: Partial<IssueDetail>) {
      server.on('GET', `/api/v0/issues/${ID}`, { body: detail(overrides) });
      return render();
    }
    const panelOf = (root: HTMLElement) =>
      root.querySelector('[aria-labelledby="related-heading"]');

    it('lists related locations in report order, linking to the file page (spec §6.1)', async () => {
      const { root } = await renderWith({
        path: 'src/refunds/limits.ts',
        startLine: 12,
        snippet: { startLine: 10, lines: ['a', 'b', 'c', 'd', 'e'] },
        secondaryLocations: [
          { path: 'src/refunds/limits.ts', startLine: 11, message: 'Policy read from the order' },
          { path: 'src/payments/gateway.ts', startLine: 40, endLine: 44 },
        ],
      });
      const panel = panelOf(root)!;
      expect(panel.querySelector('h3')?.textContent?.trim()).toBe('Related locations');
      const steps = [...panel.querySelectorAll('li')];
      expect(steps.map((li) => li.querySelector('.step-no')?.textContent?.trim())).toEqual([
        '1',
        '2',
      ]);
      expect(steps[0]!.textContent).toContain('Policy read from the order');
      expect(steps[0]!.textContent).toContain('This file');
      expect(steps[1]!.textContent).toContain('Related location');
      expect(steps[1]!.querySelector('a')?.textContent?.trim()).toBe(
        'src/payments/gateway.ts:40–44',
      );
      const href = steps[1]!.querySelector('a')!.getAttribute('href')!;
      expect(href).toContain('/code/file?');
      expect(href).toContain('path=src%2Fpayments%2Fgateway.ts');
      expect(href).toContain('#L40');
      // Step 1 lies inside the snippet (lines 10–14): its gutter carries the marker.
      const marked = root.querySelector('.snippet-line.related');
      expect(marked?.querySelector('.ln')?.textContent?.trim()).toBe('11');
      expect(marked?.querySelector('.step-mark')?.textContent?.trim()).toBe('1');
      // The marks sit together in one gutter overlay, out of the code text's flow.
      const marks = marked?.querySelector('.step-marks');
      expect(marks?.getAttribute('aria-hidden')).toBe('true');
      expect(marks?.querySelectorAll('.step-mark')).toHaveLength(1);
    });

    it('collapses more than 5 related locations behind "N more"', async () => {
      const many = Array.from({ length: 7 }, (_, i) => ({ path: 'src/a.ts', startLine: 100 + i }));
      const { root, fixture } = await renderWith({ secondaryLocations: many });
      expect(panelOf(root)!.querySelectorAll('li')).toHaveLength(5);
      buttonIn(root, '2 more')!.click();
      await settle(fixture);
      expect(panelOf(root)!.querySelectorAll('li')).toHaveLength(7);
    });

    it('shows no related-locations panel when there are none', async () => {
      const { root } = await renderWith({ secondaryLocations: [] });
      expect(panelOf(root)).toBeNull();
    });

    it("links the primary location's path to the file page", async () => {
      const { root } = await renderWith({ path: 'src/a.ts', startLine: 3 });
      const link = root.querySelector<HTMLAnchorElement>('.code-head a')!;
      expect(link.textContent?.trim()).toBe('src/a.ts');
      expect(link.getAttribute('href')).toContain('#L3');
    });
  });

  describe('the AI review of a finding', () => {
    type Review = NonNullable<IssueDetail['aiReview']>;
    const REVIEW: Review = {
      category: 'logic',
      body: 'The loop stops <b>one element early</b>.\nThe last item is never summed.',
      assumption: 'The list is never empty.',
      verification: 'needs_validation',
      suggestion: { startLine: 12, endLine: 13, lines: ['for (const x of xs) {', '  total += x;'] },
      reviewedCommit: 'c0ffee0123456789abcdef0123456789abcdef01',
    };
    async function renderReview(review: Partial<Review> | null) {
      server.on('GET', `/api/v0/issues/${ID}`, {
        body: detail({
          rule: {
            ...detail().rule,
            key: 'ai:logic',
            name: 'AI review: logic error',
            engine: 'ai',
          },
          aiReview: review === null ? null : { ...REVIEW, ...review },
        }),
      });
      return render();
    }
    const cardOf = (root: HTMLElement) =>
      root.querySelector<HTMLElement>('[aria-labelledby="ai-review-heading"]');
    const flat = (el: Element | null | undefined) => el?.textContent?.replace(/\s+/g, ' ').trim();

    it("the Assumes line starts with 'Assumes:', with no leading space", async () => {
      const { root } = await renderReview({});
      const line = cardOf(root)!.querySelector<HTMLElement>('.ai-review-assumption')!;
      // The paragraph keeps its white space collapsed (no pre-wrap), so the i18n text's own space
      // at the start is not shown; the model's assumption, a span of its own, keeps its line breaks.
      expect(line.classList.contains('prose-text')).toBe(false);
      expect(getComputedStyle(line).whiteSpace).not.toBe('pre-wrap');
      expect(line.textContent?.trimStart().startsWith('Assumes:')).toBe(true);
      const assumed = line.querySelector<HTMLElement>('span.prose-text')!;
      expect(assumed.textContent).toBe('The list is never empty.');
    });

    it('shows the finding as text with what it assumes, the second check, the suggestion, the commit and the notice', async () => {
      const { root } = await renderReview({});
      const card = cardOf(root)!;
      expect(card.querySelector('h3')?.textContent?.trim()).toBe('AI review');
      // The model's words are text: no markup of theirs is ever built, and the line break stays.
      const body = card.querySelector('.ai-review-body')!;
      expect(body.textContent).toBe(REVIEW.body);
      expect(card.querySelector('b')).toBeNull();
      expect(flat(card.querySelector('.ai-review-assumption'))).toBe(
        'Assumes: The list is never empty.',
      );
      expect(flat(card.querySelector('.ai-review-verification'))).toBe(
        'A second check could not confirm it: check it yourself.',
      );
      expect(flat(card.querySelector('.ai-review-suggestion h4'))).toBe(
        'Suggested change (lines 12–13)',
      );
      const lines = [...card.querySelectorAll('.ai-review-suggestion pre .snippet-line')];
      expect(lines.map((l) => l.querySelector('.ln')?.textContent?.trim())).toEqual(['12', '13']);
      expect(lines.map((l) => l.textContent)).toEqual([
        '12for (const x of xs) {',
        '13  total += x;',
      ]);
      expect(flat(card.querySelector('.ai-review-commit'))).toBe('Reviewed commit c0ffee012345');
      expect(flat(card.querySelector('.ai-review-notice'))).toBe(
        'Found by AI review. It may be wrong, and it never counts in the quality gate.',
      );
    });

    it('says when a second check confirmed the finding', async () => {
      const { root } = await renderReview({ verification: 'confirmed' });
      expect(flat(cardOf(root)!.querySelector('.ai-review-verification'))).toBe(
        'A second check confirmed it.',
      );
    });

    it('names a one-line suggestion by its line', async () => {
      const { root } = await renderReview({
        suggestion: { startLine: 12, endLine: 12, lines: ['total += x;'] },
      });
      expect(flat(cardOf(root)!.querySelector('.ai-review-suggestion h4'))).toBe(
        'Suggested change (line 12)',
      );
    });

    it('says a suggestion without lines deletes the ones it names', async () => {
      const { root } = await renderReview({
        suggestion: { startLine: 12, endLine: 13, lines: [] },
      });
      const suggestion = cardOf(root)!.querySelector('.ai-review-suggestion')!;
      expect(flat(suggestion.querySelector('h4'))).toBe('Suggested change (lines 12–13)');
      expect(suggestion.querySelector('pre')).toBeNull();
      expect(flat(suggestion)).toContain('The suggestion deletes these lines.');
    });

    it('leaves out what the review did not say', async () => {
      const { root } = await renderReview({
        assumption: null,
        verification: null,
        suggestion: null,
      });
      const card = cardOf(root)!;
      expect(card.querySelector('.ai-review-assumption')).toBeNull();
      expect(card.querySelector('.ai-review-verification')).toBeNull();
      expect(card.querySelector('.ai-review-suggestion')).toBeNull();
      // The finding, the commit and the notice are always there.
      expect(card.querySelector('.ai-review-body')?.textContent).toBe(REVIEW.body);
      expect(card.querySelector('.ai-review-commit')).not.toBeNull();
      expect(card.querySelector('.ai-review-notice')).not.toBeNull();
    });

    it('shows no card for an issue the analyzers reported', async () => {
      const { root } = await renderReview(null);
      expect(cardOf(root)).toBeNull();
      expect(root.querySelector('.ai-review-notice')).toBeNull();
    });
  });

  it('asks for a comment before a false positive, then sends it', async () => {
    server.on('POST', `/api/v0/issues/${ID}/transition`, {
      body: detail({ status: 'false_positive' }),
    });
    const { fixture, root } = await render();
    const button = (name: string) => buttonIn(root, name)!;
    expect(button('False positive').disabled).toBe(true);
    expect(button('Resolve').disabled).toBe(false);
    const comment = root.querySelector<HTMLTextAreaElement>('#issue-comment')!;
    comment.value = 'Test data only';
    comment.dispatchEvent(new Event('input'));
    await settle(fixture);
    button('False positive').click();
    await settle(fixture);
    expect(server.requestsTo('POST', `/api/v0/issues/${ID}/transition`)[0]?.body).toEqual({
      to: 'false_positive',
      comment: 'Test data only',
    });
    expect(button('Reopen')).toBeDefined();
    expect(server.requestsTo('GET', `/api/v0/issues/${ID}/changelog`)).toHaveLength(2);
    // The button used is gone: focus is on the section heading, and the result is announced.
    expect(document.activeElement).toBe(root.querySelector('#actions-heading'));
    expect(root.querySelector('[role="status"]')?.textContent?.trim()).toBe(
      'Status changed to False positive.',
    );
  });

  it('sends the suggestion id with the false-positive transition the panel opened', async () => {
    server.on('GET', '/api/v0/projects/p1', { body: PROJECT });
    server.on('GET', `/api/v0/organizations/${ORG_ID}/ai`, {
      body: {
        enabled: true,
        features: { explain: true, triage: true, fix: false },
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
          reviewTokensPerOrganizationPerDay: null,
        },
      },
    });
    server.on('GET', `/api/v0/issues/${ID}/ai`, {
      body: {
        explain: null,
        triage: {
          id: 't1',
          issueId: ID,
          feature: 'triage',
          status: 'succeeded',
          model: 'qwen2.5-coder',
          promptVersion: 'triage.v1',
          createdAt: '2026-09-26T10:00:00.000Z',
          finishedAt: '2026-09-26T10:00:03.000Z',
          error: null,
          result: {
            kind: 'triage',
            verdict: 'likely_false_positive',
            confidence: 'high',
            reasons: ['a is a number'],
          },
          post: null,
        },
        fix: null,
      },
    });
    server.on('POST', `/api/v0/issues/${ID}/transition`, {
      body: detail({ status: 'false_positive' }),
    });
    const { fixture, root } = await render();
    const comment = root.querySelector<HTMLTextAreaElement>('#issue-comment')!;
    comment.value = 'Draft';
    comment.dispatchEvent(new Event('input'));
    await settle(fixture);
    buttonIn(root, 'Mark as false positive…')!.click();
    await settle(fixture);
    // The person's own form, with an empty comment, focused; nothing was sent.
    expect(comment.value).toBe('');
    expect(document.activeElement).toBe(comment);
    expect(server.requestsTo('POST', `/api/v0/issues/${ID}/transition`)).toHaveLength(0);
    expect(buttonIn(root, 'False positive')!.disabled).toBe(true);
    comment.value = 'Only test data reaches this line';
    comment.dispatchEvent(new Event('input'));
    await settle(fixture);
    buttonIn(root, 'False positive')!.click();
    await settle(fixture);
    expect(server.requestsTo('POST', `/api/v0/issues/${ID}/transition`)[0]?.body).toEqual({
      to: 'false_positive',
      comment: 'Only test data reaches this line',
      suggestionId: 't1',
    });
  });

  it('does not send the suggestion id with another status', async () => {
    server.on('POST', `/api/v0/issues/${ID}/transition`, {
      body: detail({ status: 'resolved' }),
    });
    const { fixture, root } = await render();
    (
      fixture.componentInstance as unknown as { openFalsePositive(id: string): void }
    ).openFalsePositive('t1');
    await settle(fixture);
    buttonIn(root, 'Resolve')!.click();
    await settle(fixture);
    expect(server.requestsTo('POST', `/api/v0/issues/${ID}/transition`)[0]?.body).toEqual({
      to: 'resolved',
    });
  });

  it('keeps the suggestion id when the false-positive change fails, until one succeeds', async () => {
    server.on('POST', `/api/v0/issues/${ID}/transition`, {
      status: 500,
      body: problem(500, 'INTERNAL'),
    });
    const { fixture, root } = await render();
    (
      fixture.componentInstance as unknown as { openFalsePositive(id: string): void }
    ).openFalsePositive('t1');
    await settle(fixture);
    const comment = root.querySelector<HTMLTextAreaElement>('#issue-comment')!;
    comment.value = 'Checked by hand';
    comment.dispatchEvent(new Event('input'));
    await settle(fixture);
    buttonIn(root, 'False positive')!.click();
    await settle(fixture);
    expect(root.querySelector('[role="alert"]')).not.toBeNull();
    // Refused: the note stays, and pressing again still records the suggestion.
    expect(root.querySelector('#issue-suggestion')).not.toBeNull();
    server.on('POST', `/api/v0/issues/${ID}/transition`, {
      body: detail({ status: 'false_positive' }),
    });
    buttonIn(root, 'False positive')!.click();
    await settle(fixture);
    const sent = server.requestsTo('POST', `/api/v0/issues/${ID}/transition`);
    expect(sent).toHaveLength(2);
    expect(sent[1]?.body).toEqual({
      to: 'false_positive',
      comment: 'Checked by hand',
      suggestionId: 't1',
    });
    expect(root.querySelector('#issue-suggestion')).toBeNull();
  });

  it('offers no transition on a closed issue', async () => {
    server.on('GET', `/api/v0/issues/${ID}`, { body: detail({ status: 'closed' }) });
    const { root } = await render();
    expect(root.querySelector('#issue-comment')).toBeNull();
    for (const name of ['Resolve', "Won't fix", 'False positive', 'Reopen']) {
      expect(buttonIn(root, name)).toBeUndefined();
    }
  });

  it('overrides the severity, which the history then shows', async () => {
    server.on('PATCH', `/api/v0/issues/${ID}`, {
      body: detail({ severity: 'blocker', severityOverridden: true }),
    });
    const { fixture, root } = await render();
    const save = buttonIn(root, 'Set severity')!;
    const select = root.querySelector<HTMLSelectElement>('#issue-severity')!;
    expect(save.disabled).toBe(true);
    // Setting the current severity again logs nothing (api.md): not offered.
    select.value = 'high';
    select.dispatchEvent(new Event('change'));
    await settle(fixture);
    expect(save.disabled).toBe(true);
    select.value = 'blocker';
    select.dispatchEvent(new Event('change'));
    await settle(fixture);
    server.on('GET', `/api/v0/issues/${ID}/changelog`, {
      body: page([
        {
          id: 'c2',
          user: { id: 'u', username: 'admin' },
          analysisId: null,
          field: 'severity',
          oldValue: 'high',
          newValue: 'blocker',
          comment: null,
          createdAt: '2026-09-17T10:00:00.000Z',
        },
      ]),
    });
    save.click();
    await settle(fixture);
    expect(server.requestsTo('PATCH', `/api/v0/issues/${ID}`)[0]?.body).toEqual({
      severity: 'blocker',
    });
    expect(root.querySelector('header .badge')?.textContent).toBe('Blocker');
    expect(root.textContent).toContain('(set by a person)');
    expect(root.querySelector('ol li')?.textContent).toContain('Severity: High → Blocker');
    expect(save.disabled).toBe(true);
  });

  it('offers a retry after 503 CONCURRENCY_CONFLICT and keeps the comment', async () => {
    let calls = 0;
    server.on('POST', `/api/v0/issues/${ID}/transition`, () =>
      ++calls === 1
        ? {
            status: 503,
            headers: { 'retry-after': '1' },
            body: problem(503, 'CONCURRENCY_CONFLICT'),
          }
        : { body: detail({ status: 'wont_fix' }) },
    );
    const { fixture, root } = await render();
    const comment = root.querySelector<HTMLTextAreaElement>('#issue-comment')!;
    comment.value = 'Legacy code';
    comment.dispatchEvent(new Event('input'));
    await settle(fixture);
    buttonIn(root, "Won't fix")!.click();
    await settle(fixture);
    expect(root.querySelector('[role="alert"]')?.textContent).toContain('Try again in 1 s.');
    expect(comment.value).toBe('Legacy code');
    expect(buttonIn(root, 'Try again')!.disabled).toBe(true);
    await new Promise((resolve) => setTimeout(resolve, 1_050));
    await settle(fixture);
    buttonIn(root, 'Try again')!.click();
    await settle(fixture);
    const sent = server.requestsTo('POST', `/api/v0/issues/${ID}/transition`);
    expect(sent.map((r) => r.body)).toEqual([
      { to: 'wont_fix', comment: 'Legacy code' },
      { to: 'wont_fix', comment: 'Legacy code' },
    ]);
    expect(root.querySelector('[role="alert"]')).toBeNull();
    expect(buttonIn(root, 'Reopen')).toBeDefined();
    expect(root.querySelector('[role="status"]')?.textContent?.trim()).toBe(
      "Status changed to Won't fix.",
    );
  });

  it('shows a refused transition by its code, without a retry', async () => {
    server.on('POST', `/api/v0/issues/${ID}/transition`, {
      status: 409,
      body: problem(409, 'INVALID_TRANSITION'),
    });
    const { fixture, root } = await render();
    buttonIn(root, 'Resolve')!.click();
    await settle(fixture);
    expect(root.querySelector('[role="alert"]')?.textContent).toContain(
      'This status change is not allowed any more',
    );
    expect(buttonIn(root, 'Try again')).toBeUndefined();
  });
});

describe('IssuePage when the route changes or the id is odd', () => {
  let server: FakeServer;

  beforeEach(() => {
    server = new FakeServer();
    server.on('GET', `/api/v0/issues/${ID}`, { body: detail() });
    server.on('GET', `/api/v0/issues/${OTHER}`, {
      body: detail({ id: OTHER, message: 'The other issue', severity: 'low' }),
    });
    for (const id of [ID, OTHER]) {
      server.on('GET', `/api/v0/issues/${id}/changelog`, { body: page([]) });
    }
    server.on('GET', '/api/v0/projects/p1', { body: PROJECT });
    TestBed.configureTestingModule({
      imports: [IssuePage],
      providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
    });
    TestBed.inject(SessionStore).set(me());
  });

  async function render(issueId: string) {
    const fixture = TestBed.createComponent(IssuePage);
    fixture.componentRef.setInput('projectId', 'p1');
    fixture.componentRef.setInput('issueId', issueId);
    await settle(fixture);
    return { fixture, root: fixture.nativeElement as HTMLElement };
  }

  const buttonIn = (root: HTMLElement, name: string) =>
    [...root.querySelectorAll('button')].find((b) => b.textContent?.trim() === name);

  it('says "not found" for an id that is not a UUID, without asking the server', async () => {
    const { root } = await render('i1');
    expect(root.querySelector('[role="alert"]')?.textContent).toContain(
      'This item does not exist, or you cannot see it.',
    );
    // Nothing about the issue, its project or its organisation.
    expect(server.requests.map((r) => r.path)).toEqual([]);
  });

  it('starts clean on another issue and ignores a late answer for the previous one', async () => {
    let release: () => void = () => undefined;
    server.on('POST', `/api/v0/issues/${ID}/transition`, {
      status: 503,
      body: problem(503, 'CONCURRENCY_CONFLICT'),
    });
    server.on(
      'PATCH',
      `/api/v0/issues/${ID}`,
      () =>
        new Promise((resolve) => {
          release = () => resolve({ body: detail({ severity: 'blocker', message: 'Stale' }) });
        }),
    );
    const { fixture, root } = await render(ID);
    const comment = root.querySelector<HTMLTextAreaElement>('#issue-comment')!;
    comment.value = 'For issue A';
    comment.dispatchEvent(new Event('input'));
    await settle(fixture);
    buttonIn(root, "Won't fix")!.click();
    await settle(fixture);
    expect(buttonIn(root, 'Try again')).toBeDefined();
    const select = root.querySelector<HTMLSelectElement>('#issue-severity')!;
    select.value = 'blocker';
    select.dispatchEvent(new Event('change'));
    await settle(fixture);
    buttonIn(root, 'Set severity')!.click();
    await settle(fixture);

    fixture.componentRef.setInput('issueId', OTHER);
    await settle(fixture);
    expect(root.querySelector('h2')?.textContent).toBe('The other issue');
    expect(root.querySelector<HTMLTextAreaElement>('#issue-comment')!.value).toBe('');
    expect(root.querySelector('[role="alert"]')).toBeNull();
    expect(buttonIn(root, 'Try again')).toBeUndefined();
    expect(buttonIn(root, 'Set severity')!.disabled).toBe(true);

    release();
    await settle(fixture);
    expect(root.querySelector('h2')?.textContent).toBe('The other issue');
    expect(root.querySelector('header .badge')?.textContent).toBe('Low');
    expect(server.requestsTo('GET', `/api/v0/issues/${ID}/changelog`)).toHaveLength(1);
  });

  it('shows the new history entry after a change, walking to the last page', async () => {
    const entry = (id: string, newValue: string) => ({
      id,
      user: { id: 'u', username: 'admin' },
      analysisId: null,
      field: 'severity' as const,
      oldValue: 'medium',
      newValue,
      comment: null,
      createdAt: '2026-09-17T10:00:00.000Z',
    });
    let changed = false;
    server.on('GET', `/api/v0/issues/${ID}/changelog`, (request) => ({
      body: request.query.get('cursor')
        ? page(changed ? [entry('c2', 'high'), entry('c3', 'blocker')] : [entry('c2', 'high')])
        : page([entry('c1', 'low')], 'p2'),
    }));
    server.on('PATCH', `/api/v0/issues/${ID}`, () => {
      changed = true;
      return { body: detail({ severity: 'blocker', severityOverridden: true }) };
    });
    const { fixture, root } = await render(ID);
    expect(root.querySelectorAll('ol li')).toHaveLength(1);
    const select = root.querySelector<HTMLSelectElement>('#issue-severity')!;
    select.value = 'blocker';
    select.dispatchEvent(new Event('change'));
    await settle(fixture);
    buttonIn(root, 'Set severity')!.click();
    await settle(fixture);
    const items = [...root.querySelectorAll('ol li')].map((li) => li.textContent);
    expect(items).toHaveLength(3);
    expect(items[2]).toContain('Severity: Medium → Blocker');
    expect(root.querySelector('[role="status"]')?.textContent?.trim()).toBe(
      'Severity set to Blocker.',
    );
  });

  it('says so when the history is empty, outside the list', async () => {
    const { root } = await render(ID);
    expect(root.querySelector('ol li')).toBeNull();
    expect(root.querySelector('[aria-labelledby="changelog-heading"] > p')?.textContent).toBe(
      'No changes yet.',
    );
  });
});

describe('IssuePage: actions the caller may not use (rbac-audit.md §17)', () => {
  let server: FakeServer;

  beforeEach(() => {
    server = new FakeServer();
    server.on('GET', `/api/v0/issues/${ID}`, { body: detail() });
    server.on('GET', `/api/v0/issues/${ID}/changelog`, { body: page([]) });
    TestBed.configureTestingModule({
      imports: [IssuePage],
      providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
    });
    TestBed.inject(SessionStore).set(me());
  });

  async function render() {
    const fixture = TestBed.createComponent(IssuePage);
    fixture.componentRef.setInput('projectId', 'p1');
    fixture.componentRef.setInput('issueId', ID);
    await settle(fixture);
    return fixture.nativeElement as HTMLElement;
  }

  it('shows a viewer the issue without the status change and severity, and says why', async () => {
    server.on('GET', '/api/v0/projects/p1', {
      body: { ...PROJECT, permissions: [...VIEWER_PROJECT_PERMISSIONS] },
    });
    const root = await render();
    expect(root.textContent).toContain('Avoid <b>bold</b>');
    expect(root.querySelector('#actions-heading')).toBeNull();
    expect(root.querySelector('#issue-severity')).toBeNull();
    expect(root.textContent).toContain(
      'Your role lets you read this issue, not change its status or severity.',
    );
    // The side column holds Details and, for those who may, Change: each card names itself.
    expect(root.querySelector('aside')?.hasAttribute('aria-labelledby')).toBe(false);
    expect(root.querySelector('section[aria-labelledby="details-heading"]')).not.toBeNull();
    // No assistant to show: its place takes no room, so no gap doubles in the column.
    const ai = root.querySelector('q-ai-panel')!;
    expect(ai.children).toHaveLength(0);
    expect(getComputedStyle(ai).display).toBe('none');
  });

  it('shows no change while the project has not said what the caller may do', async () => {
    server.on('GET', '/api/v0/projects/p1', { status: 500, body: problem(500, 'INTERNAL') });
    const root = await render();
    expect(root.textContent).toContain('Avoid <b>bold</b>');
    expect(root.querySelector('#actions-heading')).toBeNull();
    expect(root.textContent).not.toContain('Your role lets you read this issue');
  });
});

describe('issue helpers', () => {
  it('reads a snippet defensively and keeps only http(s) links', () => {
    expect(readSnippet({ startLine: 3, lines: ['a'] })).toEqual({ startLine: 3, lines: ['a'] });
    expect(readSnippet({ startLine: '3', lines: [] })).toBeNull();
    expect(readSnippet({ startLine: 3, lines: [1] })).toBeNull();
    expect(safeHelpUri('https://eslint.org/docs/latest/rules/eqeqeq')).toBe(
      'https://eslint.org/docs/latest/rules/eqeqeq',
    );
    expect(safeHelpUri('javascript:alert(1)')).toBeNull();
    expect(safeHelpUri('not a url')).toBeNull();
    expect(safeHelpUri('data:text/html,<script>alert(1)</script>')).toBeNull();
    expect(safeHelpUri(' JavaScript:alert(1)')).toBeNull();
    expect(safeHelpUri('//evil.example/x')).toBeNull();
    expect(safeHelpUri(null)).toBeNull();
  });
});
