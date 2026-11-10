import type { Provider } from '@angular/core';
import { FETCH } from '../app/api/api';
import type {
  ComplianceReport,
  PortfolioAggregate,
  PortfolioOverview,
  PortfolioProjectRow,
} from '../app/api/ee';
import type { ItemOf, Me, ResponseBody } from '../app/api/types';
import type {
  DependencyAnswer,
  DependencyRow,
} from '../app/project/dependencies/dependencies.page';
import {
  type AiReviewBody,
  type AiReviewBudgets,
  type AiReviewProvider,
  type AiReviewScope,
  DEFAULT_AI_REVIEW_BUDGETS,
  type OrgAiReview,
} from '../app/settings/ai-review';
import { type AutoFix, DEFAULT_AUTO_FIX } from '../app/settings/auto-fix';
import type {
  LicenseGroupId,
  LicensePolicy,
  OrgLicensePolicy,
} from '../app/settings/license-policy';

export interface RecordedRequest {
  method: string;
  path: string;
  query: URLSearchParams;
  headers: Headers;
  body: unknown;
}

export interface FakeReply {
  status?: number;
  body?: unknown;
  /** Response headers (for example `retry-after`). */
  headers?: Record<string, string>;
}

/** A reply, or a function of the request; a promise lets a test hold an answer back. */
type Responder = FakeReply | ((request: RecordedRequest) => FakeReply | Promise<FakeReply>);

/**
 * A stand-in for the server in component tests: answers `fetch` by method and path, records
 * every request, and answers anything unexpected with the API's 404 problem.
 */
export class FakeServer {
  readonly requests: RecordedRequest[] = [];
  private readonly routes: { method: string; path: string | RegExp; responder: Responder }[] = [];

  /** Answers `method` on `path`: an exact path, or a pattern for paths with an id in them. */
  on(method: string, path: string | RegExp, responder: Responder): this {
    this.routes.unshift({ method, path, responder });
    return this;
  }

  requestsTo(method: string, path: string): RecordedRequest[] {
    return this.requests.filter((r) => r.method === method && r.path === path);
  }

  readonly fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    const text = request.method === 'GET' ? '' : await request.text();
    const recorded: RecordedRequest = {
      method: request.method,
      path: url.pathname,
      query: url.searchParams,
      headers: request.headers,
      body: text ? parseBody(text, request.headers.get('content-type')) : undefined,
    };
    this.requests.push(recorded);
    const route = this.routes.find(
      (r) =>
        r.method === request.method &&
        (typeof r.path === 'string' ? r.path === url.pathname : r.path.test(url.pathname)),
    );
    const reply: FakeReply = route
      ? await answer(route.responder, recorded)
      : { status: 404, body: problem(404, 'NOT_FOUND') };
    const status = reply.status ?? 200;
    const headers = reply.headers ?? {};
    if (status === 204 || reply.body === undefined) return new Response(null, { status, headers });
    return new Response(JSON.stringify(reply.body), {
      status,
      headers: {
        'content-type': status >= 400 ? 'application/problem+json' : 'application/json',
        ...headers,
      },
    });
  };
}

/** A JSON body parsed; any other body (an uploaded file) as its text. */
function parseBody(text: string, contentType: string | null): unknown {
  return contentType?.includes('json') === false ? text : (JSON.parse(text) as unknown);
}

/** The reply of a responder: itself, or what the function answers for the request. */
async function answer(responder: Responder, request: RecordedRequest): Promise<FakeReply> {
  return typeof responder === 'function' ? responder(request) : responder;
}

export function problem(
  status: number,
  code: string,
  errors?: { path: string; message: string }[],
) {
  return {
    type: `urn:qualor:problem:${code.toLowerCase().replaceAll('_', '-')}`,
    title: code,
    status,
    code,
    ...(errors ? { errors } : {}),
  };
}

export function provideFakeServer(server: FakeServer): Provider[] {
  return [{ provide: FETCH, useValue: server.fetch }];
}

export const ORG_ID = '0190a6c2-0000-7000-8000-000000000001';

/** An organisation admin's permissions, as `GET /auth/me` lists them (rbac-audit.md §3.2). */
export const ORG_ADMIN_PERMISSIONS = [
  'org.ai.manage',
  'org.audit.read',
  'org.gates.manage',
  'org.licenses.manage',
  'org.members.manage',
  'org.members.read',
  'org.profiles.manage',
  'org.projects.create',
  'org.read',
  'org.scm.manage',
  'org.webhooks.manage',
] as const;

/** A maintainer's (`member`) permissions on a project, as the project DTO lists them (§3.2). */
export const MEMBER_PROJECT_PERMISSIONS = [
  'ai.use',
  'issue.triage',
  'project.analyze',
  'project.read',
] as const;

/** A viewer's permissions on a project: reading only. */
export const VIEWER_PROJECT_PERMISSIONS = ['project.read'] as const;

export function me(
  overrides: { passwordChangeRequired?: boolean; admin?: boolean; demo?: boolean } = {},
): Me {
  return {
    user: {
      id: '0190a6c2-0000-7000-8000-00000000000a',
      username: 'alice',
      displayName: 'Alice',
      email: null,
      isInstanceAdmin: overrides.admin ?? false,
      active: true,
      passwordChangeRequired: overrides.passwordChangeRequired ?? false,
      hasPassword: true,
      sso: { identities: 0, scim: false },
      invitation: null,
      lastLoginAt: null,
      createdAt: '2026-09-01T00:00:00.000Z',
    },
    memberships: [
      {
        organizationId: ORG_ID,
        organizationKey: 'default',
        organizationName: 'Default',
        role: overrides.admin ? 'admin' : 'member',
        permissions: overrides.admin ? [...ORG_ADMIN_PERMISSIONS] : ['org.read'],
      },
    ],
    projectGrants: [],
    csrfToken: 'csrf-token',
    demo: overrides.demo ?? false,
  };
}

export function page<T>(items: T[], nextCursor: string | null = null) {
  return { items, nextCursor };
}

type ProjectItem = ItemOf<'/api/v0/projects'>;

/**
 * A project as `GET /projects` lists it: in the default organisation, with no analysis, not
 * linked to a repository, not excluded from AI and not reviewed, by default. `autoFix` and
 * `aiReview` take the fields given over those defaults.
 */
export function projectItem(
  given: Pick<ProjectItem, 'id' | 'key' | 'name'> &
    Partial<Omit<ProjectItem, 'autoFix' | 'aiReview'>> & {
      autoFix?: Partial<ProjectItem['autoFix']>;
      aiReview?: Partial<ProjectItem['aiReview']>;
    },
): ProjectItem {
  const { autoFix, aiReview, ...own } = given;
  return {
    organizationId: ORG_ID,
    mainBranchName: 'main',
    qualityGateId: null,
    newCodeDefinition: null,
    scmConnectionId: null,
    scmProjectRef: null,
    createdAt: '2026-09-01T00:00:00.000Z',
    updatedAt: '2026-09-01T00:00:00.000Z',
    mainBranch: null,
    permissions: ['project.read'],
    vulnerabilities: null,
    ...own,
    autoFix: {
      available: true,
      enabled: true,
      organizationEnabled: false,
      excludedFromAi: false,
      ...autoFix,
    },
    aiReview: {
      enabled: false,
      organizationEnabled: false,
      reason: 'review_disabled',
      ...aiReview,
    },
  };
}

/** Lets pending fetches, navigations and change detection finish (the fake fetch is async). */
export async function settle(fixture?: { whenStable(): Promise<unknown> }): Promise<void> {
  for (let i = 0; i < 5; i++) {
    await new Promise((resolve) => setTimeout(resolve));
    await fixture?.whenStable();
  }
}

/**
 * A secret field (an API key, a token, a webhook secret) that password managers must neither fill
 * nor offer to save: `data-1p-ignore` (1Password) and `data-lpignore` (LastPass); a password
 * input also has `autocomplete="new-password"`, which browsers honour where they ignore `off`.
 */
export function expectNoPasswordManager(field: Element): void {
  expect(field.hasAttribute('data-1p-ignore')).toBe(true);
  expect(field.getAttribute('data-lpignore')).toBe('true');
  if (field instanceof HTMLInputElement && field.type === 'password') {
    expect(field.getAttribute('autocomplete')).toBe('new-password');
  }
}

const COMPLIANCE = '/api/v0/ee/compliance/reports';
const COMPLIANCE_ID = /^\/api\/v0\/ee\/compliance\/reports\/([^/]+)$/;
const COMPLIANCE_DOWNLOAD = /^\/api\/v0\/ee\/compliance\/reports\/([^/]+)\/download$/;
const NO_SEVERITIES = { blocker: 0, high: 0, medium: 0, low: 0, info: 0 };

/** A compliance report as the API shows it (4E-1 §3): a ready project report by default. */
export function complianceReport(overrides: Partial<ComplianceReport> = {}): ComplianceReport {
  return {
    id: '0190a6c2-0000-7000-8000-0000000000c1',
    scope: 'project',
    organization: { id: ORG_ID, key: 'default', name: 'Default' },
    project: { id: '0190a6c2-0000-7000-8000-0000000000f1', key: 'acme/x', name: 'X' },
    branch: { id: '0190a6c2-0000-7000-8000-0000000000b1', name: 'main' },
    status: 'ready',
    createdBy: 'Alice',
    createdAt: '2026-10-12T10:00:00.000Z',
    completedAt: '2026-10-12T10:00:05.000Z',
    standards: [{ id: 'owasp-top10-2021', version: '2021', sourceSha256: 'f'.repeat(64) }],
    sha256: 'ab'.repeat(32),
    sizeBytes: 1024,
    error: null,
    summary: complianceSummary(),
    canDelete: false,
    ...overrides,
  };
}

/** A report's summary (4E-1 §2.6): one OWASP Top 10 2021 category and nothing else, by default. */
export function complianceSummary(
  overrides: Partial<NonNullable<ComplianceReport['summary']>> = {},
): NonNullable<ComplianceReport['summary']> {
  return {
    findings: { total: 3, bySeverity: { ...NO_SEVERITIES, high: 2, low: 1 }, inNewCode: 1 },
    standards: [
      {
        id: 'owasp-top10-2021',
        categories: [
          {
            id: 'A03',
            title: 'Injection',
            open: 2,
            bySeverity: { ...NO_SEVERITIES, high: 2 },
            inNewCode: 1,
            rules: 1,
            oldestFirstSeenAt: '2026-09-01T00:00:00.000Z',
          },
        ],
        notMapped: { open: 1, bySeverity: { ...NO_SEVERITIES, low: 1 }, inNewCode: 0, rules: 1 },
        distinctTotal: 3,
      },
    ],
    secrets: { open: 0 },
    dependencies: { open: 0, bySeverity: { ...NO_SEVERITIES } },
    triage: { falsePositive: 0, wontFix: 0 },
    truncated: false,
    ...overrides,
  };
}

/**
 * The compliance report API (4E-1 §3) over an in-memory list, newest first: list (by
 * organisation or project), create (a pending report), read, download and delete. A test changes
 * `reports` to play the build job, or answers a route itself with `server.on`, which wins.
 */
export class FakeCompliance {
  readonly reports: ComplianceReport[];
  private created = 0;

  /** Answers the compliance report routes on `server` over `reports`. */
  static install(server: FakeServer, reports: ComplianceReport[] = []): FakeCompliance {
    return new FakeCompliance(server, reports);
  }

  private constructor(server: FakeServer, reports: ComplianceReport[]) {
    this.reports = [...reports];
    server.on('GET', COMPLIANCE, (r) => {
      const organizationId = r.query.get('organizationId');
      const projectId = r.query.get('projectId');
      const items = this.reports
        .filter((report) =>
          projectId
            ? report.project?.id === projectId
            : report.scope === 'organization' && report.organization.id === organizationId,
        )
        .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
      return { body: page(items) };
    });
    server.on('POST', COMPLIANCE, (r) => {
      const body = r.body as { organizationId?: string; projectId?: string; branchId?: string };
      this.created++;
      const report = complianceReport({
        id: `0190a6c2-0000-7000-8000-${String(900 + this.created).padStart(12, '0')}`,
        scope: body.projectId ? 'project' : 'organization',
        project: body.projectId ? { id: body.projectId, key: 'acme/x', name: 'X' } : null,
        branch: body.branchId ? { id: body.branchId, name: 'main' } : null,
        status: 'pending',
        createdAt: new Date(Date.UTC(2026, 9, 13, 0, this.created)).toISOString(),
        completedAt: null,
        sha256: null,
        sizeBytes: null,
        summary: null,
        canDelete: true,
      });
      this.reports.unshift(report);
      return { status: 202, body: report };
    });
    server.on('GET', COMPLIANCE_ID, (r) => {
      const report = this.find(r.path, COMPLIANCE_ID);
      return report ? { body: report } : { status: 404, body: problem(404, 'NOT_FOUND') };
    });
    server.on('GET', COMPLIANCE_DOWNLOAD, (r) => {
      const report = this.find(r.path, COMPLIANCE_DOWNLOAD);
      if (!report) return { status: 404, body: problem(404, 'NOT_FOUND') };
      if (report.status !== 'ready') return { status: 409, body: problem(409, 'REPORT_NOT_READY') };
      return { body: { schemaVersion: 1, id: report.id } };
    });
    server.on('DELETE', COMPLIANCE_ID, (r) => {
      const report = this.find(r.path, COMPLIANCE_ID);
      if (!report) return { status: 404, body: problem(404, 'NOT_FOUND') };
      if (report.status === 'pending') return { status: 409, body: problem(409, 'REPORT_PENDING') };
      this.reports.splice(this.reports.indexOf(report), 1);
      return { status: 204 };
    });
  }

  /** Plays the build job: the report becomes ready with its sha256 and summary. */
  complete(id: string, overrides: Partial<ComplianceReport> = {}): void {
    const at = this.reports.findIndex((r) => r.id === id);
    const report = this.reports[at];
    if (!report) throw new Error(`no report ${id}`);
    this.reports[at] = {
      ...report,
      status: 'ready',
      completedAt: '2026-10-13T00:05:00.000Z',
      sha256: 'cd'.repeat(32),
      sizeBytes: 2048,
      summary: complianceSummary(),
      ...overrides,
    };
  }

  private find(path: string, pattern: RegExp): ComplianceReport | undefined {
    const id = pattern.exec(path)?.[1];
    return this.reports.find((r) => r.id === id);
  }
}

const PORTFOLIO = '/api/v0/ee/portfolio';
const PORTFOLIO_PROJECTS = '/api/v0/ee/portfolio/projects';

/** A set of portfolio figures (4E-2 §1): three projects, two analysed, one abandoned. */
export function portfolioAggregate(
  overrides: Partial<PortfolioAggregate> = {},
): PortfolioAggregate {
  return {
    projects: 3,
    analysed: 2,
    abandoned: 1,
    gate: { passed: 1, failed: 1, error: 0, none: 0 },
    passedShare: 0.5,
    securityRating: { A: 1, B: 0, C: 1, D: 0, E: 0 },
    reliabilityRating: { A: 2, B: 0, C: 0, D: 0, E: 0 },
    ncloc: 12345,
    coverage: 72.5,
    duplication: 3.25,
    issues: 42,
    bySeverity: { blocker: 2, high: 5, medium: 10, low: 20, info: 5 },
    securityIssues: 7,
    reliabilityIssues: 9,
    maintainabilityIssues: 26,
    newIssues: 4,
    ...overrides,
  };
}

/** A project of the portfolio (4E-2 §2): analysed, its gate failed, by default. */
export function portfolioRow(
  key: string,
  overrides: Partial<PortfolioProjectRow> = {},
): PortfolioProjectRow {
  return {
    organization: { key: 'default', name: 'Default' },
    project: {
      id: `0190a6c2-0000-7000-8000-${key.padStart(12, '0')}`,
      key,
      name: `Project ${key}`,
    },
    lastAnalysisAt: '2026-10-12T09:00:00.000Z',
    abandoned: false,
    gate: 'failed',
    securityRating: 'C',
    reliabilityRating: 'A',
    ncloc: 1000,
    coverage: 80,
    duplication: 2,
    issues: 12,
    bySeverity: { blocker: 1, high: 2, medium: 3, low: 4, info: 2 },
    newIssues: 1,
    secrets: 0,
    vulnerableDependencies: 0,
    ...overrides,
  };
}

/**
 * The portfolio of the default organisation (4E-2 §2): the totals of `portfolioAggregate`, 12
 * weekly points from 2026-07-20 (coverage 61, 62, … 72; ncloc 1 000 more each week), no
 * organisations (the organisation scope) and one project on each attention list.
 */
export function portfolioOverview(overrides: Partial<PortfolioOverview> = {}): PortfolioOverview {
  const week = 7 * 24 * 3600 * 1000;
  const first = Date.UTC(2026, 6, 20);
  return {
    generatedAt: '2026-10-13T12:00:00.000Z',
    scope: { kind: 'organization', organization: { id: ORG_ID, key: 'default', name: 'Default' } },
    granularity: 'week',
    totals: { ...portfolioAggregate(), secrets: 1, vulnerableDependencies: 4 },
    organizations: null,
    trend: Array.from({ length: 12 }, (_, i) => ({
      ...portfolioAggregate({
        coverage: 61 + i,
        ncloc: 1000 * (i + 1),
        issues: 30 + i,
        passedShare: i === 0 ? null : 0.5,
      }),
      start: new Date(first + i * week).toISOString(),
      end: i === 11 ? '2026-10-13T12:00:00.000Z' : new Date(first + (i + 1) * week).toISOString(),
      analyses: 10 + i,
      triage: i,
    })),
    attention: {
      failingGates: [portfolioRow('fail')],
      worstSecurity: [portfolioRow('weak', { securityRating: 'E' })],
      mostSevere: [
        portfolioRow('severe', { bySeverity: { blocker: 3, high: 4, medium: 0, low: 0, info: 0 } }),
      ],
      abandoned: [portfolioRow('stale', { abandoned: true, lastAnalysisAt: null, gate: null })],
    },
    ...overrides,
  };
}

/**
 * The portfolio API (4E-2 §3): the overview (`overview`, for every scope and granularity) and the
 * projects in pages of `limit` over `rows` (in the order given: the fake does not sort). A test
 * answers a route itself with `server.on`, which wins.
 */
export class FakePortfolio {
  overview: PortfolioOverview;
  rows: PortfolioProjectRow[];

  /** Answers the portfolio routes on `server` with `overview` and `rows`. */
  static install(
    server: FakeServer,
    overview: PortfolioOverview = portfolioOverview(),
    rows: PortfolioProjectRow[] = [portfolioRow('alpha'), portfolioRow('beta')],
  ): FakePortfolio {
    return new FakePortfolio(server, overview, rows);
  }

  private constructor(
    server: FakeServer,
    overview: PortfolioOverview,
    rows: PortfolioProjectRow[],
  ) {
    this.overview = overview;
    this.rows = rows;
    server.on('GET', PORTFOLIO, (r) => ({
      body: {
        ...this.overview,
        granularity: r.query.get('granularity') === 'month' ? 'month' : 'week',
      },
    }));
    server.on('GET', PORTFOLIO_PROJECTS, (r) => {
      const limit = Number(r.query.get('limit') ?? 50);
      const start = Number(r.query.get('cursor') ?? 0);
      const items = this.rows.slice(start, start + limit);
      const next = start + limit < this.rows.length ? String(start + limit) : null;
      return { body: page(items, next) };
    });
  }
}

const ORG_AUTO_FIX = /^\/api\/v0\/organizations\/([^/]+)\/ai\/auto-fix$/;
const PROJECT_AUTO_FIX = /^\/api\/v0\/projects\/([^/]+)\/ai\/auto-fix$/;

/** The starting state of a {@link FakeAutoFix}: licensed and AI-enabled, nothing stored, by default. */
export interface FakeAutoFixOptions {
  available?: boolean;
  fixEnabled?: boolean;
  organizations?: Record<string, AutoFix>;
}

/**
 * The automatic fix suggestion routes (4E-3a §2) over in-memory settings: the organisation route
 * (`GET`/`PUT /organizations/{id}/ai/auto-fix`) and the project opt-out (`PUT
 * /projects/{id}/ai/auto-fix`). Switching on from off needs `available` (else 403
 * FEATURE_NOT_LICENSED) and `fixEnabled` (else 409 AI_DISABLED); without the licence the stored
 * values are kept and read with `available: false`. A test answers a route itself with
 * `server.on`, which wins.
 */
export class FakeAutoFix {
  available: boolean;
  /** The organisation is AI-enabled with `features.fix`. */
  fixEnabled: boolean;
  /** Stored blocks by organisation id; one not listed reads as the default. */
  readonly organizations: Record<string, AutoFix>;
  /** The projects opted out. */
  readonly optedOut = new Set<string>();

  /** Answers the automatic fix suggestion routes on `server`. */
  static install(server: FakeServer, options: FakeAutoFixOptions = {}): FakeAutoFix {
    return new FakeAutoFix(server, options);
  }

  private constructor(server: FakeServer, options: FakeAutoFixOptions) {
    this.available = options.available ?? true;
    this.fixEnabled = options.fixEnabled ?? true;
    this.organizations = { ...options.organizations };
    server.on('GET', ORG_AUTO_FIX, (r) => ({
      body: { available: this.available, ...this.of(ORG_AUTO_FIX.exec(r.path)?.[1] ?? '') },
    }));
    server.on('PUT', ORG_AUTO_FIX, (r) => {
      const id = ORG_AUTO_FIX.exec(r.path)?.[1] ?? '';
      const next = r.body as AutoFix;
      if (
        !Number.isInteger(next.maxPerAnalysis) ||
        next.maxPerAnalysis < 1 ||
        next.maxPerAnalysis > 25
      ) {
        return {
          status: 422,
          body: problem(422, 'VALIDATION_FAILED', [
            { path: 'body.maxPerAnalysis', message: 'Too big' },
          ]),
        };
      }
      if (next.enabled && !this.of(id).enabled) {
        if (!this.available) return { status: 403, body: problem(403, 'FEATURE_NOT_LICENSED') };
        if (!this.fixEnabled) return { status: 409, body: problem(409, 'AI_DISABLED') };
      }
      this.organizations[id] = { ...next };
      return { body: { available: this.available, ...next } };
    });
    server.on('PUT', PROJECT_AUTO_FIX, (r) => {
      if (!this.available) return { status: 403, body: problem(403, 'FEATURE_NOT_LICENSED') };
      const id = PROJECT_AUTO_FIX.exec(r.path)?.[1] ?? '';
      const { enabled } = r.body as { enabled: boolean };
      if (enabled) this.optedOut.delete(id);
      else this.optedOut.add(id);
      return { body: { available: true, enabled } };
    });
  }

  of(organizationId: string): AutoFix {
    return this.organizations[organizationId] ?? { ...DEFAULT_AUTO_FIX };
  }
}

const ORG_AI_REVIEW = /^\/api\/v0\/organizations\/([^/]+)\/ai\/review$/;

/** An organisation's stored AI review, as a {@link FakeAiReview} keeps it. */
export interface FakeStoredReview {
  enabled: boolean;
  scope: AiReviewScope;
  projectIds: string[];
  budgets: AiReviewBudgets;
  /**
   * Who acknowledged the notice, for which provider, and the models it named; null before any. The
   * answers show the consent without its models, as the server's do.
   */
  consent: (NonNullable<OrgAiReview['consent']> & { models: string[] }) | null;
}

/** The starting state of a {@link FakeAiReview}: a provider and an enabled organisation, by default. */
export interface FakeAiReviewOptions {
  /**
   * The provider the notice names: the host with its port, the model and every model it names
   * (once each, sorted, the model among them); null: none configured.
   */
  provider?: AiReviewProvider | null;
  /** The organisation is enabled for the AI assistant by the instance administrator. */
  organizationEnabled?: boolean;
  /** The instance ceiling on the organisation's tokens per day; null: none. */
  ceiling?: number | null;
  /** The days a snapshot is kept, which the notice names. */
  retentionDays?: number;
  /** What the organisation's reviews have used today (UTC); nothing by default. */
  usage?: OrgAiReview['usage'];
  /**
   * What the instance admin's last Test of the provider says of its models, which every answer
   * carries. By default there is no Test: `at` null, `toolCalling` `unknown` and no models
   * without tools.
   */
  providerTest?: OrgAiReview['providerTest'];
  /** Stored blocks by organisation id; `consentFor` records an acknowledgement of that provider. */
  organizations?: Record<
    string,
    Partial<Omit<FakeStoredReview, 'consent'>> & { consentFor?: AiReviewProvider | null }
  >;
}

/** A list of models as a set, as the server compares them: each once, sorted. */
const modelSet = (models: readonly string[]): string[] => [...new Set(models)].sort();

function sameModels(a: readonly string[], b: readonly string[]): boolean {
  const left = modelSet(a);
  const right = modelSet(b);
  return left.length === right.length && left.every((model, i) => model === right[i]);
}

/** The stored consent as the answers show it: the host, the model, the user and the time. */
function consentAnswer(consent: NonNullable<FakeStoredReview['consent']>) {
  return {
    providerHost: consent.providerHost,
    model: consent.model,
    userId: consent.userId,
    at: consent.at,
  };
}

/** llm.md §3.3 / spec §5: the warning, word for word, as the server sends it. */
function fakeNotice(provider: AiReviewProvider, days: number): string {
  return (
    `AI review sends the merge request's diff and any repository file the model chooses to read to ${provider.host} (${provider.models.join(', ')}). ` +
    `The scanner uploads a copy of the repository to this Qualor server for each merge request; ` +
    `Qualor keeps it until the merge request is closed (at most ${days} days). ` +
    `Secrets the analyzers found are masked; credentials files are never sent.`
  );
}

/**
 * The organisation AI review routes (6I-2, `GET`/`PUT /organizations/{id}/ai/review`) over in-memory
 * settings, with the server's consent rules (R10 amended): switching on from off, or while the
 * consent does not name the provider now, needs `acknowledgeDataSharing`; without a provider or
 * an enabled organisation that is 409 AI_DISABLED, without the acknowledgement 409
 * AI_REVIEW_CONSENT_REQUIRED, and with a host, a model or a set of models other than the provider
 * now 409 AI_REVIEW_PROVIDER_CHANGED (nothing stored): the acknowledgement names the models it was
 * shown, or its model alone without them, and a consent names the set it was given for.
 * `changeProvider` plays the instance administrator switching the provider, a tier's model
 * included; `foreignProjects` are ids that belong to another organisation (422
 * PROJECT_NOT_IN_ORGANIZATION). The consent answers its host and model, the user and the time,
 * and no base URL or list of models, as the server's answers do. A test answers a route itself
 * with `server.on`, which wins.
 */
export class FakeAiReview {
  provider: AiReviewProvider | null;
  organizationEnabled: boolean;
  ceiling: number | null;
  retentionDays: number;
  /** What the organisation's reviews have used today; every answer shows it. */
  usage: OrgAiReview['usage'];
  /** What the last Test of the provider says of its models; every answer shows it. */
  providerTest: OrgAiReview['providerTest'];
  /** Stored blocks by organisation id; one not listed reads as the default. */
  readonly organizations: Record<string, FakeStoredReview> = {};
  /** Project ids of another organisation: a save that lists one is refused. */
  readonly foreignProjects = new Set<string>();

  /** Answers the AI review routes on `server`. */
  static install(server: FakeServer, options: FakeAiReviewOptions = {}): FakeAiReview {
    return new FakeAiReview(server, options);
  }

  private constructor(server: FakeServer, options: FakeAiReviewOptions) {
    this.provider =
      options.provider === undefined
        ? { host: 'llm.example.com', model: 'gpt-review', models: ['gpt-review'] }
        : options.provider;
    this.organizationEnabled = options.organizationEnabled ?? true;
    this.ceiling = options.ceiling ?? null;
    this.retentionDays = options.retentionDays ?? 14;
    this.usage = options.usage ?? { tokensToday: 0, costTodayUsd: null, reviewsToday: 0 };
    this.providerTest = options.providerTest ?? {
      at: null,
      toolCalling: 'unknown',
      modelsWithoutTools: [],
    };
    for (const [id, given] of Object.entries(options.organizations ?? {})) {
      const { consentFor, ...rest } = given;
      this.organizations[id] = { ...this.of(id), ...rest, consent: this.consentOf(consentFor) };
    }
    server.on('GET', ORG_AI_REVIEW, (r) => ({
      body: this.answer(ORG_AI_REVIEW.exec(r.path)?.[1] ?? ''),
    }));
    server.on('PUT', ORG_AI_REVIEW, (r) => this.put(ORG_AI_REVIEW.exec(r.path)?.[1] ?? '', r));
  }

  /** The stored block of an organisation, or the defaults (off, selected projects, none). */
  of(organizationId: string): FakeStoredReview {
    return (
      this.organizations[organizationId] ?? {
        enabled: false,
        scope: 'selected',
        projectIds: [],
        budgets: { ...DEFAULT_AI_REVIEW_BUDGETS },
        consent: null,
      }
    );
  }

  /** The instance administrator changes the provider (its host or model), or removes it. */
  changeProvider(next: AiReviewProvider | null): void {
    this.provider = next === null ? null : { ...next, models: [...next.models] };
  }

  /** Whether the stored consent names the provider configured now (its host and model). */
  consentCurrent(stored: FakeStoredReview): boolean {
    return (
      this.provider !== null &&
      stored.consent !== null &&
      stored.consent.providerHost === this.provider.host &&
      stored.consent.model === this.provider.model &&
      sameModels(stored.consent.models, this.provider.models)
    );
  }

  answer(organizationId: string): OrgAiReview {
    const stored = this.of(organizationId);
    let unavailableReason: OrgAiReview['unavailableReason'] = null;
    if (this.provider === null) unavailableReason = 'no_provider';
    else if (!this.organizationEnabled) unavailableReason = 'organization_disabled';
    return {
      available: unavailableReason === null,
      unavailableReason,
      provider:
        this.provider === null ? null : { ...this.provider, models: [...this.provider.models] },
      notice: this.provider === null ? null : fakeNotice(this.provider, this.retentionDays),
      enabled: stored.enabled,
      scope: stored.scope,
      projectIds: [...stored.projectIds],
      budgets: { ...stored.budgets },
      consent: stored.consent === null ? null : consentAnswer(stored.consent),
      consentCurrent: this.consentCurrent(stored),
      instanceCeiling: { tokensPerDay: this.ceiling },
      usage: { ...this.usage },
      providerTest: {
        ...this.providerTest,
        modelsWithoutTools: [...this.providerTest.modelsWithoutTools],
      },
    };
  }

  private consentOf(provider: AiReviewProvider | null | undefined): FakeStoredReview['consent'] {
    if (!provider) return null;
    return {
      providerHost: provider.host,
      model: provider.model,
      models: modelSet(provider.models),
      userId: '0190a6c2-0000-7000-8000-00000000000a',
      at: '2026-10-20T09:30:00.000Z',
    };
  }

  private put(organizationId: string, request: RecordedRequest): FakeReply {
    const body = request.body as AiReviewBody;
    const current = this.of(organizationId);
    const foreign = body.projectIds.flatMap((id, i) =>
      this.foreignProjects.has(id)
        ? [{ path: `body.projectIds.${i}`, message: 'Not a project of this organisation' }]
        : [],
    );
    if (foreign.length > 0) {
      return { status: 422, body: problem(422, 'PROJECT_NOT_IN_ORGANIZATION', foreign) };
    }
    let consent = current.consent;
    if (body.enabled && (!current.enabled || !this.consentCurrent(current))) {
      if (this.provider === null || !this.organizationEnabled) {
        return { status: 409, body: problem(409, 'AI_DISABLED') };
      }
      const acknowledged = body.acknowledgeDataSharing;
      if (acknowledged === undefined) {
        return { status: 409, body: problem(409, 'AI_REVIEW_CONSENT_REQUIRED') };
      }
      if (
        acknowledged.host.toLowerCase() !== this.provider.host.toLowerCase() ||
        acknowledged.model !== this.provider.model ||
        !sameModels(acknowledged.models ?? [acknowledged.model], this.provider.models)
      ) {
        return { status: 409, body: problem(409, 'AI_REVIEW_PROVIDER_CHANGED') };
      }
      consent = this.consentOf(this.provider);
    }
    this.organizations[organizationId] = {
      enabled: body.enabled,
      scope: body.scope,
      projectIds: [...body.projectIds],
      budgets: { ...body.budgets },
      consent,
    };
    return { body: this.answer(organizationId) };
  }
}

const DEPENDENCIES = /^\/api\/v0\/projects\/([^/]+)\/dependencies$/;

/** An inventory entry (6M §8): a direct npm package under MIT in package-lock.json, by default. */
export function dependency(overrides: Partial<DependencyRow> = {}): DependencyRow {
  return {
    ecosystem: 'npm',
    path: 'package-lock.json',
    line: 12,
    name: 'express',
    version: '4.19.2',
    licenses: ['MIT'],
    direct: true,
    ...overrides,
  };
}

/** A few members of each licence group, enough for the fakes (the server sends the real lists). */
export const FAKE_LICENSE_GROUPS: OrgLicensePolicy['groups'] = [
  {
    id: 'network-copyleft',
    label: 'Network copyleft',
    description: 'Copyleft that reaches users over a network.',
    members: ['AGPL-3.0-only', 'AGPL-3.0-or-later', 'SSPL-1.0'],
  },
  {
    id: 'strong-copyleft',
    label: 'Strong copyleft',
    description: 'Copyleft over the whole combined work.',
    members: ['GPL-2.0-only', 'GPL-2.0-or-later', 'GPL-3.0-only', 'GPL-3.0-or-later'],
  },
  {
    id: 'weak-copyleft',
    label: 'Weak copyleft',
    description: 'Copyleft over the licensed files or library only.',
    members: ['LGPL-2.1-only', 'LGPL-3.0-only', 'MPL-2.0'],
  },
  {
    id: 'non-commercial-or-source-available',
    label: 'Non-commercial or source-available',
    description: 'Licences that restrict commercial use or are not open source.',
    members: ['BUSL-1.1', 'CC-BY-NC-4.0', 'Commons-Clause'],
  },
];

/** The starting state of a {@link FakeDependencies}: one row, an inventory, no verdicts, by default. */
export interface FakeDependenciesOptions {
  rows?: DependencyRow[];
  inventory?: boolean;
  verdicts?: boolean;
}

/**
 * The dependencies route (6M §8, `GET /projects/{id}/dependencies`) over in-memory `rows`: the
 * filters (an exact licence string, a group by {@link FAKE_LICENSE_GROUPS}, the ecosystem, unknown
 * and direct, a name search, the verdict while `verdicts`), the page, and the summary of every row.
 * Without `inventory` it answers as a branch no scan has reported an inventory for. A row's
 * `verdict` is sent only while `verdicts` is on. A test answers the route itself with `server.on`,
 * which wins.
 */
export class FakeDependencies {
  rows: DependencyRow[];
  inventory: boolean;
  verdicts: boolean;

  /** Answers the dependencies route on `server`. */
  static install(server: FakeServer, options: FakeDependenciesOptions = {}): FakeDependencies {
    return new FakeDependencies(server, options);
  }

  private constructor(server: FakeServer, options: FakeDependenciesOptions = {}) {
    this.rows = options.rows ?? [dependency()];
    this.inventory = options.inventory ?? true;
    this.verdicts = options.verdicts ?? false;
    server.on('GET', DEPENDENCIES, (r) => ({ body: this.answer(r.query) }));
  }

  answer(query: URLSearchParams): DependencyAnswer {
    const page = Number(query.get('page') ?? 1);
    const pageSize = Number(query.get('pageSize') ?? 50);
    const rows = this.inventory ? this.rows : [];
    const members = FAKE_LICENSE_GROUPS.find((g) => g.id === query.get('group'))?.members;
    const q = query.get('q')?.toLowerCase();
    const verdict = query.get('verdict');
    const matching = rows.filter(
      (row) =>
        (!query.has('license') || row.licenses.includes(query.get('license') ?? '')) &&
        (!members || row.licenses.some((l) => members.includes(l))) &&
        (!query.has('ecosystem') || row.ecosystem === query.get('ecosystem')) &&
        (query.get('unknown') !== 'true' || row.licenses.length === 0) &&
        (query.get('direct') !== 'true' || row.direct === true) &&
        (!q || row.name.toLowerCase().includes(q)) &&
        (!this.verdicts || verdict === null || row.verdict === verdict),
    );
    const counts = new Map<string, number>();
    for (const row of rows) {
      for (const l of row.licenses) counts.set(l, (counts.get(l) ?? 0) + 1);
    }
    const unknown = rows.filter((row) => row.licenses.length === 0).length;
    return {
      rows: matching.slice((page - 1) * pageSize, page * pageSize).map((row) => {
        const { verdict: judged, ...rest } = row;
        return this.verdicts && judged ? { ...rest, verdict: judged } : rest;
      }),
      page,
      pageSize,
      total: matching.length,
      summary: {
        total: rows.length,
        known: rows.length - unknown,
        unknown,
        byLicense: [...counts]
          .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
          .slice(0, 20)
          .map(([license, count]) => ({ license, count })),
      },
      inventory: this.inventory,
      verdicts: this.verdicts,
    };
  }
}

export type VulnerabilityTargets = ResponseBody<
  '/api/v0/projects/{id}/vulnerabilities/targets',
  'get'
>;
export type VulnerabilityTarget = VulnerabilityTargets['targets'][number];
export type VulnerabilityList = ResponseBody<'/api/v0/projects/{id}/vulnerabilities', 'get'>;
export type VulnerabilityCard = VulnerabilityList['items'][number];
export type UntrackedVersion = VulnerabilityTargets['untracked'][number];

const NO_COUNTS = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };

/** One tracked target of the vulnerability summary: a branch with no open vulnerabilities by default. */
export function vulnerabilityTarget(given: Partial<VulnerabilityTarget> = {}): VulnerabilityTarget {
  return {
    kind: 'branch',
    id: '0190a6c2-0000-7000-8000-0000000000d0',
    name: 'main',
    isMain: false,
    tracking: null,
    hasInventory: true,
    counts: NO_COUNTS,
    exploited: null,
    new: 0,
    checkedAt: '2026-10-30T09:00:00.000Z',
    ...given,
  };
}

/** One card of the by-vulnerability list: an open, unignored High in main, found by a scan. */
export function vulnerabilityCard(given: Partial<VulnerabilityCard> = {}): VulnerabilityCard {
  return {
    vulnerabilityId: 'CVE-2026-0001',
    packageName: 'lodash',
    ecosystem: 'npm',
    severity: 'high',
    title: 'Prototype pollution in lodash',
    primaryUrl: 'https://avd.aquasec.com/nvd/cve-2026-0001',
    installedVersions: ['4.17.20'],
    fixedVersion: '4.17.21',
    in: [{ kind: 'branch', id: '0190a6c2-0000-7000-8000-0000000000d1', name: 'main' }],
    notIn: [],
    foundAt: '2026-10-20T08:00:00.000Z',
    withoutScan: false,
    new: false,
    ignored: false,
    status: 'open',
    decision: null,
    exploited: null,
    epss: null,
    ...given,
  };
}

/** One version no rule tracks. */
export function untrackedVersion(given: Partial<UntrackedVersion> = {}): UntrackedVersion {
  return {
    id: '0190a6c2-0000-7000-8000-0000000000e0',
    name: '1.0.0',
    tracking: 'auto',
    trackingReason: 'older',
    counts: NO_COUNTS,
    exploited: null,
    checkedAt: null,
    ...given,
  };
}

/**
 * The vulnerability summary route (vuln 2b, `GET /projects/{id}/vulnerabilities/targets`) over an
 * in-memory `answer`, and `PATCH /projects/{id}/versions/{versionId}`, which records the new
 * tracking on the version's row (a test changes `answer` itself for anything more). A test
 * answers a route itself with `server.on`, which wins.
 */
export class FakeVulnerabilities {
  answer: VulnerabilityTargets;
  /** The cards of `GET /vulnerabilities`; a card whose `in` names the `target` id belongs to it. */
  cards: VulnerabilityCard[] = [];
  /** The query strings the list was asked with. */
  readonly listQueries: URLSearchParams[] = [];
  /** The bodies of the decisions saved. */
  readonly decisions: unknown[] = [];

  /** Answers the summary of project `projectId` on `server`. */
  static install(
    server: FakeServer,
    projectId: string,
    answer: Partial<VulnerabilityTargets> = {},
  ): FakeVulnerabilities {
    return new FakeVulnerabilities(server, projectId, answer);
  }

  private constructor(
    server: FakeServer,
    projectId: string,
    answer: Partial<VulnerabilityTargets>,
  ) {
    this.answer = {
      priority: false,
      sbom: false,
      monitoring: 'on',
      data: { builtAt: '2026-10-29T03:00:00.000Z' },
      checkedAt: '2026-10-30T09:00:00.000Z',
      versionCount: 1,
      targets: [],
      untracked: [],
      ...answer,
    };
    server.on('GET', `/api/v0/projects/${projectId}/vulnerabilities/targets`, () => ({
      body: this.answer,
    }));
    server.on('GET', `/api/v0/projects/${projectId}/vulnerabilities`, (r) => {
      const query = new URLSearchParams(r.query);
      this.listQueries.push(query);
      const target = query.get('target')?.split(':')[1];
      const status = query.get('status') ?? 'all';
      const severity = query.get('severity');
      const page = Number(query.get('page') ?? 1);
      const size = Number(query.get('pageSize') ?? 50);
      const all = this.cards.filter(
        (c) =>
          (!target || c.in.some((t) => t.id === target) || c.notIn.some((t) => t.id === target)) &&
          (status === 'all' || c.status === status) &&
          (!severity || c.severity === severity),
      );
      return { body: { items: all.slice((page - 1) * size, page * size), total: all.length } };
    });
    server.on('PUT', `/api/v0/projects/${projectId}/vulnerability-decisions`, (r) => {
      this.decisions.push(r.body);
      return { body: { decision: {}, appliedIssues: 0 } };
    });
    const version = new RegExp(`^/api/v0/projects/${projectId}/versions/([^/]+)$`);
    server.on('PATCH', version, (r) => {
      const id = version.exec(r.path)?.[1];
      const tracking = (r.body as { tracking: VulnerabilityTarget['tracking'] }).tracking;
      this.answer = {
        ...this.answer,
        targets: this.answer.targets.map((t) => (t.id === id ? { ...t, tracking } : t)),
      };
      return { body: {} };
    });
  }
}

const LICENSE_POLICY = /^\/api\/v0\/organizations\/([^/]+)\/license-policy$/;
/** The SPDX ids the fake knows, in their canonical spelling (the server sends the whole list). */
export const FAKE_SPDX_IDS: OrgLicensePolicy['spdxIds'] = {
  licenses: [
    'AGPL-3.0-only',
    'Apache-2.0',
    'BSD-3-Clause',
    'GPL-2.0-only',
    'GPL-2.0-or-later',
    'GPL-3.0-only',
    'GPL-3.0-or-later',
    'ISC',
    'LGPL-3.0-only',
    'MIT',
    'MPL-2.0',
  ],
  exceptions: ['Classpath-exception-2.0', 'LLVM-exception'],
};

/** An entry in its canonical spelling, as far as the fake knows the ids; null for an unknown one. */
function canonical(entry: string): string | null {
  const [id = '', exception] = entry.split(/\s+WITH\s+/i);
  const known = (list: string[], value: string) =>
    list.find((v) => v.toLowerCase() === value.trim().toLowerCase()) ?? null;
  const license = known(FAKE_SPDX_IDS.licenses, id);
  if (exception === undefined) return license;
  const extra = known(FAKE_SPDX_IDS.exceptions, exception);
  return license && extra ? `${license} WITH ${extra}` : null;
}

/** The starting state of a {@link FakeLicensePolicy}: licensed, no policy stored, by default. */
export interface FakeLicensePolicyOptions {
  available?: boolean;
  policies?: Record<string, LicensePolicy | null>;
}

/**
 * The organisation licence policy routes (6M §5, `GET`/`PUT /organizations/{id}/license-policy`)
 * over in-memory policies: `available` is the feature (else PUT is 403 FEATURE_NOT_LICENSED and GET
 * says `available: false`, the stored policy kept); an id outside {@link FAKE_SPDX_IDS} is 400
 * INVALID_LICENSE_ID with `details.invalid`. A stored policy has canonical spellings and sorted
 * lists, as the server stores it. A test answers a route itself with `server.on`, which wins.
 */
export class FakeLicensePolicy {
  available: boolean;
  readonly policies: Record<string, LicensePolicy | null>;

  /** Answers the organisation licence policy routes on `server`. */
  static install(server: FakeServer, options: FakeLicensePolicyOptions = {}): FakeLicensePolicy {
    return new FakeLicensePolicy(server, options);
  }

  private constructor(server: FakeServer, options: FakeLicensePolicyOptions) {
    this.available = options.available ?? true;
    this.policies = { ...options.policies };
    server.on('GET', LICENSE_POLICY, (r) => {
      const body: OrgLicensePolicy = {
        available: this.available,
        policy: this.policies[LICENSE_POLICY.exec(r.path)?.[1] ?? ''] ?? null,
        groups: FAKE_LICENSE_GROUPS,
        spdxIds: FAKE_SPDX_IDS,
      };
      return { body };
    });
    server.on('PUT', LICENSE_POLICY, (r) => {
      if (!this.available) return { status: 403, body: problem(403, 'FEATURE_NOT_LICENSED') };
      const id = LICENSE_POLICY.exec(r.path)?.[1] ?? '';
      const { policy } = r.body as { policy: LicensePolicy | null };
      if (policy === null) {
        this.policies[id] = null;
        return { body: { available: true, policy: null } };
      }
      const invalid = [...policy.forbidden, ...policy.allowed].filter((e) => canonical(e) === null);
      if (invalid.length > 0) {
        return {
          status: 400,
          body: { ...problem(400, 'INVALID_LICENSE_ID'), details: { invalid } },
        };
      }
      const sorted = (list: string[]) => [...new Set(list.map((e) => canonical(e) ?? e))].sort();
      const stored: LicensePolicy = {
        ...policy,
        forbiddenGroups: [...new Set<LicenseGroupId>(policy.forbiddenGroups)].sort(),
        forbidden: sorted(policy.forbidden),
        allowed: sorted(policy.allowed),
      };
      this.policies[id] = stored;
      return { body: { available: true, policy: stored } };
    });
  }
}

const USERS_SEARCH = '/api/v0/users/search';
const ORG_MEMBERS = /^\/api\/v0\/organizations\/([^/]+)\/members$/;
type UserSuggestions = ResponseBody<'/api/v0/users/search', 'get'>;
type OrgMember = ItemOf<'/api/v0/organizations/{id}/members'>;

/** A user of the fake directory: inactive users are never suggested. */
export interface DirectoryUser {
  id: string;
  username: string;
  displayName: string | null;
  active?: boolean;
}

/** The fake directory's membership of a user in an organisation. */
export interface DirectoryMembership {
  organizationId: string;
  userId: string;
  role: OrgMember['role'];
}

/** A role granted on one project in the fake directory (`excludeProject` leaves it out). */
export interface DirectoryGrant {
  projectId: string;
  userId: string;
}

/**
 * The server's user-picker match (`userNameMatches`): the username starts with `q`, or the display
 * name does from its start or from just after a space or a hyphen, ignoring case. So `q` may run
 * over several words: "alice sm" matches "Alice Smith".
 */
export function userMatches(user: { username: string; displayName: string | null }, q: string) {
  const start = q.toLowerCase();
  const name = (user.displayName ?? '').toLowerCase();
  return (
    user.username.toLowerCase().startsWith(start) ||
    name.startsWith(start) ||
    name.includes(` ${start}`) ||
    name.includes(`-${start}`)
  );
}

/** The starting directory of a {@link FakeUserDirectory}: empty, not an instance admin, by default. */
export interface FakeUserDirectoryOptions {
  users?: DirectoryUser[];
  memberships?: DirectoryMembership[];
  grants?: DirectoryGrant[];
  instanceAdmin?: boolean;
}

/** Orders users by username, as the search route answers them. */
function byUsername(a: { username: string }, b: { username: string }): number {
  if (a.username < b.username) return -1;
  return a.username > b.username ? 1 : 0;
}

/**
 * The user pickers' routes over an in-memory directory, as the server answers them:
 * - `GET /users/search`: q of at most 64 UTF-16 units, then trimmed, of at least 2 characters
 *   (code points; 1 for an instance admin), else 422; limit 1 to 10; active users only, by
 *   username; `excludeOrganization` leaves its members out and `excludeProject` the users with a
 *   grant on it; never an email; 429 RATE_LIMITED while `rateLimited`.
 * - `GET /organizations/{id}/members`: its members in user id order, in pages of `limit` after
 *   `cursor`; with `q` (trimmed, else 422 when blank), the active ones that match.
 * A test answers a route itself with `server.on` after this, which wins.
 */
export class FakeUserDirectory {
  users: DirectoryUser[];
  memberships: DirectoryMembership[];
  grants: DirectoryGrant[];
  /** The caller is an instance admin: a one-character q is accepted. */
  instanceAdmin: boolean;
  rateLimited = false;

  /** Answers the user pickers' routes on `server` over the directory in `options`. */
  static install(server: FakeServer, options: FakeUserDirectoryOptions = {}): FakeUserDirectory {
    return new FakeUserDirectory(server, options);
  }

  private constructor(server: FakeServer, options: FakeUserDirectoryOptions) {
    this.users = options.users ?? [];
    this.memberships = options.memberships ?? [];
    this.grants = options.grants ?? [];
    this.instanceAdmin = options.instanceAdmin ?? false;
    server.on('GET', USERS_SEARCH, (r) => this.search(r.query));
    server.on('GET', ORG_MEMBERS, (r) =>
      this.members(ORG_MEMBERS.exec(r.path)?.[1] ?? '', r.query),
    );
  }

  private search(query: URLSearchParams): FakeReply {
    if (this.rateLimited) {
      return { status: 429, body: problem(429, 'RATE_LIMITED'), headers: { 'retry-after': '60' } };
    }
    const raw = query.get('q') ?? '';
    const q = raw.trim();
    const limit = Number(query.get('limit') ?? 10);
    // the maximum in UTF-16 units of q as sent, the minimum in characters of q trimmed.
    const short = [...q].length < (this.instanceAdmin ? 1 : 2);
    if (raw.length > 64 || short || !(limit >= 1 && limit <= 10)) {
      return {
        status: 422,
        body: problem(422, 'VALIDATION_FAILED', [{ path: 'query.q', message: 'Too short' }]),
      };
    }
    const excluded = query.get('excludeOrganization');
    const project = query.get('excludeProject');
    const members = new Set([
      ...this.memberships.filter((m) => m.organizationId === excluded).map((m) => m.userId),
      ...this.grants.filter((g) => g.projectId === project).map((g) => g.userId),
    ]);
    const body: UserSuggestions = {
      users: this.users
        .filter((u) => u.active !== false && !members.has(u.id) && userMatches(u, q))
        .sort(byUsername)
        .slice(0, limit)
        .map(({ id, username, displayName }) => ({ id, username, displayName })),
    };
    return { body };
  }

  private members(organizationId: string, query: URLSearchParams): FakeReply {
    const q = query.get('q')?.trim() ?? null;
    if (q === '') {
      return {
        status: 422,
        body: problem(422, 'VALIDATION_FAILED', [{ path: 'query.q', message: 'Too short' }]),
      };
    }
    const limit = Number(query.get('limit') ?? 50);
    const cursor = query.get('cursor');
    const rows: OrgMember[] = this.memberships
      .filter((m) => m.organizationId === organizationId)
      .flatMap((m) => {
        const user = this.users.find((u) => u.id === m.userId);
        if (!user || (q !== null && (user.active === false || !userMatches(user, q)))) return [];
        return [
          {
            userId: user.id,
            username: user.username,
            displayName: user.displayName,
            role: m.role,
            createdAt: '2026-09-01T00:00:00.000Z',
            managedBy: null,
          },
        ];
      })
      .sort((a, b) => (a.userId < b.userId ? -1 : 1))
      .filter((m) => cursor === null || m.userId > cursor);
    const items = rows.slice(0, limit);
    return { body: page(items, rows.length > limit ? (items.at(-1)?.userId ?? null) : null) };
  }
}
