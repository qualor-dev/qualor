import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import { type DependencyEntry, hex32, type Report } from '@qualor/shared';
import { and, eq, sql } from 'drizzle-orm';
import pg from 'pg';
import { createDatabase } from '../../src/db/client';
import { branches, issues, projects, reviewFindings } from '../../src/db/schema';
import { ensureAiRules } from '../../src/review/rules';

/**
 * Demo data for the UI end-to-end tests and screenshots (plan 1F), created only through the
 * public HTTP API, the way a user and the CLI would: three projects, analyses whose measures
 * change over time (trends), a failing and a passing gate, a merge request, issues with a
 * changelog, a custom gate and profile, a second user who must change the password, a personal
 * token and a webhook. Some texts carry HTML on purpose: the UI must show them as text.
 */
export interface SeedCredentials {
  adminUsername: string;
  adminPassword: string;
  /** The initial password of `alice`, set by the admin, so she must change it (ruling R7). */
  alicePassword: string;
}

export const XSS_MESSAGE =
  'Using <img src="/receipt.png" onerror="alert(1)"> could result in slower LCP and higher bandwidth. Consider using <Image /> from next/image to automatically optimize images.';
/** The open issue with related locations (ui/e2e/seed-data.ts RELATED_ISSUE_MESSAGE). */
const RELATED_ISSUE_MESSAGE = 'Detected eval() with a non-literal argument.';
const XSS_DESCRIPTION =
  'Prefer **next/image** over <img src="/logo.png" onerror="alert(\'rule\')"> so images are optimized and lazy-loaded.';
const REPORT_CONTENT_TYPE = 'application/vnd.qualor.report+json';

class Client {
  private cookie = '';
  private csrf = '';

  constructor(private readonly base: string) {}

  async login(username: string, password: string): Promise<void> {
    const res = await fetch(`${this.base}/api/v0/auth/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    if (res.status !== 204) throw new Error(`login as ${username}: ${res.status}`);
    const session = /qualor_session=([^;]+)/.exec(res.headers.get('set-cookie') ?? '')?.[1];
    if (!session) throw new Error('login set no session cookie');
    this.cookie = `qualor_session=${session}`;
    this.csrf = (await this.json<{ csrfToken: string }>('GET', '/api/v0/auth/me')).csrfToken;
  }

  async json<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await fetch(`${this.base}${path}`, {
      method,
      headers: {
        cookie: this.cookie,
        ...(method === 'GET' ? {} : { 'x-qualor-csrf': this.csrf }),
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    if (!res.ok) throw new Error(`${method} ${path}: ${res.status} ${text}`);
    return (text ? JSON.parse(text) : undefined) as T;
  }
}

interface FileSpec {
  path: string;
  language?: 'typescript' | 'javascript' | 'java' | 'other';
  kind?: 'main' | 'test';
  lines: number;
  ncloc: number;
  covered?: number;
  newLines?: [number, number][];
}

interface FindingSpec {
  engine: string;
  rule: string;
  path: string | null;
  line?: number;
  message: string;
  severity?: 'blocker' | 'high' | 'medium' | 'low' | 'info';
  /** Secondary locations, in the analyzer's order (the issue page's "Related locations"). */
  related?: { path: string; line: number; endLine?: number; message?: string }[];
}

/** A duplication group of the report: two or more blocks of the same code (report-format §8). */
interface DuplicationSpec {
  blocks: { path: string; startLine: number; endLine: number }[];
}

const ENGINES: Report['engines'] = [
  {
    id: 'eslint',
    kind: 'builtin',
    version: '9.12.0',
    status: 'ok',
    durationMs: 8_400,
    rules: [
      {
        id: '@next/next/no-img-element',
        name: 'Prevent usage of the img element',
        shortDescription: XSS_DESCRIPTION,
        helpUri: 'https://nextjs.org/docs/messages/no-img-element',
        defaultSeverity: 'medium',
        quality: 'reliability',
        languages: ['typescript', 'javascript'],
      },
      {
        id: '@typescript-eslint/no-floating-promises',
        name: 'Require Promise-like statements to be handled appropriately',
        shortDescription:
          'A Promise that is neither awaited nor given a rejection handler hides its failure.',
        helpUri: 'https://typescript-eslint.io/rules/no-floating-promises/',
        defaultSeverity: 'medium',
        quality: 'reliability',
        languages: ['typescript', 'javascript'],
      },
      {
        id: 'eqeqeq',
        name: 'Require === and !==',
        shortDescription: 'Compare with `===` and `!==`, never `==` or `!=`.',
        helpUri: 'https://eslint.org/docs/latest/rules/eqeqeq',
        defaultSeverity: 'medium',
        quality: 'reliability',
        languages: ['typescript', 'javascript'],
      },
      {
        id: 'no-unused-vars',
        name: 'Disallow unused variables',
        shortDescription: 'Variables that are declared and never used are most likely an error.',
        helpUri: 'https://eslint.org/docs/latest/rules/no-unused-vars',
        defaultSeverity: 'low',
        quality: 'maintainability',
        languages: ['typescript', 'javascript'],
      },
      {
        id: 'no-console',
        name: 'Disallow the use of console',
        defaultSeverity: 'info',
        quality: 'maintainability',
        languages: ['typescript', 'javascript'],
      },
      {
        id: 'no-param-reassign',
        name: 'Disallow reassigning function parameters',
        defaultSeverity: 'medium',
        quality: 'maintainability',
        languages: ['typescript', 'javascript'],
      },
    ],
  },
  {
    id: 'semgrep',
    kind: 'builtin',
    version: '1.30.0',
    status: 'ok',
    durationMs: 21_000,
    rules: [
      {
        id: 'javascript.lang.security.detect-eval-with-expression',
        name: 'eval() with a non-literal argument',
        shortDescription: 'Evaluating dynamic content can lead to code injection.',
        defaultSeverity: 'high',
        quality: 'security',
        cwe: [95],
      },
    ],
  },
  {
    id: 'gitleaks',
    kind: 'builtin',
    version: '8.30.1',
    status: 'ok',
    durationMs: 900,
    rules: [
      {
        id: 'generic-api-key',
        name: 'Generic API key',
        defaultSeverity: 'blocker',
        quality: 'security',
        cwe: [798],
      },
    ],
  },
];

/**
 * 6M: the dependency inventory of Payments API, as the CLI's licence pass (`trivy-licenses`)
 * reports it: npm packages in package-lock.json, a Go module, and a pnpm workspace whose packages
 * were not installed, so its licence is unknown and its entry has no line. Seven entries, six with
 * a known licence. `ledger-gpl` is strong copyleft (forbidden by the Business e2e policy),
 * `dual-licensed-math` is MIT OR GPL (allowed), `phone-format-lgpl` weak copyleft. The package
 * names are made up, so no real package is said to carry these licences.
 */
const PAYMENTS_DEPENDENCIES: DependencyEntry[] = [
  npm('express', '4.19.2', ['MIT'], 12, true),
  npm('decimal.js', '10.4.3', ['MIT'], 25, true),
  npm('ledger-gpl', '2.1.0', ['GPL-3.0-only'], 40, false),
  npm('dual-licensed-math', '1.0.0', ['MIT OR GPL-2.0-or-later'], 57, false),
  npm('phone-format-lgpl', '3.2.1', ['LGPL-3.0-only'], 71, false),
  {
    ecosystem: 'gomod',
    path: 'go.mod',
    line: 5,
    name: 'github.com/acme/retry',
    version: 'v1.4.0',
    licenses: ['Apache-2.0'],
    direct: true,
  },
  {
    ecosystem: 'pnpm',
    path: 'web/pnpm-lock.yaml',
    name: 'left-pad-internal',
    version: '0.3.1',
    licenses: [],
    direct: true,
  },
];

function npm(
  name: string,
  version: string,
  licenses: string[],
  line: number,
  direct: boolean,
): DependencyEntry {
  return { ecosystem: 'npm', path: 'package-lock.json', line, name, version, licenses, direct };
}

/** The CLI's licence pass, as a report that carries an inventory names it. */
const LICENSE_PASS: Report['engines'][number] = {
  id: 'trivy-licenses',
  kind: 'builtin',
  version: '0.70.0',
  status: 'ok',
  durationMs: 3_200,
  rules: [],
};

function report(input: {
  projectKey: string;
  projectName: string;
  version: string;
  date: string;
  revision: string;
  branch: string;
  mergeRequest?: { id: string; sourceBranch: string };
  firstAnalysis: boolean;
  files: FileSpec[];
  findings: FindingSpec[];
  duplications?: DuplicationSpec[];
  /** 6M: the dependency inventory; the report then names the licence pass too. */
  dependencies?: DependencyEntry[];
}): Report {
  const ranges = (count: number): [number, number][] => (count > 0 ? [[1, count]] : []);
  return {
    schemaVersion: 1,
    scanner: { name: 'qualor-cli', version: '0.1.0', platform: 'linux-x64' },
    project: { key: input.projectKey, name: input.projectName, version: input.version },
    scm: {
      provider: 'gitlab',
      revision: input.revision,
      branch: input.branch,
      mainBranch: 'main',
      mergeRequest: input.mergeRequest ? { targetBranch: 'main', ...input.mergeRequest } : null,
      baseline: input.firstAnalysis
        ? { revision: null, kind: 'server_baseline', status: 'first_analysis' }
        : {
            revision: 'f'.repeat(40),
            kind: input.mergeRequest ? 'merge_base' : 'server_baseline',
            status: 'ok',
          },
      renames: [],
    },
    analysisDate: input.date,
    engines: input.dependencies ? [...ENGINES, LICENSE_PASS] : ENGINES,
    files: input.files.map((f) => ({
      path: f.path,
      language: f.language ?? 'typescript',
      kind: f.kind ?? 'main',
      sha256: hex32(`${input.revision}:${f.path}`).repeat(2),
      lines: f.lines,
      ...(f.language === 'other'
        ? {}
        : {
            metrics: {
              ncloc: f.ncloc,
              commentLines: Math.round(f.lines / 10),
              functions: Math.round(f.ncloc / 12),
              classes: 1,
              statements: Math.round(f.ncloc * 0.6),
              complexity: Math.round(f.ncloc / 6),
              cognitiveComplexity: Math.round(f.ncloc / 8),
            },
          }),
      ...(input.firstAnalysis ? {} : { newLines: f.newLines ?? [] }),
      ...(f.covered === undefined
        ? {}
        : {
            coverage: {
              covered: ranges(f.covered),
              uncovered: f.covered < f.ncloc ? [[f.covered + 1, f.ncloc] as [number, number]] : [],
              branches: [],
            },
          }),
    })),
    findings: input.findings.map((f) => {
      const seed = `${f.engine}:${f.rule}:${f.path}:${f.line ?? 0}`;
      return {
        engineId: f.engine,
        ruleId: f.rule,
        message: f.message,
        ...(f.severity ? { severity: f.severity } : {}),
        location: f.path === null ? null : { path: f.path, startLine: f.line ?? 1 },
        ...(f.related
          ? {
              secondaryLocations: f.related.map((r) => ({
                path: r.path,
                startLine: r.line,
                ...(r.endLine ? { endLine: r.endLine } : {}),
                ...(r.message ? { message: r.message } : {}),
              })),
            }
          : {}),
        lineHash: hex32(`line:${seed}`),
        contextHash: hex32(`context:${seed}`),
        ...(f.path === null
          ? {}
          : {
              // Demo source text shown next to the issue; it is data, never executed.
              snippet: {
                startLine: Math.max(1, (f.line ?? 1) - 2),
                // The flagged line (the third) holds the `==` the fake LLM's fix replaces.
                lines: [
                  'export function refundLimit(order: Order, amount: number) {',
                  '  const limit = eval(order.policy);',
                  '  if (order.currency == "EUR") {',
                  '    return Math.min(amount, limit);',
                  '  }',
                ],
              },
            }),
      };
    }),
    duplications: input.duplications ?? [],
    warnings: [],
    ...(input.dependencies ? { dependencies: input.dependencies } : {}),
  };
}

const PAYMENTS_BASE: FindingSpec[] = [
  {
    engine: 'eslint',
    rule: 'eqeqeq',
    path: 'src/refunds/limits.ts',
    line: 12,
    message: "Expected '===' and instead saw '=='.",
  },
  {
    engine: 'eslint',
    rule: 'no-unused-vars',
    path: 'src/refunds/service.ts',
    line: 7,
    message: "'refundCap' is assigned a value but never used.",
  },
  {
    engine: 'eslint',
    rule: 'no-console',
    path: 'src/util/log.ts',
    line: 3,
    message: 'Unexpected console statement.',
  },
  {
    engine: 'semgrep',
    rule: 'javascript.lang.security.detect-eval-with-expression',
    path: 'src/payments/gateway.ts',
    line: 88,
    message: RELATED_ISSUE_MESSAGE,
    related: [
      { path: 'src/refunds/limits.ts', line: 10, message: 'The policy comes from the order' },
      {
        path: 'src/payments/gateway.ts',
        line: 88,
        endLine: 92,
        message: 'Orders are built from the request body here',
      },
      { path: 'src/payments/gateway.ts', line: 140 },
    ],
  },
  {
    engine: 'eslint',
    rule: 'no-param-reassign',
    path: 'src/payments/currency.ts',
    line: 41,
    message: "Assignment to function parameter 'amount'.",
  },
];
const PAYMENTS_SECOND: FindingSpec[] = [
  {
    engine: 'eslint',
    rule: 'no-unused-vars',
    path: 'src/payments/currency.ts',
    line: 18,
    message: "'rounding' is defined but never used.",
  },
  {
    engine: 'gitleaks',
    rule: 'generic-api-key',
    path: 'config/staging.env',
    line: 4,
    message: 'Generic API key detected.',
  },
];
const PAYMENTS_THIRD: FindingSpec[] = [
  {
    engine: 'eslint',
    rule: '@typescript-eslint/no-floating-promises',
    path: 'src/refunds/limits.ts',
    line: 44,
    message:
      'Promises must be awaited, end with a call to .catch, end with a call to .then with a rejection handler or be explicitly marked as ignored with the `void` operator.',
    severity: 'high',
  },
  {
    engine: 'eslint',
    rule: 'no-param-reassign',
    path: 'src/refunds/limits.ts',
    line: 50,
    message: "Assignment to function parameter 'limit'.",
  },
];

/**
 * Findings fixed before September, on files removed by then (UI redesign spec §9): the early
 * history of the overview's charts. None uses eslint:no-console or eslint:no-unused-vars, the rules
 * `seedDemo` looks up with `byRule` to triage open issues.
 */
const PAYMENTS_FIXED: FindingSpec[] = [
  {
    engine: 'eslint',
    rule: 'eqeqeq',
    path: 'src/payments/legacy-rates.ts',
    line: 21,
    message: "Expected '===' and instead saw '=='.",
  },
  {
    engine: 'eslint',
    rule: 'no-param-reassign',
    path: 'src/payments/legacy-rates.ts',
    line: 57,
    message: "Assignment to function parameter 'rate'.",
  },
  {
    engine: 'semgrep',
    rule: 'javascript.lang.security.detect-eval-with-expression',
    path: 'src/payments/legacy-rates.ts',
    line: 90,
    message: 'Detected eval() with a non-literal argument.',
  },
  {
    engine: 'eslint',
    rule: 'eqeqeq',
    path: 'src/refunds/legacy-queue.ts',
    line: 14,
    message: "Expected '===' and instead saw '=='.",
    severity: 'high',
  },
  {
    engine: 'eslint',
    rule: 'no-param-reassign',
    path: 'src/refunds/legacy-queue.ts',
    line: 33,
    message: "Assignment to function parameter 'queue'.",
  },
  {
    engine: 'gitleaks',
    rule: 'generic-api-key',
    path: 'config/legacy.env',
    line: 2,
    message: 'Generic API key detected.',
  },
];
/** The files of those findings, gone from the September analyses on. */
const LEGACY_FILES: FileSpec[] = [
  { path: 'src/payments/legacy-rates.ts', lines: 140, ncloc: 110, covered: 22 },
  { path: 'src/refunds/legacy-queue.ts', lines: 90, ncloc: 70, covered: 14 },
  { path: 'config/legacy.env', language: 'other', lines: 6, ncloc: 0 },
];
/** June to August on main: [day, version, scale, fixed findings still there, base findings]. */
const PAYMENTS_HISTORY: [string, string, number, number, number][] = [
  ['2026-06-02', '1.0.0', 0.55, 6, 3],
  ['2026-06-16', '1.0.1', 0.6, 6, 5],
  ['2026-06-30', '1.1.0', 0.64, 5, 5],
  ['2026-07-14', '1.1.1', 0.68, 5, 5],
  ['2026-07-28', '1.1.2', 0.72, 4, 5],
  ['2026-08-04', '1.1.3', 0.74, 3, 5],
  ['2026-08-11', '1.1.4', 0.76, 2, 5],
  ['2026-08-18', '1.1.5', 0.78, 1, 5],
];

function paymentsFiles(scale: number, newLines = false): FileSpec[] {
  return [
    {
      path: 'src/refunds/limits.ts',
      lines: 212,
      ncloc: Math.round(160 * scale),
      covered: Math.round(110 * scale),
      ...(newLines ? { newLines: [[40, 58]] } : {}),
    },
    { path: 'src/refunds/service.ts', lines: 180, ncloc: 140, covered: 92 },
    { path: 'src/payments/gateway.ts', lines: 320, ncloc: 260, covered: Math.round(150 * scale) },
    { path: 'src/payments/currency.ts', lines: 96, ncloc: 80, covered: 64 },
    { path: 'src/util/log.ts', lines: 20, ncloc: 14, covered: 14 },
    { path: 'config/staging.env', language: 'other', lines: 12, ncloc: 0 },
    { path: 'test/refunds.test.ts', kind: 'test', lines: 140, ncloc: 120 },
    // 6M: the lockfiles of the dependency inventory, for the Dependencies tab's links.
    { path: 'package-lock.json', language: 'other', lines: 96, ncloc: 0 },
    { path: 'go.mod', language: 'other', lines: 12, ncloc: 0 },
    { path: 'web/pnpm-lock.yaml', language: 'other', lines: 40, ncloc: 0 },
  ];
}

async function upload(
  base: string,
  token: string,
  projectKey: string,
  body: Report,
): Promise<void> {
  const res = await fetch(`${base}/api/v0/analyses?projectKey=${encodeURIComponent(projectKey)}`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': REPORT_CONTENT_TYPE,
      'content-encoding': 'gzip',
    },
    body: gzipSync(Buffer.from(JSON.stringify(body), 'utf8')),
  });
  if (res.status !== 202)
    throw new Error(`upload ${projectKey}: ${res.status} ${await res.text()}`);
  const { analysisId } = (await res.json()) as { analysisId: string };
  // Wait for the worker, so the next analysis of the branch is never older than a stored one.
  for (let i = 0; i < 300; i++) {
    const poll = await fetch(`${base}/api/v0/analyses/${analysisId}`, {
      headers: { authorization: `Bearer ${token}` },
    });
    const analysis = (await poll.json()) as { status: string; error: unknown };
    if (analysis.status === 'succeeded') return;
    if (analysis.status === 'failed') {
      throw new Error(`analysis of ${projectKey} failed: ${JSON.stringify(analysis.error)}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error(`analysis of ${projectKey} did not finish`);
}

interface Page<T> {
  items: T[];
}
interface Issue {
  id: string;
  message: string;
  rule: { key: string };
}

/** What {@link seedDemo} hands back: the last report of Payments API's main branch (6M). */
export interface DemoSeed {
  paymentsMainReport: Report;
}

export async function seedDemo(base: string, credentials: SeedCredentials): Promise<DemoSeed> {
  const admin = new Client(base);
  await admin.login(credentials.adminUsername, credentials.adminPassword);
  const [org] = (await admin.json<Page<{ id: string }>>('GET', '/api/v0/organizations')).items;
  if (!org) throw new Error('no default organization');

  const project = async (key: string, name: string) => {
    const created = await admin.json<{ id: string }>('POST', '/api/v0/projects', {
      organizationId: org.id,
      key,
      name,
    });
    const { token } = await admin.json<{ token: string }>(
      'POST',
      `/api/v0/projects/${created.id}/tokens`,
      { name: 'ci' },
    );
    return { id: created.id, key, token };
  };

  const payments = await project('acme/payments-api', 'Payments API');
  const common = { projectKey: payments.key, projectName: 'Payments API', branch: 'main' };
  // A history from June, so the overview's charts have a shape; it leaves the September state as
  // it was: the same open issues, new code and gate.
  for (const [index, [day, version, scale, fixed, baseCount]] of PAYMENTS_HISTORY.entries()) {
    await upload(
      base,
      payments.token,
      payments.key,
      report({
        ...common,
        version,
        date: `${day}T09:00:00Z`,
        // A 40-character revision per day (hex32 gives 32).
        revision: `${hex32(`history:${day}`)}${hex32(`rev:${day}`)}`.slice(0, 40),
        firstAnalysis: index === 0,
        files: [...paymentsFiles(scale), ...LEGACY_FILES],
        findings: [...PAYMENTS_FIXED.slice(0, fixed), ...PAYMENTS_BASE.slice(0, baseCount)],
      }),
    );
  }
  await upload(
    base,
    payments.token,
    payments.key,
    report({
      ...common,
      version: '1.2.0',
      date: '2026-09-01T09:00:00Z',
      revision: 'a'.repeat(40),
      firstAnalysis: false,
      files: paymentsFiles(0.8),
      findings: PAYMENTS_BASE,
    }),
  );
  await upload(
    base,
    payments.token,
    payments.key,
    report({
      ...common,
      version: '1.3.0',
      date: '2026-09-08T09:00:00Z',
      revision: 'b'.repeat(40),
      firstAnalysis: false,
      files: paymentsFiles(0.9),
      findings: [...PAYMENTS_BASE, ...PAYMENTS_SECOND],
    }),
  );
  const paymentsMainReport = report({
    ...common,
    version: '1.4.0',
    date: '2026-09-15T09:00:00Z',
    revision: '3f9a1c7e5b2d80a46c1e93d7f2b5a08e4c6d1b97',
    firstAnalysis: false,
    files: paymentsFiles(1, true),
    findings: [...PAYMENTS_BASE, ...PAYMENTS_SECOND, ...PAYMENTS_THIRD],
    // Outside the new lines (40–58), so the gate's new-code duplication stays as it was.
    duplications: [
      {
        blocks: [
          { path: 'src/refunds/limits.ts', startLine: 60, endLine: 80 },
          { path: 'src/refunds/service.ts', startLine: 30, endLine: 50 },
        ],
      },
    ],
    dependencies: PAYMENTS_DEPENDENCIES,
  });
  await upload(base, payments.token, payments.key, paymentsMainReport);
  await upload(
    base,
    payments.token,
    payments.key,
    report({
      ...common,
      branch: 'feature/refund-limits',
      version: '1.4.0',
      date: '2026-09-16T09:00:00Z',
      revision: 'd'.repeat(40),
      mergeRequest: { id: '42', sourceBranch: 'feature/refund-limits' },
      firstAnalysis: false,
      files: paymentsFiles(1, true),
      findings: [...PAYMENTS_BASE, ...PAYMENTS_THIRD],
      dependencies: PAYMENTS_DEPENDENCIES,
    }),
  );

  const shop = await project('acme/web-shop', 'Web Shop');
  await upload(
    base,
    shop.token,
    shop.key,
    report({
      projectKey: shop.key,
      projectName: 'Web Shop',
      branch: 'main',
      version: '2.0.0',
      date: '2026-09-14T09:00:00Z',
      revision: 'e'.repeat(40),
      firstAnalysis: true,
      files: [
        { path: 'src/cart.js', language: 'javascript', lines: 150, ncloc: 120, covered: 108 },
        { path: 'src/checkout.js', language: 'javascript', lines: 90, ncloc: 70, covered: 60 },
      ],
      findings: [
        {
          engine: 'eslint',
          rule: 'no-console',
          path: 'src/cart.js',
          line: 22,
          message: 'Unexpected console statement.',
        },
        // The markup in this message must stay text (ui/e2e/issues.spec.ts). It lives on Web
        // Shop so that the screens of the Payments API project read like a real project.
        {
          engine: 'eslint',
          rule: '@next/next/no-img-element',
          path: 'src/cart.js',
          line: 40,
          message: XSS_MESSAGE,
          severity: 'high',
        },
      ],
    }),
  );
  await project('acme/legacy-billing', 'Legacy Billing');

  // Triage: one false positive (with its reason) and one resolved issue on the main branch.
  const [mainBranch] = (
    await admin.json<Page<{ id: string }>>(
      'GET',
      `/api/v0/projects/${payments.id}/branches?kind=branch`,
    )
  ).items;
  if (!mainBranch) throw new Error('no main branch');
  const issues = (
    await admin.json<Page<Issue>>('GET', `/api/v0/issues?branchId=${mainBranch.id}&limit=100`)
  ).items;
  const byRule = (key: string) => issues.find((i) => i.rule.key === key);
  const logged = byRule('eslint:no-console');
  const unused = byRule('eslint:no-unused-vars');
  if (logged) {
    await admin.json('POST', `/api/v0/issues/${logged.id}/transition`, {
      to: 'false_positive',
      comment: 'Logging goes through this wrapper on purpose.',
    });
  }
  if (unused)
    await admin.json('POST', `/api/v0/issues/${unused.id}/transition`, { to: 'resolved' });

  // A custom gate and profile next to the built-ins.
  const gates = (
    await admin.json<Page<{ id: string; isBuiltin: boolean }>>(
      'GET',
      `/api/v0/quality-gates?organizationId=${org.id}`,
    )
  ).items;
  const builtinGate = gates.find((g) => g.isBuiltin);
  if (builtinGate) {
    const strict = await admin.json<{ id: string }>(
      'POST',
      `/api/v0/quality-gates/${builtinGate.id}/copy`,
      { name: 'Strict' },
    );
    await admin.json('POST', `/api/v0/quality-gates/${strict.id}/conditions`, {
      metric: 'coverage',
      operator: 'lt',
      threshold: 80,
    });
  }
  const profiles = (
    await admin.json<Page<{ id: string; language: string; isBuiltin: boolean }>>(
      'GET',
      `/api/v0/quality-profiles?organizationId=${org.id}&language=typescript`,
    )
  ).items;
  const builtinTs = profiles.find((p) => p.isBuiltin);
  if (builtinTs) {
    const custom = await admin.json<{ id: string }>(
      'POST',
      `/api/v0/quality-profiles/${builtinTs.id}/copy`,
      { name: 'Payments TypeScript' },
    );
    await admin.json(
      'PUT',
      `/api/v0/quality-profiles/${custom.id}/rules/${encodeURIComponent('eslint:no-console')}`,
      { active: false },
    );
    await admin.json('PUT', `/api/v0/projects/${payments.id}/quality-profiles/typescript`, {
      profileId: custom.id,
    });
  }

  // A member created by the admin must change the initial password (ruling R7).
  const alice = await admin.json<{ id: string }>('POST', '/api/v0/users', {
    username: 'alice',
    password: credentials.alicePassword,
    displayName: 'Alice Martin',
    email: 'alice@example.com',
  });
  await admin.json('PUT', `/api/v0/organizations/${org.id}/members/${alice.id}`, {
    role: 'member',
  });

  await admin.json('POST', '/api/v0/tokens', { name: 'laptop', scopes: ['read'] });
  await admin.json('POST', '/api/v0/webhooks', {
    organizationId: org.id,
    url: 'https://hooks.example.com/qualor',
    events: ['analysis.completed', 'gate.status_changed'],
  });
  // A webhook of Payments API only, and a second analysis token of it (project settings).
  await admin.json('POST', '/api/v0/webhooks', {
    organizationId: org.id,
    projectId: payments.id,
    url: 'https://hooks.example.com/payments',
    events: ['gate.status_changed'],
  });
  await admin.json('POST', `/api/v0/projects/${payments.id}/tokens`, {
    name: 'ci-main',
    expiresInDays: 90,
  });
  return { paymentsMainReport };
}

/**
 * A GitHub App connection of the default organisation, at a GitHub Enterprise Server address that
 * cannot resolve (`.invalid`, RFC 6761), with a fresh RSA key and a webhook secret (github.md
 * §2.2), for the GitHub tab's screenshot. Nothing calls GitHub, and nothing could: creating a
 * connection only stores it. Seeded through a server with another
 * QUALOR_SECRET_KEY, the App's key and secret show as no longer readable.
 */
export async function seedGitHubApp(
  base: string,
  credentials: SeedCredentials,
  appId: string,
): Promise<void> {
  const admin = new Client(base);
  await admin.login(credentials.adminUsername, credentials.adminPassword);
  const [org] = (await admin.json<Page<{ id: string }>>('GET', '/api/v0/organizations')).items;
  if (!org) throw new Error('no default organization');
  const { privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
  await admin.json('POST', '/api/v0/scm-connections', {
    organizationId: org.id,
    provider: 'github',
    baseUrl: 'https://github.qualor.invalid/api/v3',
    appId,
    privateKey,
    webhookSecret: `e2e-webhook-secret-${appId}`,
  });
}

/** What {@link seedAi} points the instance at: local fakes only, never a real host. */
export interface AiSeedTargets {
  /** The fake LLM's OpenAI-compatible base URL (`http://127.0.0.1:<port>/v1`). */
  llmBaseUrl: string;
  llmApiKey: string;
  /** The fake GitLab's base URL and token. */
  gitlabUrl: string;
  gitlabToken: string;
  /** The fake GitLab project Payments API is mapped to. */
  gitlabProjectRef: string;
}

/**
 * The AI assistant (llm.md §18), for its end-to-end tests and screenshots: the provider set to the
 * fake LLM on loopback (the served server lists it in QUALOR_LLM_INTERNAL_HOSTS), the default
 * organisation enabled with every feature, and Payments API mapped to a GitLab connection at the
 * fake GitLab, so a fix suggestion on merge request !42 can be posted. Mapped after the analyses
 * were uploaded: nothing is decorated while seeding.
 */
export async function seedAi(
  base: string,
  credentials: SeedCredentials,
  targets: AiSeedTargets,
): Promise<void> {
  const admin = new Client(base);
  await admin.login(credentials.adminUsername, credentials.adminPassword);
  const [org] = (await admin.json<Page<{ id: string }>>('GET', '/api/v0/organizations')).items;
  if (!org) throw new Error('no default organization');
  const current = await admin.json<{
    excludePaths: string[];
    budgets: unknown;
    pricing: unknown;
    storePrompts: boolean;
    promptRetentionDays: number;
  }>('GET', '/api/v0/system/llm');
  await admin.json('PUT', '/api/v0/system/llm', {
    provider: {
      kind: 'openai',
      baseUrl: targets.llmBaseUrl,
      model: 'fake-model',
      apiKey: targets.llmApiKey,
    },
    organizations: {
      [org.id]: {
        enabled: true,
        features: { explain: true, triage: true, fix: true },
        excludedProjectIds: [],
      },
    },
    excludePaths: current.excludePaths,
    budgets: current.budgets,
    pricing: current.pricing,
    storePrompts: current.storePrompts,
    promptRetentionDays: current.promptRetentionDays,
  });

  const connection = await admin.json<{ id: string }>('POST', '/api/v0/scm-connections', {
    organizationId: org.id,
    provider: 'gitlab',
    baseUrl: targets.gitlabUrl,
    token: targets.gitlabToken,
  });
  const payments = (
    await admin.json<Page<{ id: string; key: string }>>('GET', '/api/v0/projects?limit=100')
  ).items.find((p) => p.key === 'acme/payments-api');
  if (!payments) throw new Error('no Payments API project');
  await admin.json('PATCH', `/api/v0/projects/${payments.id}`, {
    scmConnectionId: connection.id,
    scmProjectRef: targets.gitlabProjectRef,
  });
}

/**
 * Email (E1 spec) for the screenshots and the settings tests: a server nothing listens on (no real
 * SMTP in the tests), so Settings → Email shows a configured server, its alerts and one failed
 * test message in the log.
 */
export async function seedMail(base: string, credentials: SeedCredentials): Promise<void> {
  const admin = new Client(base);
  await admin.login(credentials.adminUsername, credentials.adminPassword);
  await admin.json('PUT', '/api/v0/system/mail', {
    server: {
      host: '127.0.0.1',
      port: 9,
      security: 'none',
      username: 'qualor',
      password: ['e2e', 'smtp', 'password'].join('-'),
      fromName: 'Qualor',
      fromAddress: 'qualor@example.com',
      replyTo: null,
    },
  });
  // Nothing listens on port 9: the test message fails (502), and the log shows it.
  const refused = await admin
    .json('POST', '/api/v0/system/mail/test', { to: 'admin@example.com' })
    .then(
      () => null,
      (err: unknown) => err,
    );
  if (!(refused instanceof Error) || !refused.message.includes(': 502 ')) {
    throw new Error(`the e2e test message should have been refused: ${String(refused)}`);
  }
}

/** The people of the roles tests (rbac-audit.md §17), with the passwords they end up with. */
export interface RoleSeedUsers {
  /** An organisation admin of the default organisation who is not an instance admin. */
  olgaPassword: string;
  /** A user in no organisation, with a Viewer grant on Web Shop only. */
  victorPassword: string;
}

/**
 * Creates a user through the API, then signs in as that user and changes the initial password
 * (ruling R7), so the end-to-end tests can sign in with `password` directly.
 */
async function userWithPassword(
  base: string,
  admin: Client,
  username: string,
  displayName: string,
  password: string,
): Promise<{ id: string }> {
  const initial = `${password} (initial)`;
  const user = await admin.json<{ id: string }>('POST', '/api/v0/users', {
    username,
    password: initial,
    displayName,
  });
  const self = new Client(base);
  await self.login(username, initial);
  await self.json('PUT', '/api/v0/auth/me/password', {
    currentPassword: initial,
    newPassword: password,
  });
  return user;
}

/**
 * The roles and project grants of both e2e servers (rbac-audit.md §1.3, §17: every edition has
 * them since 5B), created through the core API: an organisation admin `olga`, a Viewer `vera`
 * and a Project admin `pat` of the default organisation, `victor` with only a Viewer grant on
 * Web Shop, and `petra` with a Project admin grant on Web Shop.
 */
export async function seedRoles(
  base: string,
  credentials: SeedCredentials,
  users: RoleSeedUsers,
): Promise<void> {
  const admin = new Client(base);
  await admin.login(credentials.adminUsername, credentials.adminPassword);
  const [org] = (await admin.json<Page<{ id: string }>>('GET', '/api/v0/organizations')).items;
  if (!org) throw new Error('no default organization');
  const shop = (
    await admin.json<Page<{ id: string; key: string }>>('GET', '/api/v0/projects?limit=100')
  ).items.find((p) => p.key === 'acme/web-shop');
  if (!shop) throw new Error('no Web Shop project');

  const olga = await userWithPassword(base, admin, 'olga', 'Olga Berg', users.olgaPassword);
  await admin.json('PUT', `/api/v0/organizations/${org.id}/members/${olga.id}`, { role: 'admin' });
  for (const [username, displayName, role] of [
    ['vera', 'Vera Lind', 'viewer'],
    ['pat', 'Pat Moreau', 'project_admin'],
  ] as const) {
    const user = await admin.json<{ id: string }>('POST', '/api/v0/users', {
      username,
      password: `${username} initial passphrase`,
      displayName,
    });
    await admin.json('PUT', `/api/v0/organizations/${org.id}/members/${user.id}`, { role });
  }
  const victor = await userWithPassword(base, admin, 'victor', 'Victor Hale', users.victorPassword);
  const petra = await admin.json<{ id: string }>('POST', '/api/v0/users', {
    username: 'petra',
    password: 'petra initial passphrase',
    displayName: 'Petra Novak',
  });
  await admin.json('PUT', `/api/v0/projects/${shop.id}/members/${victor.id}`, {
    role: 'viewer',
  });
  await admin.json('PUT', `/api/v0/projects/${shop.id}/members/${petra.id}`, {
    role: 'project_admin',
  });

  // The organisation admins of the suite are past onboarding: their setup checklist is closed, as
  // an admin closes it once the server is set up ("Don't show again"). ui/e2e's
  // setup-checklist.spec.ts opens the admin's again for itself.
  const olgaSession = new Client(base);
  await olgaSession.login('olga', users.olgaPassword);
  for (const session of [admin, olgaSession]) {
    await session.json('PUT', `/api/v0/organizations/${org.id}/setup-checklist`, { closed: true });
  }
}

/**
 * The enterprise data of the licensed e2e server (`audit-log`, `sso`, `scim`), created through
 * the app so that the audit log records it: the people of {@link seedRoles}, then `olga`, as an
 * organisation admin, gives `victor` the Viewer role on Payments API. Every step (users, members,
 * grants, sign-ins, password changes) is an audit event; olga's grant is the newest
 * `project_member.*` one (ui/e2e/enterprise.spec.ts).
 */
export async function seedEnterprise(
  base: string,
  credentials: SeedCredentials,
  users: RoleSeedUsers,
): Promise<void> {
  await seedRoles(base, credentials, users);
  const olga = new Client(base);
  await olga.login('olga', users.olgaPassword);
  const payments = (
    await olga.json<Page<{ id: string; key: string }>>('GET', '/api/v0/projects?limit=100')
  ).items.find((p) => p.key === 'acme/payments-api');
  if (!payments) throw new Error('no Payments API project');
  const victor = await olga.json<{ id: string }>('GET', '/api/v0/users/lookup?username=victor');
  await olga.json('PUT', `/api/v0/projects/${payments.id}/members/${victor.id}`, {
    role: 'viewer',
  });
}

/**
 * The committed test certificate of server/test/fixtures/saml (a throwaway key pair made for the
 * SAML tests; it protects nothing). Read by path, so the seed does not load the SAML test helpers.
 */
const TEST_IDP_CERTIFICATE = new URL('../../test/fixtures/saml/idp.cert.pem', import.meta.url);

/** What {@link seedSso} created, for the SQL step that follows it. */
export interface SsoSeed {
  acmeId: string;
}

/**
 * Single sign-on and SCIM on the licensed e2e server (sso-scim.md §18, plan 4D Task 22), through
 * the app so the audit log records it:
 * - "Acme SSO", an enabled OIDC connection for the sign-in page's button, and "Staging OIDC", a
 *   disabled one. Both issuers are under `.invalid` (RFC 6761): saving a connection contacts
 *   nothing, and no test presses Test, starts a flow or reads discovery for them, so the e2e
 *   server makes no outbound call.
 * - "Corp SAML", a disabled SAML connection pinning the SAML tests' certificate, so the screen
 *   shows a real SHA-256 fingerprint and expiry.
 * - Group mappings of Acme SSO onto the default organisation and Web Shop.
 * - A SCIM token of Acme SSO, used once here to provision `sso-user`, an account without a
 *   password (the Users screen's "No password" and "SCIM" badges). The token itself is dropped.
 * The server must run with QUALOR_PUBLIC_URL set, since enabling a connection needs it.
 */
export async function seedSso(base: string, credentials: SeedCredentials): Promise<SsoSeed> {
  const admin = new Client(base);
  await admin.login(credentials.adminUsername, credentials.adminPassword);
  const [org] = (await admin.json<Page<{ id: string }>>('GET', '/api/v0/organizations')).items;
  if (!org) throw new Error('no default organization');
  const shop = (
    await admin.json<Page<{ id: string; key: string }>>('GET', '/api/v0/projects?limit=100')
  ).items.find((p) => p.key === 'acme/web-shop');
  if (!shop) throw new Error('no Web Shop project');
  // Split, so no secret scanner takes the test value for a real one.
  const clientSecret = ['e2e', 'client', 'secret', 'never', 'sent'].join('-');

  const acme = await admin.json<{ id: string }>('POST', '/api/v0/ee/sso/connections', {
    name: 'Acme SSO',
    protocol: 'oidc',
    enabled: true,
    groupSource: 'claims',
    claims: { groups: 'groups' },
    oidc: { issuer: 'https://idp.invalid/realms/acme', clientId: 'qualor', clientSecret },
  });
  await admin.json('POST', '/api/v0/ee/sso/connections', {
    name: 'Staging OIDC',
    protocol: 'oidc',
    enabled: false,
    oidc: { issuer: 'https://staging-idp.invalid', clientId: 'qualor-staging', clientSecret },
  });
  await admin.json('POST', '/api/v0/ee/sso/connections', {
    name: 'Corp SAML',
    protocol: 'saml',
    enabled: false,
    saml: {
      idpEntityId: 'https://idp.corp.invalid/saml',
      idpSsoUrl: 'https://idp.corp.invalid/saml/sso',
      idpCertificates: [readFileSync(TEST_IDP_CERTIFICATE, 'utf8')],
      metadataUrl: 'https://idp.corp.invalid/saml/metadata',
    },
  });
  await admin.json('PUT', `/api/v0/ee/sso/connections/${acme.id}/mappings`, [
    { group: 'engineering', organizationId: org.id, projectId: null, role: 'member' },
    { group: 'qa', organizationId: org.id, projectId: shop.id, role: 'viewer' },
  ]);

  const { token } = await admin.json<{ token: string }>('POST', '/api/v0/ee/scim/tokens', {
    connectionId: acme.id,
    name: 'Entra ID provisioning',
  });
  const res = await fetch(`${base}/api/v0/ee/scim/v2/Users`, {
    method: 'POST',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/scim+json' },
    body: JSON.stringify({
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
      userName: 'sso-user',
      displayName: 'Sam Singh',
      name: { givenName: 'Sam', familyName: 'Singh' },
      active: true,
    }),
  });
  if (res.status !== 201) throw new Error(`SCIM POST /Users: ${res.status} ${await res.text()}`);
  return { acmeId: acme.id };
}

/**
 * The one step the API cannot take: an identity of the instance admin on Acme SSO, as a completed
 * link would leave it (sso-scim.md §8.1), so the Linked accounts screen has a row. Linking needs a
 * sign-in at the identity provider, which the e2e server never contacts.
 */
export async function seedSsoIdentity(databaseUrl: string, seed: SsoSeed): Promise<void> {
  const client = new pg.Client({ connectionString: databaseUrl });
  await client.connect();
  try {
    await client.query(
      `INSERT INTO identities (id, connection_id, user_id, subject, linked_by, last_sign_in_at)
       SELECT gen_random_uuid(), $1, id, 'e2e-admin-subject', 'user', now() - interval '2 days'
       FROM users WHERE username = 'admin'`,
      [seed.acmeId],
    );
  } finally {
    await client.end();
  }
}

/**
 * The AI finding of merge request !42 of Payments API (ui/e2e/seed-data.ts AI_FINDING): a finding of
 * the review's `logic` category on the line the merge request changed (the fake GitLab's diff),
 * with a suggestion, and a body that carries markup, which the UI must show as text.
 */
const AI_FINDING = {
  message: 'Loose equality lets a value of another type pass for the euro.',
  body: 'The currency is compared with ==, so a value that only converts to "EUR" takes the euro branch. Strict equality, <img src=x onerror="alert(1)"> as in the rest of the file, avoids that.',
  assumption: 'order.currency is always a string.',
  path: 'src/refunds/limits.ts',
  line: 12,
  snippet: {
    startLine: 11,
    lines: [
      '  const limit = eval(order.policy);',
      '  if (order.currency == "EUR") {',
      '    return Math.min(amount, limit);',
    ],
  },
  suggestion: { startLine: 12, endLine: 12, lines: ['  if (order.currency === "EUR") {'] },
  /** The head commit of the merge request's analysis. */
  headSha: 'd'.repeat(40),
};

/**
 * The one step the API cannot take: a finding of the AI review on merge request !42 of Payments
 * API, as a finished review leaves it (an issue of the `ai` engine with its finding row, in new
 * code). A review needs a worker, a repository snapshot and a model's answer, none of which the e2e
 * server has; the tests only need what a review leaves behind.
 */
export async function seedAiFinding(databaseUrl: string): Promise<void> {
  const database = createDatabase(databaseUrl, { max: 1 });
  try {
    const { db } = database;
    const ruleId = (await ensureAiRules(db)).get('logic');
    const [branch] = await db
      .select({ id: branches.id, projectId: branches.projectId })
      .from(branches)
      .innerJoin(projects, eq(projects.id, branches.projectId))
      .where(
        and(
          eq(projects.key, 'acme/payments-api'),
          eq(branches.kind, 'merge_request'),
          eq(branches.name, '42'),
        ),
      );
    if (!ruleId || !branch)
      throw new Error('no AI rule or no merge request !42 to put a finding on');
    await db.transaction(async (tx) => {
      const [issue] = await tx
        .insert(issues)
        .values({
          projectId: branch.projectId,
          branchId: branch.id,
          ruleId,
          fingerprint: hex32('e2e-ai-finding'),
          lineHash: hex32('e2e-ai-line'),
          contextHash: hex32('e2e-ai-context'),
          path: AI_FINDING.path,
          startLine: AI_FINDING.line,
          endLine: AI_FINDING.line,
          message: AI_FINDING.message,
          severity: 'medium',
          quality: 'reliability',
          kind: 'issue',
          status: 'open',
          inNewCode: true,
          snippet: AI_FINDING.snippet,
          confidence: 'high',
          firstSeenAt: sql`now()`,
        })
        .returning({ id: issues.id });
      if (!issue) throw new Error('the AI finding was not stored');
      await tx.insert(reviewFindings).values({
        issueId: issue.id,
        category: 'logic',
        body: AI_FINDING.body,
        assumption: AI_FINDING.assumption,
        suggestion: AI_FINDING.suggestion,
        anchorLine: AI_FINDING.line,
        reviewedHeadSha: AI_FINDING.headSha,
      });
    });
  } finally {
    await database.close();
  }
}
