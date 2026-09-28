import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  branchesSchema,
  componentShowSchema,
  componentsPageSchema,
  currentUserSchema,
  gateByProjectSchema,
  gateListSchema,
  gateShowSchema,
  hotspotsPageSchema,
  issuesPageSchema,
  organizationsSchema,
  planGate,
  planProfile,
  profilesSchema,
  rulesPageSchema,
  SONAR_LINE_HASH,
  type SonarIssue,
  sonarLineHash,
  versionAtLeast,
} from '@qualor/shared';
import { z } from 'zod';
import { buildStatusItems } from '../src/import/issues';
import {
  connectSonar,
  detectSonarKind,
  SONAR_READ_ENDPOINTS,
  type SonarConnection,
  type Transport,
} from '../src/import/sonarqube/client';
import {
  countReviewedHotspots,
  fetchGates,
  fetchProfiles,
  fetchProjectSettings,
  fetchResolvedIssues,
  listProjects,
  openIssueFilters,
} from '../src/import/sonarqube/fetch';
import { silentLogger } from '../src/log';
import { type HttpResponse, request, type ServerEndpoint } from '../src/server/http';

/**
 * Plan 3A Task 17, import-sonarqube.md §17.1: the opt-in live check of a real SonarQube Server or
 * SonarQube Cloud organisation, run only by hand through `pnpm sonar:live`
 * (`sonar-live.live.test.ts`). It reads (GET only, allow-listed paths, a capped request budget),
 * maps and builds items as the import would, contacts no Qualor server and writes nothing. Its
 * summary is aggregate only: counts, field names and API shapes; it refuses to print anything
 * that holds the token, the organisation key, or a project, profile, gate, branch or file name,
 * an issue's key, message, comment or hash, or a line of code. Checked against the fake by
 * `sonar-live-check.test.ts`.
 */

/** The import's read endpoints plus `api/sources/lines`, for the line hash check only (S1). */
export const LIVE_READ_ENDPOINTS: ReadonlySet<string> = new Set([
  ...SONAR_READ_ENDPOINTS,
  'api/sources/lines',
]);

/** `api/sources/lines` (SonarSource Web API): the lines of a file, `code` as HTML. */
export const sourceLinesSchema = z.looseObject({
  sources: z
    .array(
      z.looseObject({
        line: z.number().int().min(1),
        code: z.string().max(1_000_000).optional(),
      }),
    )
    .max(1000),
});

const SCHEMAS: Readonly<Record<string, z.ZodType>> = {
  'api/users/current': currentUserSchema,
  'api/organizations/search': organizationsSchema,
  'api/qualityprofiles/search': profilesSchema,
  'api/rules/search': rulesPageSchema,
  'api/qualitygates/list': gateListSchema,
  'api/qualitygates/show': gateShowSchema,
  'api/qualitygates/get_by_project': gateByProjectSchema,
  'api/components/search': componentsPageSchema,
  'api/components/show': componentShowSchema,
  'api/project_branches/list': branchesSchema,
  'api/issues/search': issuesPageSchema,
  'api/hotspots/search': hotspotsPageSchema,
  'api/sources/lines': sourceLinesSchema,
};

/** SonarSource's public rule repositories; any other (a custom one) is counted as `other`. */
const PUBLIC_REPOSITORIES: ReadonlySet<string> = new Set([
  'javascript',
  'typescript',
  'java',
  'squid',
  'python',
  'csharpsquid',
  'vbnet',
  'css',
  'Web',
  'xml',
  'secrets',
  'text',
  'docker',
  'kubernetes',
  'terraform',
  'cloudformation',
  'azureresourcemanager',
  'go',
  'kotlin',
  'php',
  'ruby',
  'scala',
  'swift',
  'plsql',
  'tsql',
  'flex',
  'c',
  'cpp',
  'objc',
  'jssecurity',
  'tssecurity',
  'javasecurity',
  'pythonsecurity',
  'phpsecurity',
  'roslyn.sonaranalyzer.security.cs',
  'external_eslint_repo',
  'external_pmd',
  'external_spotbugs',
  'external_roslyn',
  'pmd',
  'findbugs',
  'fb-contrib',
  'findsecbugs',
  'common-java',
  'common-js',
  'common-ts',
]);

const repositoryOf = (rule: string) => {
  const repo = rule.includes(':') ? rule.slice(0, rule.indexOf(':')) : '';
  return PUBLIC_REPOSITORIES.has(repo) ? repo : 'other';
};

export class LiveBudgetExhausted extends Error {
  override name = 'LiveBudgetExhausted';
  constructor(budget: number) {
    super(`live check: the request budget (${String(budget)}) is used up`);
  }
}

class LiveRefusal extends Error {
  override name = 'LiveRefusal';
}

export interface EndpointObservation {
  requests: number;
  statuses: Record<string, number>;
  /** Answers the shared schema (or `sourceLinesSchema`) accepted or refused; 200 JSON only. */
  schema: { accepted: number; rejected: number };
  /** Top-level field names of the 200 answers. */
  fields: string[];
  /** Field names (paths like `issues[].type`) the schema does not declare; allowed, listed. */
  unknownFields: string[];
}

const FIELD_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const fieldName = (k: string) => (FIELD_NAME.test(k) ? k : '<not an identifier>');
const MAX_WALK_ITEMS = 100;

/** Field paths of `value` that `schema` does not declare; keys of records are never names. */
function unknownFields(schema: z.ZodType, value: unknown, at: string, out: Set<string>): void {
  let def = (schema as unknown as { _zod: { def: Record<string, unknown> } })._zod.def;
  for (;;) {
    const inner = (def['innerType'] ?? def['in']) as z.ZodType | undefined;
    if (inner === undefined) break;
    def = (inner as unknown as { _zod: { def: Record<string, unknown> } })._zod.def;
  }
  const type = def['type'];
  if (type === 'object' && value !== null && typeof value === 'object' && !Array.isArray(value)) {
    const shape = def['shape'] as Record<string, z.ZodType>;
    for (const [k, v] of Object.entries(value)) {
      const child = shape[k];
      if (child === undefined) out.add(`${at}${fieldName(k)}`);
      else unknownFields(child, v, `${at}${fieldName(k)}.`, out);
    }
  } else if (type === 'array' && Array.isArray(value)) {
    for (const v of value.slice(0, MAX_WALK_ITEMS)) {
      unknownFields(def['element'] as z.ZodType, v, `${at.replace(/\.$/, '')}[].`, out);
    }
  } else if (type === 'record' && value !== null && typeof value === 'object') {
    for (const v of Object.values(value).slice(0, MAX_WALK_ITEMS)) {
      unknownFields(def['valueType'] as z.ZodType, v, `${at.replace(/\.$/, '')}{}.`, out);
    }
  }
}

/**
 * The live check's own transport: `GET` on a path of `LIVE_READ_ENDPOINTS` and no body, all
 * checked before any I/O, and at most `budget` requests. It records each answer's status and
 * shape (field names only) and the authenticated endpoint, for the line reads.
 */
export function guardTransport(base: Transport, budget: number) {
  let used = 0;
  let authed: ServerEndpoint | null = null;
  const endpoints = new Map<
    string,
    {
      requests: number;
      statuses: Map<number, number>;
      accepted: number;
      rejected: number;
      fields: Set<string>;
      unknown: Set<string>;
    }
  >();
  const observe = (p: string, res: HttpResponse) => {
    let e = endpoints.get(p);
    if (e === undefined) {
      e = {
        requests: 0,
        statuses: new Map(),
        accepted: 0,
        rejected: 0,
        fields: new Set(),
        unknown: new Set(),
      };
      endpoints.set(p, e);
    }
    e.requests += 1;
    e.statuses.set(res.status, (e.statuses.get(res.status) ?? 0) + 1);
    const schema = SCHEMAS[p];
    if (res.status !== 200 || schema === undefined) return;
    let body: unknown;
    try {
      body = JSON.parse(res.body) as unknown;
    } catch {
      e.rejected += 1;
      return;
    }
    if (schema.safeParse(body).success) e.accepted += 1;
    else e.rejected += 1;
    if (body !== null && typeof body === 'object' && !Array.isArray(body)) {
      for (const k of Object.keys(body)) e.fields.add(fieldName(k));
    }
    unknownFields(schema, body, '', e.unknown);
  };
  const transport: Transport = async (ep, o) => {
    if (o.method !== 'GET') throw new LiveRefusal(`live check: refusing ${String(o.method)}`);
    if (!LIVE_READ_ENDPOINTS.has(o.path)) {
      throw new LiveRefusal('live check: refusing a path outside the read list');
    }
    if (o.json !== undefined || o.body !== undefined) {
      throw new LiveRefusal('live check: refusing a request with a body');
    }
    if (used >= budget) throw new LiveBudgetExhausted(budget);
    used += 1;
    const res = await base(ep, o);
    if (ep.auth !== 'none' && res.status === 200) authed = ep;
    observe(o.path, res);
    return res;
  };
  return {
    transport,
    used: () => used,
    authed: () => authed,
    endpoints: (): Record<string, EndpointObservation> =>
      Object.fromEntries(
        [...endpoints]
          .sort((a, b) => (a[0] < b[0] ? -1 : 1))
          .map(([p, e]) => [
            p,
            {
              requests: e.requests,
              statuses: Object.fromEntries([...e.statuses].sort((a, b) => a[0] - b[0])),
              schema: { accepted: e.accepted, rejected: e.rejected },
              fields: [...e.fields].sort(),
              unknownFields: [...e.unknown].sort(),
            },
          ]),
      ),
  };
}

const ENTITIES: Record<string, string> = { lt: '<', gt: '>', quot: '"', apos: "'", amp: '&' };

/**
 * The source text of a line of `api/sources/lines`: SonarQube wraps tokens in `<span>` and
 * escapes `<`, `>`, `&`, `"` and `'`. One pass, so `&amp;lt;` stays `&lt;`.
 */
export function sonarSourceText(code: string): string {
  return code
    .replace(/<[^>]*>/g, '')
    .replace(
      /&(?:#(\d{1,7})|#[xX]([0-9a-fA-F]{1,6})|(lt|gt|quot|apos|amp));/g,
      (m, dec, hex, name) => {
        if (typeof name === 'string') return ENTITIES[name] ?? m;
        const cp = typeof dec === 'string' ? Number(dec) : Number.parseInt(String(hex), 16);
        return cp <= 0x10ffff ? String.fromCodePoint(cp) : m;
      },
    );
}

/** Values under this length cannot be told from ordinary words of the summary: not checked. */
const MIN_CHECKED = 3;

/** The categories of the `sensitive` values `text` holds; never the values themselves. */
export function leakedCategories(text: string, sensitive: ReadonlyMap<string, string>): string[] {
  const found = new Set<string>();
  for (const [value, category] of sensitive) {
    if (value.length >= MIN_CHECKED && text.includes(value)) found.add(category);
  }
  return [...found].sort();
}

function redact(message: string, sensitive: ReadonlyMap<string, string>): string {
  let out = message;
  const values = [...sensitive.keys()]
    .filter((v) => v.length >= MIN_CHECKED)
    .sort((a, b) => b.length - a.length);
  for (const v of values) out = out.split(v).join('<redacted>');
  return out;
}

export interface LiveOptions {
  url: string;
  token: string;
  organization: string | null;
  kind: 'auto' | 'server' | 'cloud';
  maxRequests: number;
  maxProjects: number;
  maxHashes: number;
  /** Resolved issues read per sampled project. */
  maxIssues: number;
  /** The real transport; the tests' fake is reached through `request` too. */
  transport?: Transport;
  sleep?: (ms: number) => Promise<void>;
}

export interface LiveEnv extends LiveOptions {
  /** `QUALOR_LIVE_SONAR_SUMMARY`: where to write the aggregate JSON (outside the repository). */
  summaryPath: string | null;
}

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

export function liveEnabled(env: Readonly<Record<string, string | undefined>>): boolean {
  return (
    (env['QUALOR_LIVE_SONAR_URL'] ?? '') !== '' && (env['QUALOR_LIVE_SONAR_TOKEN'] ?? '') !== ''
  );
}

function limit(
  env: Readonly<Record<string, string | undefined>>,
  name: string,
  fallback: number,
  max: number,
): number {
  const raw = env[name] ?? '';
  if (raw === '') return fallback;
  const n = Number(raw);
  if (!/^\d+$/.test(raw) || !Number.isSafeInteger(n) || n < 1 || n > max) {
    throw new Error(`${name} must be a whole number from 1 to ${String(max)}`);
  }
  return n;
}

/**
 * The live check's settings from the environment (spec §17.1). The URL must be `https`; SonarQube
 * Cloud needs `QUALOR_LIVE_SONAR_ORG`. Small defaults: 200 requests, 3 projects, 20 line hashes.
 */
export function readLiveEnv(env: Readonly<Record<string, string | undefined>>): LiveEnv {
  const url = (env['QUALOR_LIVE_SONAR_URL'] ?? '').trim().replace(/\/+$/, '');
  const token = (env['QUALOR_LIVE_SONAR_TOKEN'] ?? '').trim();
  const org = (env['QUALOR_LIVE_SONAR_ORG'] ?? '').trim();
  if (url === '' || token === '') {
    throw new Error('QUALOR_LIVE_SONAR_URL and QUALOR_LIVE_SONAR_TOKEN are both needed');
  }
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error('QUALOR_LIVE_SONAR_URL is not a URL');
  }
  if (parsed.protocol !== 'https:' || parsed.username !== '' || parsed.password !== '') {
    throw new Error('QUALOR_LIVE_SONAR_URL must be an https URL without credentials');
  }
  if (detectSonarKind(url) === 'cloud' && org === '') {
    throw new Error('QUALOR_LIVE_SONAR_ORG (the organisation key) is needed for SonarQube Cloud');
  }
  const summary = (env['QUALOR_LIVE_SONAR_SUMMARY'] ?? '').trim();
  let summaryPath: string | null = null;
  if (summary !== '') {
    summaryPath = path.resolve(summary);
    const rel = path.relative(repoRoot, summaryPath);
    if (rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel))) {
      throw new Error('QUALOR_LIVE_SONAR_SUMMARY must be a path outside the repository');
    }
  }
  return {
    url,
    token,
    organization: org === '' ? null : org,
    kind: 'auto',
    maxRequests: limit(env, 'QUALOR_LIVE_SONAR_MAX_REQUESTS', 200, 5000),
    maxProjects: limit(env, 'QUALOR_LIVE_SONAR_MAX_PROJECTS', 3, 50),
    maxHashes: limit(env, 'QUALOR_LIVE_SONAR_MAX_HASHES', 20, 500),
    maxIssues: limit(env, 'QUALOR_LIVE_SONAR_MAX_ISSUES', 500, 10_000),
    summaryPath,
  };
}

type Count = Record<string, number>;
const bump = (m: Count, k: string, by = 1) => {
  m[k] = (m[k] ?? 0) + by;
};
const sorted = (m: Count): Count =>
  Object.fromEntries(Object.entries(m).sort((a, b) => (a[0] < b[0] ? -1 : 1)));

export interface LiveSummary {
  kind: 'server' | 'cloud' | null;
  version: string | null;
  requests: { used: number; budget: number; budgetExhausted: boolean };
  failures: { phase: string; error: string }[];
  endpoints: Record<string, EndpointObservation>;
  profiles: {
    total: number;
    byLanguage: Count;
    skipped: Count;
    activeRules: number;
    mapped: number;
    pendingReview: number;
    statusOnly: number;
    unmapped: number;
    /** Across the read profiles, each rule once: `active` = the other four added up. */
    distinct: {
      active: number;
      mapped: number;
      pendingReview: number;
      statusOnly: number;
      unmapped: number;
    };
  };
  gates: { total: number; skipped: Count; conditions: Count };
  projects: { total: number; sampled: number };
  issues: {
    issueQuery: 'issueStatuses' | 'resolutions' | null;
    resolved: number;
    notRead: number;
    /** Summed over the projects counted; `null` when none was (finding L1). */
    reviewedHotspots: number | null;
    /** Sampled projects whose hotspot count failed (`HOTSPOTS_NOT_COUNTED`); their issues still count. */
    hotspotsNotCounted: number;
    withIssueStatus: number;
    byStatus: Count;
    byRepository: Count;
    items: {
      built: number;
      unmappedRule: number;
      pathInvalid: number;
      invalid: number;
      ignored: number;
      withHash: number;
      fileLess: number;
    };
  };
  /** Ruling S1: `sonarLineHash` of the line read through `api/sources/lines` vs the issue's hash. */
  lineHash: {
    sampled: number;
    compared: number;
    match: number;
    mismatch: number;
    blankLines: number;
    unreadable: number;
    skippedNoHash: number;
    byLanguage: Record<string, { match: number; mismatch: number }>;
  };
  /** Whether the `rules` facet of a query with `rules=` lists that rule only, at the query's total. */
  facetHonoursFilter: 'yes' | 'no' | 'not observed';
  warnings: Count;
}

/** The query of the import's resolved read (fetch.ts), rebuilt for the facet observation. */
function resolvedFilter(conn: SonarConnection): Record<string, string> {
  return conn.kind === 'server' && conn.version !== null && versionAtLeast(conn.version, 10, 4)
    ? { issueStatuses: 'ACCEPTED,FALSE_POSITIVE' }
    : { resolutions: 'FALSE-POSITIVE,WONTFIX' };
}

/** The first filter of the import's open read (fetch.ts), for one page of open issues. */
function openFilter(conn: SonarConnection): Record<string, string> {
  return openIssueFilters(conn)[0] ?? { resolved: 'false' };
}

/** Default branch names say nothing of the organisation (and `main` is inside `remaining`). */
const COMMON_BRANCHES: ReadonlySet<string> = new Set(['main', 'master', 'trunk', 'develop']);

const lineOf = (i: SonarIssue) => i.line ?? i.textRange?.startLine ?? null;

/**
 * Runs the live check (spec §17.1) and returns its summary and the JSON text to print. Throws,
 * without the value, if the text would hold anything of the organisation; a failed connection
 * throws with the token and the organisation key redacted. A later phase that fails is recorded
 * (its message redacted) and the others still run, until the request budget is used up.
 */
export async function runLiveCheck(
  o: LiveOptions,
): Promise<{ summary: LiveSummary; text: string }> {
  const sensitive = new Map<string, string>();
  const mark = (v: string | null | undefined, category: string) => {
    if (v !== null && v !== undefined && v !== '' && !sensitive.has(v)) sensitive.set(v, category);
  };
  mark(o.token, 'token');
  mark(o.organization, 'organisation key');
  const guard = guardTransport(o.transport ?? request, o.maxRequests);

  const summary: LiveSummary = {
    kind: null,
    version: null,
    requests: { used: 0, budget: o.maxRequests, budgetExhausted: false },
    failures: [],
    endpoints: {},
    profiles: {
      total: 0,
      byLanguage: {},
      skipped: {},
      activeRules: 0,
      mapped: 0,
      pendingReview: 0,
      statusOnly: 0,
      unmapped: 0,
      distinct: { active: 0, mapped: 0, pendingReview: 0, statusOnly: 0, unmapped: 0 },
    },
    gates: { total: 0, skipped: {}, conditions: {} },
    projects: { total: 0, sampled: 0 },
    issues: {
      issueQuery: null,
      resolved: 0,
      notRead: 0,
      reviewedHotspots: null,
      hotspotsNotCounted: 0,
      withIssueStatus: 0,
      byStatus: {},
      byRepository: {},
      items: {
        built: 0,
        unmappedRule: 0,
        pathInvalid: 0,
        invalid: 0,
        ignored: 0,
        withHash: 0,
        fileLess: 0,
      },
    },
    lineHash: {
      sampled: 0,
      compared: 0,
      match: 0,
      mismatch: 0,
      blankLines: 0,
      unreadable: 0,
      skippedNoHash: 0,
      byLanguage: {},
    },
    facetHonoursFilter: 'not observed',
    warnings: {},
  };

  let conn: SonarConnection;
  try {
    conn = await connectSonar({
      url: o.url,
      token: o.token,
      kind: o.kind,
      organization: o.organization,
      auth: 'auto',
      timeoutMs: 30_000,
      log: silentLogger,
      transport: guard.transport,
      sleep: o.sleep,
    });
  } catch (err) {
    // No `cause`: the original message may name the organisation, and vitest prints causes.
    // eslint-disable-next-line preserve-caught-error
    throw new Error(
      `live check: connect failed: ${redact(err instanceof Error ? err.message : String(err), sensitive)}`,
    );
  }
  mark(conn.login, 'login');
  summary.kind = conn.kind;
  summary.version = conn.version?.text ?? null;
  summary.issues.issueQuery =
    'issueStatuses' in resolvedFilter(conn) ? 'issueStatuses' : 'resolutions';

  const errors: { phase: string; error: unknown }[] = [];
  let stopped = false;
  const phase = async (name: string, body: () => Promise<void>) => {
    if (stopped) return;
    try {
      await body();
    } catch (err) {
      errors.push({ phase: name, error: err });
      if (err instanceof LiveBudgetExhausted || err instanceof LiveRefusal) stopped = true;
    }
  };

  /** Rule key → SonarQube language, from the profiles' active rules (never a file name). */
  const ruleLanguage = new Map<string, string>();
  await phase('profiles', async () => {
    const profiles = await fetchProfiles(conn.client);
    const distinct = {
      active: new Set<string>(),
      pendingReview: new Set<string>(),
      statusOnly: new Set<string>(),
      unmapped: new Set<string>(),
    };
    const p = summary.profiles;
    for (const profile of profiles) {
      mark(profile.key, 'profile key');
      mark(profile.name, 'profile name');
      for (const r of profile.active) {
        if (r.language !== '') ruleLanguage.set(r.key, r.language);
      }
      const planned = planProfile(profile);
      p.total += 1;
      bump(p.byLanguage, profile.language);
      if (planned.skip !== null) bump(p.skipped, planned.skip);
      p.activeRules += planned.stats.active;
      p.mapped += planned.stats.mapped;
      p.pendingReview += planned.stats.pendingReview.length;
      p.statusOnly += planned.stats.statusOnly.length;
      p.unmapped += planned.stats.unmapped.length;
      if (planned.skip === 'language_unsupported') continue;
      for (const r of profile.active) distinct.active.add(r.key);
      for (const k of planned.stats.pendingReview) distinct.pendingReview.add(k);
      for (const k of planned.stats.statusOnly) distinct.statusOnly.add(k);
      for (const u of planned.stats.unmapped) distinct.unmapped.add(u.key);
    }
    const notMapped = new Set([
      ...distinct.pendingReview,
      ...distinct.statusOnly,
      ...distinct.unmapped,
    ]);
    p.distinct = {
      active: distinct.active.size,
      mapped: [...distinct.active].filter((k) => !notMapped.has(k)).length,
      pendingReview: distinct.pendingReview.size,
      statusOnly: [...distinct.statusOnly].filter((k) => !distinct.pendingReview.has(k)).length,
      unmapped: [...distinct.unmapped].filter(
        (k) => !distinct.pendingReview.has(k) && !distinct.statusOnly.has(k),
      ).length,
    };
  });

  await phase('gates', async () => {
    const gates = await fetchGates(conn.client);
    for (const g of gates) {
      mark(g.name, 'gate name');
      const planned = planGate(g);
      summary.gates.total += 1;
      if (planned.skip !== null) bump(summary.gates.skipped, planned.skip);
      for (const c of planned.conditions) {
        const metric = /^[a-z0-9_]{1,64}$/.test(c.sonar.metric)
          ? c.sonar.metric
          : '<custom metric>';
        bump(
          summary.gates.conditions,
          `${metric}:${c.mapping.ok ? 'mapped' : `unmapped(${c.mapping.reason})`}`,
        );
      }
    }
  });

  let sampled: { key: string; name: string }[] = [];
  await phase('projects', async () => {
    const { projects } = await listProjects(conn.client, []);
    for (const p of projects) {
      mark(p.key, 'project key');
      mark(p.name, 'project name');
    }
    summary.projects.total = projects.length;
    sampled = projects.slice(0, o.maxProjects);
    summary.projects.sampled = sampled.length;
  });

  /** Per sampled project, its resolved issues (the line hash pool) and the resolved probe. */
  const read: { key: string; issues: SonarIssue[]; rules: string[] }[] = [];
  const markIssue = (i: SonarIssue) => {
    mark(i.key, 'issue key');
    mark(i.component, 'file or project key');
    mark(i.message, 'issue message');
    mark(i.hash, 'line hash');
    for (const c of i.comments ?? []) mark(c.markdown, 'issue comment');
    // The component key is `<project>:<path>`; the path alone must not appear either.
    const colon = i.component.lastIndexOf(':');
    if (colon >= 0) mark(i.component.slice(colon + 1), 'file path');
  };
  for (const project of sampled) {
    await phase('issues', async () => {
      const settings = await fetchProjectSettings(conn.client, project);
      if (!COMMON_BRANCHES.has(settings.mainBranch)) mark(settings.mainBranch, 'branch name');
      mark(settings.gate?.name, 'gate name');
      for (const p of settings.profiles) mark(p.profileKey, 'profile key');
      const r = await fetchResolvedIssues(conn.client, conn, project.key, o.maxIssues);
      const s = summary.issues;
      s.resolved += r.issues.length;
      s.notRead += r.notRead;
      for (const i of r.issues) {
        markIssue(i);
        bump(s.byStatus, i.issueStatus ?? `resolution:${i.resolution ?? 'none'}`);
        bump(s.byRepository, repositoryOf(i.rule));
        if (i.issueStatus !== undefined) s.withIssueStatus += 1;
      }
      const built = buildStatusItems(project.key, r.issues, { pathPrefix: null });
      for (const item of built.items) mark(item.path, 'file path');
      s.items.built += built.items.length;
      s.items.unmappedRule += [...built.unmappedRules.values()].reduce((a, b) => a + b, 0);
      s.items.pathInvalid += built.pathInvalid;
      s.items.invalid += built.invalid;
      s.items.ignored += built.ignored;
      s.items.withHash += built.items.filter((i) => i.sonarLineHash !== null).length;
      s.items.fileLess += built.items.filter((i) => i.path === null).length;
      read.push({ key: project.key, issues: r.issues, rules: Object.keys(r.probe.counts) });
    });
    // A phase of its own (finding L1): nothing of the hotspot count, not even a used-up budget,
    // can discard the issues the phase before recorded.
    await phase('hotspots', async () => {
      if (!read.some((r) => r.key === project.key)) return;
      const n = await countReviewedHotspots(conn.client, conn, project.key);
      const s = summary.issues;
      if (n === null) s.hotspotsNotCounted += 1;
      else s.reviewedHotspots = (s.reviewedHotspots ?? 0) + n;
    });
  }

  // The sticky facet (fix 9a): does a query's `rules` facet honour its own `rules=` filter?
  await phase('facet', async () => {
    const target = read.find((r) => r.rules.length >= 2);
    if (target === undefined) return;
    const rule = [...target.rules].sort()[0]!;
    const page = await conn.client.get(
      'api/issues/search',
      {
        projects: target.key,
        ...resolvedFilter(conn),
        rules: rule,
        ps: '1',
        p: '1',
        facets: 'rules',
      },
      issuesPageSchema,
      'issue page',
    );
    for (const i of page.issues) markIssue(i);
    const values = page.facets?.find((f) => f.property === 'rules')?.values;
    if (values === undefined) return;
    const honours =
      values.every((v) => v.val === rule) &&
      (values.find((v) => v.val === rule)?.count ?? 0) === page.paging.total;
    summary.facetHonoursFilter = honours ? 'yes' : 'no';
  });

  // Ruling S1: the line hash of real issues against the line SonarQube shows, counts only.
  await phase('lineHash', async () => {
    const lh = summary.lineHash;
    const quota = Math.ceil(o.maxHashes / Math.max(1, read.length));
    const sample: SonarIssue[] = [];
    for (const r of read) {
      if (sample.length >= o.maxHashes) break;
      const want = Math.min(quota, o.maxHashes - sample.length);
      const seen = new Set<string>();
      const picked: SonarIssue[] = [];
      const consider = (issues: readonly SonarIssue[]) => {
        for (const i of issues) {
          if (picked.length >= want) return;
          if (seen.has(i.key)) continue;
          seen.add(i.key);
          if (i.hash === undefined || !SONAR_LINE_HASH.test(i.hash) || lineOf(i) === null) {
            lh.skippedNoHash += 1;
            continue;
          }
          picked.push(i);
        }
      };
      consider(r.issues);
      if (picked.length < want) {
        const open = await conn.client.get(
          'api/issues/search',
          { projects: r.key, ...openFilter(conn), ps: '100', p: '1' },
          issuesPageSchema,
          'issue page',
        );
        for (const i of open.issues) markIssue(i);
        consider(open.issues);
      }
      sample.push(...picked);
    }
    lh.sampled = sample.length;
    const ep = guard.authed();
    if (ep === null) return;
    for (const i of sample) {
      const line = lineOf(i)!;
      const lang = ruleLanguage.get(i.rule) ?? 'unknown';
      const res = await guard.transport(ep, {
        method: 'GET',
        path: 'api/sources/lines',
        query: { key: i.component, from: String(line), to: String(line) },
        maxResponseBytes: 1024 * 1024,
      });
      let code: string | undefined;
      if (res.status === 200) {
        try {
          const parsed = sourceLinesSchema.safeParse(JSON.parse(res.body) as unknown);
          code = parsed.success
            ? parsed.data.sources.find((s) => s.line === line)?.code
            : undefined;
        } catch {
          code = undefined;
        }
      }
      if (code === undefined) {
        lh.unreadable += 1;
        continue;
      }
      const text = sonarSourceText(code);
      const hash = sonarLineHash(text);
      mark(code, 'line of code');
      mark(text, 'line of code');
      mark(text.trim(), 'line of code');
      mark(hash, 'line hash');
      if (hash === '') {
        lh.blankLines += 1;
        continue;
      }
      lh.compared += 1;
      const by = (lh.byLanguage[lang] ??= { match: 0, mismatch: 0 });
      if (hash === i.hash) {
        lh.match += 1;
        by.match += 1;
      } else {
        lh.mismatch += 1;
        by.mismatch += 1;
      }
    }
  });

  for (const w of conn.client.warnings) bump(summary.warnings, w.code);
  summary.warnings = sorted(summary.warnings);
  summary.profiles.byLanguage = sorted(summary.profiles.byLanguage);
  summary.profiles.skipped = sorted(summary.profiles.skipped);
  summary.gates.skipped = sorted(summary.gates.skipped);
  summary.gates.conditions = sorted(summary.gates.conditions);
  summary.issues.byStatus = sorted(summary.issues.byStatus);
  summary.issues.byRepository = sorted(summary.issues.byRepository);
  summary.lineHash.byLanguage = Object.fromEntries(
    Object.entries(summary.lineHash.byLanguage).sort((a, b) => (a[0] < b[0] ? -1 : 1)),
  );
  summary.requests = {
    used: guard.used(),
    budget: o.maxRequests,
    budgetExhausted: errors.some((e) => e.error instanceof LiveBudgetExhausted),
  };
  summary.endpoints = guard.endpoints();
  summary.failures = errors.map((e) => ({
    phase: e.phase,
    error: redact(e.error instanceof Error ? e.error.message : String(e.error), sensitive),
  }));

  const text = JSON.stringify(summary, null, 2);
  const leaked = leakedCategories(text, sensitive);
  if (leaked.length > 0) {
    throw new Error(
      `live check: the summary would hold a ${leaked.join(', a ')} of the organisation; nothing is printed`,
    );
  }
  return { summary, text };
}
