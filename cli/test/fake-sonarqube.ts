import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';

/**
 * A fake SonarQube Server or Cloud for the import's tests (ruling SQ16): it serves a data model
 * through the shapes of `packages/shared/test/sonarqube-shapes/`, written from SonarSource's
 * published Web API documentation, never from a live server. It records every request, answers
 * anything but `GET` with 405 (so a test can assert that none came), checks authentication like
 * the kind and version it plays, requires `organization` on the **org** endpoints in Cloud mode,
 * answers Cloud's hotspot search by `projectKey` only (Server's `project` is a 400 there, as the
 * live check found) and enforces the result window. Rule names are invented placeholders.
 */

type Legacy = 'BLOCKER' | 'CRITICAL' | 'MAJOR' | 'MINOR' | 'INFO';
interface Impact {
  softwareQuality: string;
  severity: 'BLOCKER' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
}

export interface FakeRule {
  key: string;
  name: string;
  lang: string;
  severity: Legacy;
  impacts?: Impact[];
  params?: { key: string; defaultValue: string }[];
}
export interface FakeActivation {
  /** The profile the activation names, when not the profile asked (to test a wrong answer). */
  qProfile?: string;
  severity?: Legacy;
  impacts?: Impact[];
  params?: { key: string; value: string }[];
}
export interface FakeProfile {
  key: string;
  name: string;
  language: string;
  isDefault?: boolean;
  isBuiltIn?: boolean;
  active: Record<string, FakeActivation>;
}
export interface FakeGate {
  name: string;
  isDefault?: boolean;
  isBuiltIn?: boolean;
  conditions: { metric: string; op: string; error: string }[];
}
export interface FakeProject {
  key: string;
  name: string;
  mainBranch?: string;
  /** SonarQube language → profile key, when not the default. */
  profiles?: Record<string, string>;
  /** Gate name, when not the default. */
  gate?: string;
}
/**
 * `FIXED`: closed by SonarQube's analysis (no longer in the code). `RESOLVED_FIXED`: resolved as
 * fixed by a person (status `RESOLVED`, resolution `FIXED`), still in the code until the next
 * analysis. `IN_SANDBOX`: SonarQube Server 2025.5's sandboxed issue (no resolution).
 */
export type FakeIssueStatus =
  | 'FALSE_POSITIVE'
  | 'ACCEPTED'
  | 'WONTFIX'
  | 'OPEN'
  | 'CONFIRMED'
  | 'FIXED'
  | 'RESOLVED_FIXED'
  | 'IN_SANDBOX';
export interface FakeIssue {
  key: string;
  rule: string;
  project: string;
  path: string | null;
  line?: number;
  hash?: string;
  message: string;
  status: FakeIssueStatus;
  comments?: string[];
  updateDate?: string;
}
export interface FakeSonarData {
  kind: 'server' | 'cloud';
  /** Server only; Cloud answers `api/server/version` with 404, so a stray call fails a test. */
  version: string;
  organization?: string;
  token: string;
  login?: string;
  rules: FakeRule[];
  profiles: FakeProfile[];
  gates: FakeGate[];
  projects: FakeProject[];
  issues: FakeIssue[];
  hotspotsReviewed?: Record<string, number>;
  /**
   * `api/sources/lines`, which only the live check reads (never the import, spec §17.1): a file's
   * component key → its lines as SonarQube shows them (HTML: token spans, escaped characters).
   */
  sources?: Record<string, string[]>;
}
export interface FakeSonarRequest {
  method: string;
  path: string;
  query: Record<string, string>;
  authorization: string | undefined;
}
interface Fault {
  status: number;
  body?: string;
  headers?: Record<string, string>;
}
export interface FakeSonar {
  url: string;
  requests: FakeSonarRequest[];
  data: FakeSonarData;
  /** Answer a request differently (a fault, a redirect, garbage); null to serve normally. */
  fault: ((r: FakeSonarRequest) => Fault | null) | null;
  close(): Promise<void>;
}

/** The endpoints SonarQube Cloud scopes by `organization` (spec §4.4). */
const ORG_ENDPOINTS = new Set([
  'api/qualityprofiles/search',
  'api/rules/search',
  'api/qualitygates/list',
  'api/qualitygates/show',
  'api/qualitygates/get_by_project',
  'api/components/search',
  'api/issues/search',
]);

/** What `api/issues/search` says of a fake issue, and filters it by. */
function statusFields(status: FakeIssueStatus): {
  status: string;
  resolution?: string;
  issueStatus: string;
} {
  switch (status) {
    case 'FALSE_POSITIVE':
      return { status: 'RESOLVED', resolution: 'FALSE-POSITIVE', issueStatus: 'FALSE_POSITIVE' };
    case 'ACCEPTED':
    case 'WONTFIX':
      return { status: 'RESOLVED', resolution: 'WONTFIX', issueStatus: 'ACCEPTED' };
    case 'FIXED':
      return { status: 'CLOSED', resolution: 'FIXED', issueStatus: 'FIXED' };
    case 'RESOLVED_FIXED':
      return { status: 'RESOLVED', resolution: 'FIXED', issueStatus: 'FIXED' };
    case 'IN_SANDBOX':
      return { status: 'IN_SANDBOX', issueStatus: 'IN_SANDBOX' };
    default:
      return { status, issueStatus: status };
  }
}

/** The documented values of `api/issues/search`'s status filters (I-2: the fake refuses others). */
const ISSUE_STATUSES = new Set(['OPEN', 'CONFIRMED', 'FALSE_POSITIVE', 'ACCEPTED', 'FIXED']);
const LEGACY_STATUSES = new Set(['OPEN', 'CONFIRMED', 'REOPENED', 'RESOLVED', 'CLOSED']);
const RESOLUTIONS = new Set(['FALSE-POSITIVE', 'WONTFIX', 'FIXED', 'REMOVED']);

/** `echoCredentials`: what an error answer to this response echoes. */
const echoes = new WeakMap<ServerResponse, string>();

function send(res: ServerResponse, status: number, body: unknown, type = 'application/json'): void {
  const echo = status >= 400 ? echoes.get(res) : undefined;
  const text =
    echo !== undefined
      ? JSON.stringify({ errors: [{ msg: `request refused: ${echo}` }], original: body })
      : typeof body === 'string'
        ? body
        : JSON.stringify(body);
  if (echo !== undefined) type = 'application/json';
  res.writeHead(status, {
    'content-type': type,
    'content-length': String(Buffer.byteLength(text)),
  });
  res.end(text);
}
const errors = (msg: string) => ({ errors: [{ msg }] });
const cmp = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/** One page, or null past the window (`p × ps > window`), as SonarQube refuses it with 400. */
function page<T>(all: readonly T[], q: Record<string, string>, window: number) {
  const ps = Math.min(Number(q['ps'] ?? '100'), 500);
  const p = Number(q['p'] ?? '1');
  if (!Number.isInteger(ps) || !Number.isInteger(p) || ps < 1 || p < 1) return null;
  if (p * ps > window) return null;
  return {
    items: all.slice((p - 1) * ps, p * ps),
    paging: { pageIndex: p, pageSize: ps, total: all.length },
  };
}

export interface FakeSonarOptions {
  window?: number;
  facetCap?: number;
  /**
   * SonarQube's facets are "sticky": the `rules` facet ignores the query's own `rules=` filter
   * (every other filter still applies), so it lists rules the query did not ask for.
   */
  stickyFacets?: boolean;
  /**
   * Every error answer (4xx and 5xx) echoes the request's `Authorization` header and query in its
   * message, as a careless proxy or server might: the client must never repeat an answer's body.
   */
  echoCredentials?: boolean;
}

export async function startFakeSonarQube(
  data: FakeSonarData,
  o: FakeSonarOptions = {},
): Promise<FakeSonar> {
  const window = o.window ?? 10_000;
  const facetCap = o.facetCap ?? 100;
  const [major = 0, minor = 0] = data.version.split('.').map(Number);
  const modern = data.kind === 'cloud' || major > 10 || (major === 10 && minor >= 4);
  /** SonarQube Server 2025.5 added the sandbox (`IN_SANDBOX`); Community Builds are 24–99. */
  const sandbox = data.kind === 'server' && (major > 2025 || (major === 2025 && minor >= 5));
  const requests: FakeSonarRequest[] = [];
  const fake: FakeSonar = { url: '', requests, data, fault: null, close: async () => {} };

  const authorised = (auth: string | undefined): boolean => {
    const bearer = auth === `Bearer ${data.token}`;
    const basic = auth === `Basic ${Buffer.from(`${data.token}:`).toString('base64')}`;
    if (data.kind === 'cloud') return bearer;
    return major >= 10 ? bearer || basic : basic;
  };
  const profileOf = (key: string) => data.profiles.find((p) => p.key === key);
  const defaultProfile = (lang: string) =>
    data.profiles.find((p) => p.language === lang && p.isDefault === true);
  const tooFar = () => errors(`Can return only the first ${window} results.`);

  const issueJson = (i: FakeIssue) => {
    const f = statusFields(i.status);
    return {
      key: i.key,
      rule: i.rule,
      severity: 'MAJOR',
      component: i.path === null ? i.project : `${i.project}:${i.path}`,
      project: i.project,
      ...(i.line !== undefined && {
        line: i.line,
        textRange: { startLine: i.line, endLine: i.line, startOffset: 0, endOffset: 1 },
      }),
      ...(i.hash !== undefined && { hash: i.hash }),
      status: f.status,
      ...(f.resolution !== undefined && { resolution: f.resolution }),
      ...(modern && { issueStatus: f.issueStatus }),
      message: i.message,
      comments: (i.comments ?? []).map((markdown, n) => ({
        key: `c${n}`,
        login: 'someone',
        htmlText: markdown,
        markdown,
        updatable: false,
        createdAt: '2026-09-10T10:00:00+0000',
      })),
      creationDate: '2026-09-01T10:00:00+0000',
      updateDate: i.updateDate ?? '2026-09-10T10:00:00+0000',
      type: 'CODE_SMELL',
    };
  };

  /**
   * The status filters of an `api/issues/search` query, each one a condition (all must hold), or
   * a refusal: a value SonarQube does not document for the version played is a 400 (I-2), and so
   * is `issueStatuses` before 10.4 (where a real server would ignore it and answer everything).
   */
  const statusFilter = (q: Record<string, string>): ((i: FakeIssue) => boolean) | string => {
    const list = (k: string) => (q[k] === undefined ? null : q[k].split(','));
    const issueStatuses = list('issueStatuses');
    const statuses = list('statuses');
    const resolutions = list('resolutions');
    const resolved = q['resolved'];
    if (issueStatuses !== null) {
      if (!modern) return 'issueStatuses';
      const known = (s: string) => ISSUE_STATUSES.has(s) || (sandbox && s === 'IN_SANDBOX');
      if (!issueStatuses.every(known)) return 'issueStatuses';
    }
    if (statuses !== null && !statuses.every((s) => LEGACY_STATUSES.has(s))) return 'statuses';
    if (resolutions !== null && !resolutions.every((r) => RESOLUTIONS.has(r))) return 'resolutions';
    if (resolved !== undefined && resolved !== 'true' && resolved !== 'false') return 'resolved';
    return (i) => {
      const f = statusFields(i.status);
      return (
        (issueStatuses === null || issueStatuses.includes(f.issueStatus)) &&
        (statuses === null || statuses.includes(f.status)) &&
        (resolutions === null ||
          (f.resolution !== undefined && resolutions.includes(f.resolution))) &&
        (resolved === undefined || (f.resolution !== undefined) === (resolved === 'true'))
      );
    };
  };

  const handle = (path: string, q: Record<string, string>, res: ServerResponse): void => {
    switch (path) {
      case 'api/server/version':
        if (data.kind === 'cloud') return send(res, 404, errors('Unknown url'));
        return send(res, 200, data.version, 'text/plain');
      case 'api/users/current':
        return send(res, 200, { isLoggedIn: true, login: data.login ?? 'importer', groups: [] });
      case 'api/organizations/search': {
        if (data.kind !== 'cloud') return send(res, 404, errors('Unknown url'));
        const keys = (q['organizations'] ?? '').split(',');
        const orgs =
          data.organization !== undefined && keys.includes(data.organization)
            ? [{ key: data.organization, name: 'Org' }]
            : [];
        return send(res, 200, {
          paging: { pageIndex: 1, pageSize: 100, total: orgs.length },
          organizations: orgs,
        });
      }
      case 'api/qualityprofiles/search': {
        const key = q['project'];
        const project = key === undefined ? undefined : data.projects.find((p) => p.key === key);
        if (key !== undefined && project === undefined) {
          return send(res, 404, errors('Project not found'));
        }
        const list =
          project === undefined
            ? data.profiles
            : [...new Set(data.profiles.map((p) => p.language))].flatMap((lang) => {
                const assigned = project.profiles?.[lang];
                const chosen = assigned !== undefined ? profileOf(assigned) : defaultProfile(lang);
                return chosen === undefined ? [] : [chosen];
              });
        return send(res, 200, {
          profiles: list.map((p) => ({
            key: p.key,
            name: p.name,
            language: p.language,
            languageName: p.language,
            isInherited: false,
            isDefault: p.isDefault ?? false,
            isBuiltIn: p.isBuiltIn ?? false,
            activeRuleCount: Object.keys(p.active).length,
          })),
        });
      }
      case 'api/rules/search': {
        const profile = profileOf(q['qprofile'] ?? '');
        if (profile === undefined) return send(res, 400, errors('qprofile is required'));
        const active = q['activation'] === 'true';
        const langs = (q['languages'] ?? profile.language).split(',');
        const rules = data.rules.filter((r) =>
          active ? r.key in profile.active : langs.includes(r.lang) && !(r.key in profile.active),
        );
        const pg = page(rules, q, window);
        if (pg === null) return send(res, 400, tooFar());
        return send(res, 200, {
          total: pg.paging.total,
          p: pg.paging.pageIndex,
          ps: pg.paging.pageSize,
          // 9.9's rules endpoint carries only the top-level total (spec §17).
          ...(major !== 9 && { paging: pg.paging }),
          rules: pg.items.map((r) =>
            active
              ? {
                  key: r.key,
                  repo: r.key.split(':')[0],
                  name: r.name,
                  lang: r.lang,
                  severity: r.severity,
                  ...(r.impacts !== undefined && { impacts: r.impacts }),
                  params: (r.params ?? []).map((x) => ({
                    key: x.key,
                    htmlDesc: '',
                    defaultValue: x.defaultValue,
                    type: 'STRING',
                  })),
                }
              : { key: r.key, lang: r.lang },
          ),
          ...(active && {
            actives: Object.fromEntries(
              pg.items.map((r) => {
                const a = profile.active[r.key] ?? {};
                return [
                  r.key,
                  [
                    {
                      qProfile: a.qProfile ?? profile.key,
                      inherit: 'NONE',
                      severity: a.severity ?? r.severity,
                      ...(a.impacts !== undefined && { impacts: a.impacts }),
                      params: a.params ?? [],
                    },
                  ],
                ];
              }),
            ),
          }),
        });
      }
      case 'api/qualitygates/list':
        return send(res, 200, {
          qualitygates: data.gates.map((g) => ({
            name: g.name,
            isDefault: g.isDefault ?? false,
            isBuiltIn: g.isBuiltIn ?? false,
          })),
        });
      case 'api/qualitygates/show': {
        const gate = data.gates.find((g) => g.name === q['name']);
        if (gate === undefined) return send(res, 404, errors('No quality gate has been found'));
        return send(res, 200, {
          name: gate.name,
          isBuiltIn: gate.isBuiltIn ?? false,
          conditions: gate.conditions.map((c, n) => ({ id: `g${n}`, ...c })),
        });
      }
      case 'api/qualitygates/get_by_project': {
        const project = data.projects.find((p) => p.key === q['project']);
        if (project === undefined) return send(res, 404, errors('Project not found'));
        const name = project.gate ?? data.gates.find((g) => g.isDefault === true)?.name ?? '';
        return send(res, 200, { qualityGate: { name, default: project.gate === undefined } });
      }
      case 'api/components/search': {
        const pg = page(data.projects, q, window);
        if (pg === null) return send(res, 400, tooFar());
        return send(res, 200, {
          paging: pg.paging,
          components: pg.items.map((p) => ({
            key: p.key,
            name: p.name,
            qualifier: 'TRK',
            project: p.key,
          })),
        });
      }
      case 'api/components/show': {
        const project = data.projects.find((p) => p.key === q['component']);
        if (project === undefined) return send(res, 404, errors('Component not found'));
        return send(res, 200, {
          component: { key: project.key, name: project.name, qualifier: 'TRK' },
          ancestors: [],
        });
      }
      case 'api/project_branches/list': {
        const project = data.projects.find((p) => p.key === q['project']);
        if (project === undefined) return send(res, 404, errors('Project not found'));
        return send(res, 200, {
          branches: [{ name: project.mainBranch ?? 'main', isMain: true, type: 'BRANCH' }],
        });
      }
      case 'api/issues/search': {
        const projects = (q['projects'] ?? '').split(',');
        const wanted = statusFilter(q);
        if (typeof wanted === 'string') {
          return send(res, 400, errors(`Value of parameter '${wanted}' is not valid`));
        }
        const rules = q['rules'] === undefined ? undefined : new Set(q['rules'].split(','));
        const unfiltered = data.issues.filter((i) => projects.includes(i.project) && wanted(i));
        const matching = unfiltered
          .filter((i) => rules === undefined || rules.has(i.rule))
          .sort(
            (a, b) =>
              cmp(a.path ?? '', b.path ?? '') || (a.line ?? 0) - (b.line ?? 0) || cmp(a.key, b.key),
          );
        const pg = page(matching, q, window);
        if (pg === null) return send(res, 400, tooFar());
        const counts = new Map<string, number>();
        for (const i of o.stickyFacets === true ? unfiltered : matching) {
          counts.set(i.rule, (counts.get(i.rule) ?? 0) + 1);
        }
        const facets =
          q['facets'] === 'rules'
            ? [
                {
                  property: 'rules',
                  values: [...counts]
                    .sort((a, b) => b[1] - a[1] || cmp(a[0], b[0]))
                    .slice(0, facetCap)
                    .map(([val, count]) => ({ val, count })),
                },
              ]
            : [];
        return send(res, 200, {
          total: pg.paging.total,
          p: pg.paging.pageIndex,
          ps: pg.paging.pageSize,
          paging: pg.paging,
          issues: pg.items.map(issueJson),
          components: [],
          facets,
        });
      }
      case 'api/hotspots/search': {
        // Finding L1: SonarQube Cloud names the project `projectKey` and answers Server's
        // `project` with 400, as the live check saw; Server takes `project`.
        const param = data.kind === 'cloud' ? 'projectKey' : 'project';
        if (data.kind === 'cloud' && q['project'] !== undefined) {
          return send(res, 400, errors("The 'project' parameter is not supported"));
        }
        const key = q[param];
        if (key === undefined) return send(res, 400, errors(`The '${param}' parameter is missing`));
        const total = data.hotspotsReviewed?.[key] ?? 0;
        return send(res, 200, {
          paging: { pageIndex: 1, pageSize: 1, total },
          hotspots: [],
          components: [],
        });
      }
      case 'api/sources/lines': {
        const lines = data.sources?.[q['key'] ?? ''];
        if (lines === undefined) return send(res, 404, errors('Component not found'));
        const from = Math.max(1, Number(q['from'] ?? '1'));
        const to = Math.min(lines.length, Number(q['to'] ?? String(lines.length)));
        const sources = [];
        for (let line = from; line <= to; line += 1) {
          sources.push({
            line,
            code: lines[line - 1] ?? '',
            scmRevision: '0000000000000000000000000000000000000000',
            scmAuthor: 'someone',
            scmDate: '2026-09-01T10:00:00+0000',
            duplicated: false,
            isNew: false,
          });
        }
        return send(res, 200, { sources });
      }
      default:
        return send(res, 404, errors('Unknown url'));
    }
  };

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? '/', 'http://fake');
    const path = url.pathname.replace(/^\//, '');
    const query = Object.fromEntries(url.searchParams);
    const recorded: FakeSonarRequest = {
      method: req.method ?? '',
      path,
      query,
      authorization: req.headers.authorization,
    };
    requests.push(recorded);
    if (o.echoCredentials === true) {
      echoes.set(res, `authorization=${req.headers.authorization ?? ''} url=${req.url ?? ''}`);
    }
    req.resume();
    req.on('end', () => {
      const f = fake.fault?.(recorded) ?? null;
      if (f !== null) {
        const echo = f.status >= 400 && f.body === undefined ? echoes.get(res) : undefined;
        res.writeHead(f.status, { 'content-type': 'application/json', ...f.headers });
        res.end(echo === undefined ? (f.body ?? '') : JSON.stringify(errors(`refused: ${echo}`)));
        return;
      }
      if (req.method !== 'GET') return send(res, 405, errors('Method not allowed'));
      if (path !== 'api/server/version' && !authorised(req.headers.authorization)) {
        return send(res, 401, errors('Authentication required'));
      }
      if (
        data.kind === 'cloud' &&
        ORG_ENDPOINTS.has(path) &&
        query['organization'] !== data.organization
      ) {
        return send(
          res,
          query['organization'] === undefined ? 400 : 404,
          errors('The organization parameter is missing or unknown'),
        );
      }
      handle(path, query, res);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  fake.url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  fake.close = () =>
    new Promise<void>((resolve) => {
      server.closeAllConnections();
      server.close(() => resolve());
    });
  return fake;
}

/** A small consistent data set for unit tests; tests change copies of it. Names are invented. */
export function sampleSonarData(over: Partial<FakeSonarData> = {}): FakeSonarData {
  return {
    kind: 'server',
    version: '10.7.0.96327',
    token: 'squ_fake0000000000000000000000000000000000',
    rules: [
      { key: 'typescript:S1440', name: 'Rule S1440', lang: 'ts', severity: 'MAJOR' },
      { key: 'typescript:S3504', name: 'Rule S3504', lang: 'ts', severity: 'MAJOR' },
      { key: 'typescript:S3776', name: 'Rule S3776', lang: 'ts', severity: 'CRITICAL' },
      { key: 'java:S1481', name: 'Rule S1481', lang: 'java', severity: 'MINOR' },
      { key: 'pmd:SystemPrintln', name: 'Rule SystemPrintln', lang: 'java', severity: 'MAJOR' },
      { key: 'pmd:EmptyCatchBlock', name: 'Rule EmptyCatchBlock', lang: 'java', severity: 'MAJOR' },
    ],
    profiles: [
      {
        key: 'p-ts',
        name: 'Team TS',
        language: 'ts',
        active: { 'typescript:S1440': { severity: 'CRITICAL' }, 'typescript:S3776': {} },
      },
      {
        key: 'p-ts-default',
        name: 'Sonar way',
        language: 'ts',
        isDefault: true,
        isBuiltIn: true,
        active: { 'typescript:S1440': {} },
      },
      {
        key: 'p-java',
        name: 'Team Java',
        language: 'java',
        isDefault: true,
        active: { 'pmd:SystemPrintln': {}, 'java:S1481': {} },
      },
      { key: 'p-py', name: 'Team Python', language: 'py', active: {} },
    ],
    gates: [
      {
        name: 'Sonar way',
        isDefault: true,
        isBuiltIn: true,
        conditions: [
          { metric: 'new_violations', op: 'GT', error: '0' },
          { metric: 'new_coverage', op: 'LT', error: '80' },
          { metric: 'new_duplicated_lines_density', op: 'GT', error: '3' },
          { metric: 'new_security_hotspots_reviewed', op: 'LT', error: '100' },
        ],
      },
      { name: 'Strict', conditions: [{ metric: 'violations', op: 'GT', error: '0' }] },
    ],
    projects: [{ key: 'acme:shop', name: 'Shop', profiles: { ts: 'p-ts' }, gate: 'Strict' }],
    issues: [
      {
        key: 'AYi-fp-1',
        rule: 'external_eslint_repo:eqeqeq',
        project: 'acme:shop',
        path: 'src/a.ts',
        line: 2,
        message: "Expected '===' and instead saw '=='.",
        status: 'FALSE_POSITIVE',
        comments: ['safe here'],
      },
      {
        key: 'AYi-ac-1',
        rule: 'typescript:S1440',
        project: 'acme:shop',
        path: 'src/a.ts',
        line: 3,
        message: 'Use strict equality.',
        status: 'ACCEPTED',
      },
      {
        key: 'AYi-um-1',
        rule: 'typescript:S3776',
        project: 'acme:shop',
        path: 'src/a.ts',
        line: 9,
        message: 'Too complex.',
        status: 'FALSE_POSITIVE',
      },
      {
        key: 'AYi-open',
        rule: 'typescript:S1440',
        project: 'acme:shop',
        path: 'src/a.ts',
        line: 4,
        message: 'Open.',
        status: 'OPEN',
      },
    ],
    hotspotsReviewed: { 'acme:shop': 2 },
    ...over,
  };
}
