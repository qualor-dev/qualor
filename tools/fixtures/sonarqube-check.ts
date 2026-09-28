import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';
import {
  mappedConditions,
  matchStatuses,
  planGate,
  planProfile,
  reportSchema,
  snippetLineHash,
  statusMatchItem,
  type PlannedRow,
  type StatusCandidate,
} from '@qualor/shared';
import { buildWithCompetitors } from '../../cli/src/import/issues';
import { connectSonar } from '../../cli/src/import/sonarqube/client';
import {
  fetchGates,
  fetchProfiles,
  fetchResolvedIssues,
} from '../../cli/src/import/sonarqube/fetch';
import { silentLogger } from '../../cli/src/log';
import { startFakeSonarQube, type FakeSonarData } from '../../cli/test/fake-sonarqube';

/** What a fixture's `sonarqube-expected.json` says the import plans and matches. */
export interface SonarExpected {
  profiles: Record<
    string,
    {
      skip: string | null;
      rows: PlannedRow[];
      pendingReview: string[];
      statusOnly: string[];
      unmapped: string[];
    }
  >;
  gates: Record<
    string,
    {
      skip: string | null;
      mapped: { metric: string; operator: 'gt' | 'lt'; threshold: number }[];
      unmapped: string[];
    }
  >;
  /**
   * Per SonarQube issue key: the scan finding its status goes to, or why it goes nowhere
   * (`competitorsUnknown` and `changed` as in import-sonarqube.md §10.5 and §12.2).
   */
  statuses: Record<
    string,
    | { ruleKey: string; line: number | null }
    | 'unmatched'
    | 'ambiguous'
    | 'competitorsUnknown'
    | 'changed'
    | 'unmappedRule'
  >;
}

/** JSON with every object's keys sorted, so that key order never counts as a difference. */
function canonical(value: unknown): string {
  return JSON.stringify(value, (_key, v: unknown) =>
    v !== null && typeof v === 'object' && !Array.isArray(v)
      ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)))
      : v,
  );
}

/** Every difference between two plans, one line each, in a stable order. */
export function compareSonarImport(expected: SonarExpected, actual: SonarExpected): string[] {
  const out: string[] = [];
  const labels = { profiles: 'profile', gates: 'gate', statuses: 'status' } as const;
  for (const section of ['profiles', 'gates', 'statuses'] as const) {
    const e = expected[section] as Record<string, unknown>;
    const a = actual[section] as Record<string, unknown>;
    for (const key of [...new Set([...Object.keys(e), ...Object.keys(a)])].sort()) {
      if (canonical(e[key] ?? null) === canonical(a[key] ?? null)) continue;
      const show = (v: unknown) => (v === undefined ? 'nothing' : JSON.stringify(v));
      out.push(`${labels[section]} ${key}: expected ${show(e[key])}, got ${show(a[key])}`);
    }
  }
  return out;
}

/**
 * Plans the fixture's SonarQube data (`sonarqube/data.json`, served by the fake SonarQube and read
 * with the real client, `GET` only) and matches its statuses against the findings of the scan's
 * report, as the import endpoint would against the issues of that scan.
 */
export async function checkSonarImport(fixtureDir: string, reportFile: string): Promise<string[]> {
  const data = JSON.parse(
    readFileSync(path.join(fixtureDir, 'sonarqube', 'data.json'), 'utf8'),
  ) as FakeSonarData;
  const expected = JSON.parse(
    readFileSync(path.join(fixtureDir, 'sonarqube-expected.json'), 'utf8'),
  ) as SonarExpected;
  const report = reportSchema.parse(JSON.parse(gunzipSync(readFileSync(reportFile)).toString('utf8')));
  const fake = await startFakeSonarQube(data);
  try {
    const conn = await connectSonar({
      url: fake.url,
      token: data.token,
      kind: 'auto',
      organization: data.kind === 'cloud' ? (data.organization ?? null) : null,
      auth: 'auto',
      timeoutMs: 10_000,
      log: silentLogger,
    });
    const actual: SonarExpected = { profiles: {}, gates: {}, statuses: {} };
    for (const p of (await fetchProfiles(conn.client)).map((x) => planProfile(x))) {
      if (p.language === null) continue;
      actual.profiles[p.name] = {
        skip: p.skip,
        rows: p.rows,
        pendingReview: p.stats.pendingReview,
        statusOnly: p.stats.statusOnly,
        unmapped: p.stats.unmapped.map((u) => u.key),
      };
    }
    for (const g of (await fetchGates(conn.client)).map((x) => planGate(x))) {
      actual.gates[g.name] = {
        skip: g.skip,
        mapped: mappedConditions(g),
        unmapped: g.conditions.filter((c) => !c.mapping.ok).map((c) => c.sonar.metric),
      };
    }
    for (const project of data.projects) {
      const fetched = await fetchResolvedIssues(conn.client, conn, project.key, 100_000);
      const built = await buildWithCompetitors(conn.client, conn, project.key, fetched.issues, {
        pathPrefix: null,
        maxIssues: 100_000,
        unreadResolved: fetched.unread,
        probe: fetched.probe,
      });
      for (const i of fetched.issues) {
        if (built.unmappedRules.has(i.rule)) actual.statuses[i.key] = 'unmappedRule';
      }
      for (const i of built.changed) actual.statuses[i.ref] = 'changed';
      const candidates: StatusCandidate[] = report.findings.map((f, n) => ({
        id: String(n),
        ruleKey: `${f.engineId}:${f.ruleId}`,
        path: f.location?.path ?? null,
        line: f.location?.startLine ?? null,
        message: f.message,
        sonarLineHash: snippetLineHash(f.snippet ?? null, f.location?.startLine ?? null),
      }));
      const items = [...built.items, ...built.competitors];
      const marked = new Set(built.items.filter((i) => i.competitorsUnknown === true).map((i) => i.ref));
      const resolved = new Set(built.items.map((i) => i.ref));
      for (const m of matchStatuses(items.map(statusMatchItem), candidates)) {
        if (!resolved.has(m.ref)) continue;
        const c = m.candidateId === null ? undefined : candidates[Number(m.candidateId)];
        actual.statuses[m.ref] =
          m.competitorsUnknown || marked.has(m.ref)
            ? 'competitorsUnknown'
            : m.ambiguous
              ? 'ambiguous'
              : c === undefined
                ? 'unmatched'
                : { ruleKey: c.ruleKey, line: c.line };
      }
    }
    const writes = fake.requests.filter((r) => r.method !== 'GET');
    if (writes.length > 0) {
      return [`the SonarQube client sent ${writes.length} requests that are not a GET`];
    }
    return compareSonarImport(expected, actual);
  } finally {
    await fake.close();
  }
}

if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  const [fixtureDir, reportFile] = process.argv.slice(2);
  if (fixtureDir === undefined || reportFile === undefined) {
    console.log('usage: sonarqube-check.ts <fixture directory> <report.json.gz>');
    process.exit(2);
  }
  checkSonarImport(fixtureDir, reportFile).then(
    (problems) => {
      for (const p of problems) console.log(p);
      process.exit(problems.length === 0 ? 0 : 1);
    },
    (err: unknown) => {
      console.log(err instanceof Error ? err.message : String(err));
      process.exit(1);
    },
  );
}
