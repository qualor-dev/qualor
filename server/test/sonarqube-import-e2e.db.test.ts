import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { hex32, importReportSchema, type ImportReport } from '@qualor/shared';
import { sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  sampleSonarData,
  startFakeSonarQube,
  type FakeIssue,
  type FakeSonar,
} from '../../cli/test/fake-sonarqube';
import { createIngestHarness, type IngestHarness } from './ingest';
import { engine, file, finding, reportWith } from './reports';

/**
 * Plan 3A Task 15 (import-sonarqube.md §16): the real CLI (TypeScript sources, or `QUALOR_BIN`, as
 * a child process) imports from the fake SonarQube into a real server (Fastify on a local port,
 * Postgres through Testcontainers): profiles, gates, assignments and statuses land; a second run
 * and a dry run write nothing; SonarQube Cloud mode scopes by organisation; a competitor makes a
 * status ambiguous and a capped read leaves statuses unapplied; every request to SonarQube is a
 * `GET` of a read endpoint; and neither token (nor the basic credential) leaks anywhere.
 */
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const cliEntry = path.join(repoRoot, 'cli', 'src', 'cli.ts');
const tsxLoader = pathToFileURL(createRequire(import.meta.url).resolve('tsx')).href;
const qualorBin = process.env['QUALOR_BIN'];
const cliCommand: [string, string[]] =
  qualorBin !== undefined && qualorBin !== ''
    ? [path.resolve(repoRoot, qualorBin), []]
    : [process.execPath, ['--import', tsxLoader, cliEntry]];
const CI_VARIABLE = /^(CI|CI_.*|GITHUB_.*|GITLAB_.*|QUALOR_.*|SONAR_.*)$/i;
/** A CLI that runs longer than this is killed and the test fails: nothing here may hang. */
const CLI_KILL_MS = 90_000;

/** Spec §4.4, written out here so the test checks the spec's list, not the client's own. */
const READ_ENDPOINTS = new Set([
  'api/server/version',
  'api/users/current',
  'api/organizations/search',
  'api/qualityprofiles/search',
  'api/rules/search',
  'api/qualitygates/list',
  'api/qualitygates/show',
  'api/qualitygates/get_by_project',
  'api/components/search',
  'api/components/show',
  'api/project_branches/list',
  'api/issues/search',
  'api/hotspots/search',
]);
/** Spec §4.4: the endpoints marked **org**. */
const ORG_ENDPOINTS = new Set([
  'api/qualityprofiles/search',
  'api/rules/search',
  'api/qualitygates/list',
  'api/qualitygates/show',
  'api/qualitygates/get_by_project',
  'api/components/search',
  'api/issues/search',
]);

const EQEQEQ = "Expected '===' and instead saw '=='.";
const SNIPPET = {
  startLine: 1,
  lines: ['const a = 1;', 'if (a == 1) {}', 'if (a == 2) {}', 'export {};'],
};

let harness: IngestHarness;
let url: string;
let pat: string;
const work = mkdtempSync(path.join(os.tmpdir(), 'qualor-sonar-e2e-'));
const fakes: FakeSonar[] = [];
/** What Qualor received: every request's method, URL, headers and body. */
const received: string[] = [];
/** Every run's stdout and stderr. */
const outputs: string[] = [];
const reportFiles: string[] = [];

const baseEnv: Record<string, string> = Object.fromEntries(
  Object.entries(process.env).filter(
    (e): e is [string, string] => e[1] !== undefined && !CI_VARIABLE.test(e[0]),
  ),
);

interface Run {
  code: number | null;
  stdout: string;
  stderr: string;
  report: ImportReport;
}

/** `qualor import sonarqube <args> --output <work>/<name>.json`, from the SonarQube `fake`. */
function runImport(fake: FakeSonar, name: string, args: string[]): Promise<Run> {
  const output = path.join(work, `${name}.json`);
  reportFiles.push(output);
  return new Promise((resolve, reject) => {
    const child = spawn(
      cliCommand[0],
      [...cliCommand[1], 'import', 'sonarqube', '--url', fake.url, ...args, '--output', output],
      {
        cwd: work,
        env: {
          ...baseEnv,
          QUALOR_URL: url,
          QUALOR_TOKEN: pat,
          SONAR_TOKEN: fake.data.token,
          QUALOR_LOG_LEVEL: 'debug',
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );
    let stdout = '';
    let stderr = '';
    const killer = setTimeout(() => {
      stderr += `\n[killed after ${CLI_KILL_MS} ms]`;
      child.kill('SIGKILL');
    }, CLI_KILL_MS);
    child.stdout.on('data', (d: Buffer) => (stdout += d.toString('utf8')));
    child.stderr.on('data', (d: Buffer) => (stderr += d.toString('utf8')));
    child.on('close', (code) => {
      clearTimeout(killer);
      outputs.push(stdout, stderr);
      try {
        const report = importReportSchema.parse(JSON.parse(readFileSync(output, 'utf8')));
        resolve({ code, stdout, stderr, report });
      } catch (err) {
        reject(new Error(`no valid report (exit ${code}): ${stderr}`, { cause: err }));
      }
    });
  });
}

async function rows<T>(query: ReturnType<typeof sql>): Promise<T[]> {
  return (await harness.ctx.db.execute(query)).rows as T[];
}

/** The rows an import may write; a run that writes nothing leaves all of them as they were. */
async function counts(): Promise<Record<string, number>> {
  const out: Record<string, number> = {};
  for (const table of [
    'quality_profiles',
    'quality_gates',
    'gate_conditions',
    'profile_rules',
    'project_profiles',
    'projects',
    'issue_changes',
  ]) {
    const [row] = await rows<{ n: number }>(
      sql`SELECT count(*)::int AS n FROM ${sql.identifier(table)}`,
    );
    out[table] = row?.n ?? -1;
  }
  const statuses = await rows<{ status: string; n: number }>(
    sql`SELECT status, count(*)::int AS n FROM issues GROUP BY status ORDER BY status`,
  );
  for (const s of statuses) out[`issues.${s.status}`] = s.n;
  const updated = await rows<{ t: string | null }>(
    sql`SELECT max(updated_at)::text AS t FROM (
          SELECT updated_at FROM quality_profiles UNION ALL SELECT updated_at FROM quality_gates
          UNION ALL SELECT updated_at FROM projects UNION ALL SELECT updated_at FROM issues) u`,
  );
  out[`updated:${updated[0]?.t ?? ''}`] = 1;
  return out;
}

async function issueAt(projectKey: string, filePath: string, line: number) {
  const [row] = await rows<{ id: string; status: string }>(sql`
    SELECT i.id, i.status FROM issues i JOIN projects p ON p.id = i.project_id
     WHERE p.key = ${projectKey} AND i.path = ${filePath} AND i.start_line = ${line}
     ORDER BY i.message`);
  return row!;
}

const itemsOf = (r: Run, key: string) =>
  r.report.projects.find((p) => p.key === key)?.issues?.items ?? [];

beforeAll(async () => {
  harness = await createIngestHarness({
    beforeReady: (app) => {
      app.addHook('preHandler', async (req) => {
        received.push(
          JSON.stringify({ m: req.method, u: req.url, h: req.headers, b: req.body ?? null }),
        );
      });
    },
  });
  await harness.ctx.app.listen({ port: 0, host: '127.0.0.1' });
  url = `http://127.0.0.1:${(harness.ctx.app.server.address() as AddressInfo).port}`;
  const eslint = engine('eslint', [
    { id: 'eqeqeq', defaultSeverity: 'high', quality: 'maintainability' },
    {
      id: '@typescript-eslint/no-unused-vars',
      defaultSeverity: 'high',
      quality: 'maintainability',
    },
    { id: 'no-console', defaultSeverity: 'medium', quality: 'maintainability' },
  ]);

  const shop = await harness.project('acme:shop');
  await shop.ingestOk(
    reportWith({
      projectKey: 'acme:shop',
      engines: [eslint],
      files: [file('src/a.ts', { lines: 10 })],
      findings: [2, 3].map((line) =>
        finding({ ruleId: 'eqeqeq', line, message: EQEQEQ, snippet: SNIPPET }),
      ),
    }),
  );
  // `import { a, b } from './x';`: two issues of one rule on one line (the safety case).
  const safe = await harness.project('acme:safe');
  await safe.ingestOk(
    reportWith({
      projectKey: 'acme:safe',
      engines: [eslint],
      files: [file('src/s.ts', { lines: 5 })],
      findings: ['a', 'b'].map((name) =>
        finding({
          ruleId: '@typescript-eslint/no-unused-vars',
          path: 'src/s.ts',
          line: 1,
          message: `'${name}' is defined but never used.`,
          lineHash: hex32(`line:${name}`),
          contextHash: hex32(`context:${name}`),
        }),
      ),
    }),
  );
  const capped = await harness.project('acme:capped');
  await capped.ingestOk(
    reportWith({
      projectKey: 'acme:capped',
      engines: [eslint],
      files: [file('src/c.ts', { lines: 10 })],
      findings: [
        finding({
          ruleId: 'no-console',
          path: 'src/c.ts',
          line: 5,
          message: 'Unexpected console statement.',
        }),
      ],
    }),
  );

  const res = await harness.ctx.app.inject({
    method: 'POST',
    url: '/api/v0/tokens',
    headers: harness.orgAdmin.headers,
    payload: { name: 'import', scopes: ['read', 'write', 'admin'] },
  });
  expect(res.statusCode, res.body).toBe(201);
  pat = (res.json() as { token: string }).token;
}, 180_000);

afterAll(async () => {
  for (const fake of fakes) await fake.close();
  await harness?.close();
  rmSync(work, { recursive: true, force: true, maxRetries: 5 });
});

describe('qualor import sonarqube against a real server and the fake SonarQube', () => {
  let server: FakeSonar;
  let afterFirst: Record<string, number>;

  it('imports profiles, gates, projects and statuses', async () => {
    server = await startFakeSonarQube(
      sampleSonarData({
        projects: [
          ...sampleSonarData().projects,
          { key: 'acme:new', name: 'New', mainBranch: 'trunk' },
        ],
        issues: [
          ...sampleSonarData().issues,
          {
            key: 'AYi-new-1',
            rule: 'external_eslint_repo:no-console',
            project: 'acme:new',
            path: 'src/x.ts',
            line: 1,
            message: 'Unexpected console statement.',
            status: 'FALSE_POSITIVE',
          },
        ],
      }),
    );
    fakes.push(server);
    const r1 = await runImport(server, 'r1', ['--create-projects']);
    expect(r1.code, r1.stderr).toBe(0);
    expect(r1.report.aborted).toBeNull();

    const org = harness.organizationId;
    const profiles = await rows<{
      id: string;
      name: string;
      language: string;
      unknown_rules: string;
    }>(
      sql`SELECT id, name, language, unknown_rules FROM quality_profiles
           WHERE organization_id = ${org} AND NOT is_builtin ORDER BY name`,
    );
    // "Team Java" is created as before. "Team TS" and "Sonar way" (TypeScript) are also created
    // now (Phase 8): each leaves S3504 inactive, and S3504 is a real sonarjs 2.0.4 key (a
    // repository target, always reviewed), so each gets that one deactivation row even though
    // none of its *active* rules is mapped (S1440 is curated overlap only; S9999 is unmapped).
    // "Team Python" is a language Qualor does not analyse.
    expect(profiles.map((p) => [p.name, p.language, p.unknown_rules])).toEqual([
      ['Sonar way', 'typescript', 'activate'],
      ['Team Java', 'java', 'activate'],
      ['Team TS', 'typescript', 'activate'],
    ]);
    const javaProfile = profiles.find((p) => p.name === 'Team Java')!;
    const javaRows = await rows<{
      key: string;
      active: boolean;
      severity_override: string | null;
    }>(sql`
      SELECT r.key, pr.active, pr.severity_override FROM profile_rules pr
        JOIN rules r ON r.id = pr.rule_id WHERE pr.profile_id = ${javaProfile.id} ORDER BY r.key`);
    expect(javaRows).toEqual([
      { key: 'pmd:EmptyCatchBlock', active: false, severity_override: null },
      { key: 'pmd:SystemPrintln', active: true, severity_override: null },
    ]);
    const teamTsProfile = profiles.find((p) => p.name === 'Team TS')!;
    const teamTsRows = await rows<{ key: string; active: boolean }>(sql`
      SELECT r.key, pr.active FROM profile_rules pr
        JOIN rules r ON r.id = pr.rule_id WHERE pr.profile_id = ${teamTsProfile.id} ORDER BY r.key`);
    expect(teamTsRows).toEqual([{ key: 'sonarjs:S3504', active: false }]);

    const gates = await rows<{ id: string; name: string; conditions: string[] }>(sql`
      SELECT g.id, g.name,
             array_agg(c.metric_key || ' ' || c.operator || ' ' || c.threshold ORDER BY c.metric_key)
               AS conditions
        FROM quality_gates g JOIN gate_conditions c ON c.gate_id = g.id
       WHERE g.organization_id = ${org} AND NOT g.is_builtin GROUP BY g.id, g.name ORDER BY g.name`);
    expect(gates.map((g) => [g.name, g.conditions])).toEqual([
      ['Sonar way', ['new_coverage lt 80', 'new_duplicated_lines_density gt 3', 'new_issues gt 0']],
      ['Strict', ['issues gt 0']],
    ]);
    const strict = gates.find((g) => g.name === 'Strict')!;
    const projects = await rows<{ key: string; quality_gate_id: string | null; main: string }>(sql`
      SELECT key, quality_gate_id, main_branch_name AS main FROM projects
       WHERE key IN ('acme:shop', 'acme:new') ORDER BY key`);
    expect(projects).toEqual([
      { key: 'acme:new', quality_gate_id: null, main: 'trunk' },
      { key: 'acme:shop', quality_gate_id: strict.id, main: 'main' },
    ]);

    const fp = await issueAt('acme:shop', 'src/a.ts', 2);
    const accepted = await issueAt('acme:shop', 'src/a.ts', 3);
    expect([fp.status, accepted.status]).toEqual(['false_positive', 'wont_fix']);
    const changes = await rows<{ issue_id: string; new_value: string; comment: string }>(sql`
      SELECT issue_id, new_value, comment FROM issue_changes
       WHERE field = 'status' AND issue_id IN (${fp.id}, ${accepted.id}) ORDER BY new_value`);
    expect(changes).toHaveLength(2);
    expect(changes[0]!.new_value).toBe('false_positive');
    expect(changes[0]!.comment).toMatch(
      /^Imported from SonarQube issue AYi-fp-1 \(False positive on \d{4}-\d{2}-\d{2}\): safe here$/,
    );
    expect(changes[1]!.new_value).toBe('wont_fix');
    expect(changes[1]!.comment).toMatch(/^Imported from SonarQube issue AYi-ac-1 \(Accepted on /);

    const shop = r1.report.projects.find((p) => p.key === 'acme:shop')!;
    expect(shop.outcome).toBe('found');
    expect(shop.gate).toMatchObject({ outcome: 'assigned', gate: 'Strict' });
    expect(shop.issues).toMatchObject({ outcome: 'done', applied: 2, unmappedRule: 1 });
    expect(shop.issues?.unmappedRules).toEqual([{ key: 'typescript:S9999', issues: 1 }]);
    expect(itemsOf(r1, 'acme:shop').map((i) => [i.sonarKey, i.rule, i.outcome])).toEqual([
      ['AYi-fp-1', 'external_eslint_repo:eqeqeq', 'applied'],
      ['AYi-ac-1', 'typescript:S1440', 'applied'],
    ]);
    const created = r1.report.projects.find((p) => p.key === 'acme:new')!;
    expect(created.outcome).toBe('created');
    expect(created.issues?.outcome).toBe('not_analysed');
    // Phase 8: S3504 (left inactive) is now a real sonarjs key, so "Team TS" gets that one
    // deactivation row and is created, even though its active rules (S1440, S9999) are not mapped.
    expect(r1.report.profiles.find((p) => p.name === 'Team TS')).toMatchObject({
      outcome: 'created',
      reason: null,
    });
    afterFirst = await counts();
  }, 180_000);

  it('writes nothing when run again', async () => {
    const r2 = await runImport(server, 'r2', ['--create-projects']);
    expect(r2.code, r2.stderr).toBe(0);
    for (const p of r2.report.profiles) expect(['unchanged', 'skipped']).toContain(p.outcome);
    for (const g of r2.report.gates) expect(['unchanged', 'skipped']).toContain(g.outcome);
    for (const p of r2.report.projects) {
      expect(p.outcome).toBe('found');
      for (const a of [...p.profiles, ...(p.gate === null ? [] : [p.gate])]) {
        expect(['unchanged', 'skipped']).toContain(a.outcome);
      }
    }
    const shop = r2.report.projects.find((p) => p.key === 'acme:shop')!;
    expect(shop.gate?.outcome).toBe('unchanged');
    expect(shop.issues).toMatchObject({ alreadySet: 2, applied: 0, conflict: 0 });
    expect(await counts()).toEqual(afterFirst);
  }, 180_000);

  it('writes nothing in a dry run (basic authentication)', async () => {
    const extra: FakeIssue = {
      key: 'AYi-fp-2',
      rule: 'external_eslint_repo:eqeqeq',
      project: 'acme:shop',
      path: 'src/a.ts',
      line: 3,
      message: EQEQEQ,
      status: 'FALSE_POSITIVE',
    };
    server.data.issues.push(extra);
    server.data.gates.push({
      name: 'Extra',
      conditions: [{ metric: 'coverage', op: 'LT', error: '50' }],
    });
    const before = server.requests.length;
    const r3 = await runImport(server, 'r3', [
      '--create-projects',
      '--dry-run',
      '--sonar-auth',
      'basic',
    ]);
    expect(r3.code, r3.stderr).toBe(0);
    expect(r3.report.dryRun).toBe(true);
    expect(r3.report.gates.find((g) => g.name === 'Extra')?.outcome).toBe('would_create');
    // A `wont_fix` is already on that issue: a decision made in Qualor is never overwritten.
    expect(itemsOf(r3, 'acme:shop').find((i) => i.sonarKey === 'AYi-fp-2')?.outcome).toBe(
      'conflict',
    );
    expect(r3.report.projects.find((p) => p.key === 'acme:shop')?.issues?.applied).toBe(0);
    expect(await counts()).toEqual(afterFirst);
    expect(await rows(sql`SELECT id FROM quality_gates WHERE name = 'Extra'`)).toEqual([]);
    // The basic credential was really used (it is searched for below).
    const authed = server.requests.slice(before).filter((r) => r.path !== 'api/server/version');
    expect(authed.length).toBeGreaterThan(0);
    for (const r of authed) expect(r.authorization).toMatch(/^Basic /);
  }, 180_000);

  it('imports from SonarQube Cloud, scoped by organisation', async () => {
    const cloud = await startFakeSonarQube(
      sampleSonarData({ kind: 'cloud', organization: 'acme' }),
    );
    fakes.push(cloud);
    const r4 = await runImport(cloud, 'r4', [
      '--sonar-kind',
      'cloud',
      '--organization',
      'acme',
      '--dry-run',
    ]);
    expect(r4.code, r4.stderr).toBe(0);
    expect(r4.report.source).toMatchObject({
      edition: 'cloud',
      organization: 'acme',
      version: null,
    });
    expect(r4.report.gates.map((g) => [g.name, g.outcome])).toEqual([
      ['Sonar way', 'unchanged'],
      ['Strict', 'unchanged'],
    ]);
    expect(cloud.requests.some((r) => r.path === 'api/server/version')).toBe(false);
    const org = cloud.requests.filter((r) => ORG_ENDPOINTS.has(r.path));
    expect(org.length).toBeGreaterThan(0);
    for (const r of org) expect(r.query['organization'], r.path).toBe('acme');
    for (const r of cloud.requests) expect(r.authorization).toBe(`Bearer ${cloud.data.token}`);
    expect(await counts()).toEqual(afterFirst);
  }, 180_000);

  it('applies nothing where a competitor makes a status ambiguous or a capped read leaves competitors unknown', async () => {
    const issue = (over: Partial<FakeIssue> & Pick<FakeIssue, 'key' | 'project'>): FakeIssue => ({
      rule: 'typescript:S1481',
      path: 'src/s.ts',
      line: 1,
      message: 'Remove this unused import.',
      status: 'FALSE_POSITIVE',
      comments: ['not used yet'],
      ...over,
    });
    const safety = await startFakeSonarQube(
      sampleSonarData({
        projects: [
          { key: 'acme:safe', name: 'Safe' },
          { key: 'acme:capped', name: 'Capped' },
        ],
        issues: [
          // `import { a, b }`: one false positive and one open issue of that line's rule. Nothing
          // tells which Qualor issue is which.
          issue({ key: 'AYs-fp', project: 'acme:safe' }),
          issue({ key: 'AYs-open', project: 'acme:safe', status: 'OPEN', comments: [] }),
          // A false positive that pairs on its own, and two open issues of its rule, of which a
          // read capped at one leaves one unread.
          issue({
            key: 'AYc-fp',
            project: 'acme:capped',
            rule: 'external_eslint_repo:no-console',
            path: 'src/c.ts',
            line: 5,
            message: 'Unexpected console statement.',
          }),
          ...[1, 2].map((line) =>
            issue({
              key: `AYc-open-${line}`,
              project: 'acme:capped',
              rule: 'external_eslint_repo:no-console',
              path: 'src/other.ts',
              line,
              message: 'Unexpected console statement.',
              status: 'OPEN',
              comments: [],
            }),
          ),
        ],
      }),
    );
    fakes.push(safety);

    // Without the cap, the capped project's status would apply (a dry run shows it).
    const control = await runImport(safety, 'r5', ['--only', 'issues', '--dry-run']);
    expect(control.code, control.stderr).toBe(0);
    expect(itemsOf(control, 'acme:capped').map((i) => [i.sonarKey, i.outcome])).toEqual([
      ['AYc-fp', 'would_apply'],
    ]);
    expect(itemsOf(control, 'acme:safe').map((i) => [i.sonarKey, i.outcome])).toEqual([
      ['AYs-fp', 'ambiguous'],
    ]);

    const r6 = await runImport(safety, 'r6', ['--only', 'issues', '--max-issues', '1']);
    expect(r6.code, r6.stderr).toBe(0);
    expect(itemsOf(r6, 'acme:safe').map((i) => [i.sonarKey, i.outcome])).toEqual([
      ['AYs-fp', 'ambiguous'],
    ]);
    expect(itemsOf(r6, 'acme:capped').map((i) => [i.sonarKey, i.outcome])).toEqual([
      ['AYc-fp', 'competitors_unknown'],
    ]);
    expect(r6.report.projects.find((p) => p.key === 'acme:capped')?.issues).toMatchObject({
      competitorsUnknown: 1,
      applied: 0,
    });
    expect(r6.report.warnings.map((w) => w.code)).toContain('SONARQUBE_ISSUE_WINDOW');
    const untouched = await rows<{ key: string; status: string; changes: number }>(sql`
      SELECT p.key, i.status, (SELECT count(*)::int FROM issue_changes c WHERE c.issue_id = i.id)
             AS changes
        FROM issues i JOIN projects p ON p.id = i.project_id
       WHERE p.key IN ('acme:safe', 'acme:capped') ORDER BY p.key, i.message`);
    expect(untouched).toEqual([
      { key: 'acme:capped', status: 'open', changes: 0 },
      { key: 'acme:safe', status: 'open', changes: 0 },
      { key: 'acme:safe', status: 'open', changes: 0 },
    ]);
  }, 180_000);

  it('sent SonarQube only GETs of read endpoints, and leaked no secret', async () => {
    const all = fakes.flatMap((f) => f.requests);
    expect(all.length).toBeGreaterThan(0);
    for (const r of all) {
      expect(r.method, r.path).toBe('GET');
      expect(READ_ENDPOINTS.has(r.path), r.path).toBe(true);
    }

    const sonarToken = sampleSonarData().token;
    const basic = Buffer.from(`${sonarToken}:`).toString('base64');
    const secrets = [sonarToken, basic, basic.replace(/=+$/, ''), pat];
    // The fakes never received the Qualor token, in a header or a query.
    for (const r of all) {
      const seen = JSON.stringify([r.authorization ?? '', r.query]);
      expect(seen).not.toContain(pat);
    }
    // Qualor never received the SonarQube token or the basic credential.
    expect(received.length).toBeGreaterThan(0);
    for (const secret of [sonarToken, basic, basic.replace(/=+$/, '')]) {
      for (const r of received) expect(r).not.toContain(secret);
    }
    const texts: [string, string][] = [
      ...outputs.map((t, n): [string, string] => [`run output ${n}`, t]),
      ...reportFiles.map((f): [string, string] => [f, readFileSync(f, 'utf8')]),
      ['server log', harness.ctx.logs.join('\n')],
    ];
    // Every row Qualor stored, of every table.
    const tables = await rows<{ name: string }>(sql`
      SELECT table_name AS name FROM information_schema.tables
       WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'`);
    expect(tables.map((t) => t.name)).toEqual(
      expect.arrayContaining(['issue_changes', 'jobs', 'quality_profiles', 'quality_gates']),
    );
    for (const { name } of tables) {
      const dump = await rows<{ row: string }>(
        sql`SELECT t::text AS row FROM ${sql.identifier(name)} t`,
      );
      texts.push([`table ${name}`, dump.map((d) => d.row).join('\n')]);
    }
    for (const [where, text] of texts) {
      for (const secret of secrets) {
        expect(text.includes(secret), `a secret in ${where}`).toBe(false);
      }
    }
  }, 180_000);
});
