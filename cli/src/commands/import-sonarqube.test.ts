import { existsSync, mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { importReportSchema, type StatusImportRequestItem } from '@qualor/shared';
import { afterEach, describe, expect, it } from 'vitest';
import {
  sampleSonarData,
  startFakeSonarQube,
  type FakeIssue,
  type FakeSonar,
  type FakeSonarOptions,
} from '../../test/fake-sonarqube';
import { MemoryQualor, ORG_ID } from '../../test/memory-qualor';
import type { ImportFlags } from '../args';
import { EXIT } from '../errors';
import { createLogger } from '../log';
import { runImportSonarqube } from './import-sonarqube';

const QUALOR_TOKEN = 'qlr_pat_memory0123456789';
let fake: FakeSonar | undefined;
afterEach(async () => {
  if (fake !== undefined) expect(fake.requests.every((r) => r.method === 'GET')).toBe(true);
  await fake?.close();
  fake = undefined;
});

const baseFlags = (url: string): ImportFlags => ({
  url,
  sonarKind: 'auto',
  projects: [],
  only: ['profiles', 'gates', 'projects', 'issues'],
  createProjects: false,
  setDefaults: false,
  overwrite: false,
  dryRun: false,
  sonarAuth: 'auto',
  timeoutSeconds: 5,
  maxIssues: 1000,
  allowInsecureHttp: false,
  output: 'report.json',
});

/** One run; a thrown error (a fatal failure) is returned with whatever report it left. */
async function attempt(
  over: Partial<ImportFlags> = {},
  q = new MemoryQualor(),
  env: Record<string, string> = {},
  dir = mkdtempSync(path.join(os.tmpdir(), 'qualor-import-')),
) {
  const lines: string[] = [];
  const out: string[] = [];
  let code: number | null = null;
  let error: unknown = null;
  try {
    code = await runImportSonarqube(
      { ...baseFlags(fake!.url), ...over },
      {
        cwd: dir,
        env: { SONAR_TOKEN: fake!.data.token, QUALOR_URL: 'https://q.test', QUALOR_TOKEN, ...env },
        stdout: (t) => out.push(t),
        stderr: (t) => lines.push(t),
      },
      createLogger('debug', (t) => lines.push(t)),
      { qualor: q, sleep: () => Promise.resolve() },
    );
  } catch (err) {
    error = err;
  }
  const file = path.join(dir, 'report.json');
  const reportText =
    existsSync(file) && statSync(file).isFile() ? readFileSync(file, 'utf8') : null;
  return {
    code,
    error,
    log: lines.join(''),
    stdout: out.join(''),
    reportText,
    report: reportText === null ? null : importReportSchema.parse(JSON.parse(reportText)),
    q,
  };
}

async function run(
  over: Partial<ImportFlags> = {},
  q = new MemoryQualor(),
  env: Record<string, string> = {},
) {
  const r = await attempt(over, q, env);
  if (r.error !== null) throw r.error;
  if (r.code === null || r.reportText === null || r.report === null) throw new Error('no report');
  return { ...r, code: r.code, reportText: r.reportText, report: r.report };
}

const resolvedOnly = (items: readonly StatusImportRequestItem[]) =>
  items.filter((i) => i.status !== 'open');

/** A Qualor with the project `acme:shop`, whose issues on `src/a.ts` take every status. */
const withProject = () => {
  const q = new MemoryQualor();
  q.projectsList.push({
    id: '00000000-0000-7000-8000-0000000000aa',
    key: 'acme:shop',
    name: 'Shop',
    qualityGateId: null,
    organizationId: ORG_ID,
    profiles: new Map(),
  });
  q.statusHandler = (_p, items, dryRun) => ({
    kind: 'ok',
    results: resolvedOnly(items).map((i) => ({
      ref: i.ref,
      outcome: i.path === 'src/a.ts' ? (dryRun ? 'would_apply' : 'applied') : 'unmatched',
      issueId: null,
      status: null,
    })),
    competitors: items.length - resolvedOnly(items).length,
  });
  return q;
};

const start = async (data = sampleSonarData(), o: FakeSonarOptions = {}) => {
  fake = await startFakeSonarQube(data, o);
  return fake;
};

describe('qualor import sonarqube (import-sonarqube.md §3, §12)', () => {
  it('imports profiles, gates, assignments and statuses, and exits 0', async () => {
    await start();
    const { code, report, q } = await run({}, withProject());
    expect(code).toBe(EXIT.OK);
    expect(report.profiles.find((p) => p.name === 'Team Java')).toMatchObject({
      outcome: 'created',
      defaultChange: null,
    });
    expect(report.profiles.find((p) => p.name === 'Team TS')).toMatchObject({
      outcome: 'skipped',
      reason: 'no_mapped_rules',
      // S1440 overlaps eslint:eqeqeq: it drives statuses only, never a profile (fix 4a).
      rules: { pendingReview: [], statusOnly: ['typescript:S1440'] },
    });
    expect(report.profiles.find((p) => p.name === 'Team Python')).toMatchObject({
      outcome: 'skipped',
      reason: 'language_unsupported',
    });
    expect(
      report.gates
        .find((g) => g.name === 'Sonar way')
        ?.conditions.filter((c) => c.outcome === 'unmapped')
        .map((c) => c.metric),
    ).toEqual(['new_security_hotspots_reviewed']);
    expect(report.projects[0]).toMatchObject({
      key: 'acme:shop',
      outcome: 'found',
      gate: { outcome: 'assigned' },
    });
    expect(report.projects[0]?.issues).toMatchObject({
      outcome: 'done',
      read: 3,
      applied: 2,
      unmappedRule: 1,
      hotspotsNotImported: 2,
      competitorsUnknown: 0,
      notSent: 0,
    });
    // The resolved items and, with them, the open issue of a competing rule on their file.
    const sent = q.statusCalls[0]?.items ?? [];
    expect(
      resolvedOnly(sent)
        .map((i) => i.ref)
        .sort(),
    ).toEqual(['AYi-ac-1', 'AYi-fp-1']);
    expect(sent.filter((i) => i.status === 'open').map((i) => i.ref)).toEqual(['AYi-open']);
    expect(report.projects[0]?.issues?.items.map((i) => i.sonarKey).sort()).toEqual([
      'AYi-ac-1',
      'AYi-fp-1',
    ]);
  });

  it('writes nothing on a second run: unchanged and already set', async () => {
    await start();
    const q = withProject();
    await run({}, q);
    q.writes = [];
    q.statusHandler = (_p, items) => ({
      kind: 'ok',
      results: resolvedOnly(items).map((i) => ({
        ref: i.ref,
        outcome: 'already_set',
        issueId: null,
        status: 'false_positive',
      })),
      competitors: 0,
    });
    const { code, report } = await run({}, q);
    expect(code).toBe(EXIT.OK);
    expect(q.writes).toEqual([]);
    expect(report.gates.every((g) => ['unchanged', 'skipped'].includes(g.outcome))).toBe(true);
    expect(report.projects[0]?.gate?.outcome).toBe('unchanged');
    expect(report.projects[0]?.issues?.alreadySet).toBe(2);
  });

  it('writes nothing under --dry-run', async () => {
    await start();
    const { code, report, q, log } = await run({ dryRun: true }, withProject());
    expect(code).toBe(EXIT.OK);
    expect(q.writes).toEqual([]);
    expect(q.statusCalls.every((c) => c.dryRun)).toBe(true);
    expect(report.dryRun).toBe(true);
    expect(report.projects[0]?.issues?.wouldApply).toBe(2);
    expect(log).toContain('profile Team Java (java): would create');
    expect(log).toContain('dry run: nothing was written to Qualor');
  });

  it('reports the defaults --set-defaults sets', async () => {
    await start();
    const dry = await run({ setDefaults: true, dryRun: true }, withProject());
    expect(dry.report.profiles.find((p) => p.name === 'Team Java')?.defaultChange).toBe(
      'would_set',
    );
    const { report, log, q } = await run({ setDefaults: true }, withProject());
    expect(report.profiles.find((p) => p.name === 'Team Java')?.defaultChange).toBe('set');
    expect(q.writes).toContain('setDefaultProfile');
    expect(log).toContain('profile Team Java (java): created; made the default');
  });

  it('hints at --path-prefix when most items of an analysed project are unmatched', async () => {
    const data = sampleSonarData();
    data.issues = Array.from({ length: 12 }, (_, n) => ({
      key: `AYi-p${n}`,
      rule: 'external_eslint_repo:eqeqeq',
      project: 'acme:shop',
      path: `lib/f${n}.ts`,
      line: 1,
      message: 'm',
      status: 'FALSE_POSITIVE' as const,
    }));
    await start(data);
    const { report, log, code } = await run({}, withProject());
    expect(code).toBe(EXIT.OK);
    expect(report.warnings.map((w) => w.code)).toContain('PATH_PREFIX_HINT');
    // Logged once, where it arose; the summary names only its code.
    expect(log.match(/pass it as --path-prefix/g)).toHaveLength(1);
    expect(log).toMatch(/warnings \(shown above as they occurred\): .*PATH_PREFIX_HINT 1/);
  });

  it('exits 0 when statuses come back ambiguous or competitors_unknown: they are reported outcomes', async () => {
    await start();
    const q = withProject();
    q.statusHandler = (_p, items) => ({
      kind: 'ok',
      results: resolvedOnly(items).map((i) => ({
        ref: i.ref,
        outcome: i.ref === 'AYi-fp-1' ? 'ambiguous' : 'competitors_unknown',
        issueId: null,
        status: null,
      })),
      competitors: 1,
    });
    const { code, report } = await run({}, q);
    expect(code).toBe(EXIT.OK);
    expect(report.projects[0]?.issues).toMatchObject({
      outcome: 'done',
      ambiguous: 1,
      competitorsUnknown: 1,
      notSent: 0,
    });
  });

  it('reports a status reopened in SonarQube during the run as changed, and never sends it as resolved (S11)', async () => {
    const f = await start();
    f.fault = (req) => {
      if (req.path === 'api/issues/search' && req.query['issueStatuses'] === 'OPEN,CONFIRMED') {
        f.data.issues.find((i) => i.key === 'AYi-fp-1')!.status = 'OPEN';
      }
      return null;
    };
    const { code, report, q, log } = await run({}, withProject());
    expect(code).toBe(EXIT.OK);
    const issues = report.projects[0]?.issues;
    expect(issues).toMatchObject({ outcome: 'done', read: 3, changed: 1, applied: 1 });
    expect(issues?.items.find((i) => i.sonarKey === 'AYi-fp-1')).toMatchObject({
      outcome: 'changed',
      qualorIssueId: null,
    });
    const sent = q.statusCalls.flatMap((c) => c.items);
    expect(resolvedOnly(sent).map((i) => i.ref)).toEqual(['AYi-ac-1']);
    // Ruling S14 (c): the resolved re-probe sees the total change, so nothing is trusted.
    expect(resolvedOnly(sent)[0]?.competitorsUnknown).toBe(true);
    expect(sent.find((i) => i.ref === 'AYi-fp-1')?.status).toBe('open');
    expect(log).toContain('1 changed in SonarQube');
  });

  it('marks the statuses of a capped resolved read competitors_unknown (S11)', async () => {
    await start();
    const { code, report, q } = await run({ maxIssues: 1 }, withProject());
    expect(code).toBe(EXIT.OK);
    const sent = resolvedOnly(q.statusCalls.flatMap((c) => c.items));
    expect(sent.map((i) => [i.ref, i.competitorsUnknown])).toEqual([['AYi-fp-1', true]]);
    expect(report.projects[0]?.issues).toMatchObject({ read: 1, notRead: 2 });
  });

  it('lists statuses never sent (a file too large for one request) apart from competitors_unknown', async () => {
    const data = sampleSonarData();
    const many: FakeIssue[] = Array.from({ length: 1001 }, (_, n) => ({
      key: `AYi-big${n}`,
      rule: 'external_eslint_repo:eqeqeq',
      project: 'acme:shop',
      path: 'src/big.ts',
      line: n + 1,
      message: 'm',
      status: 'FALSE_POSITIVE' as const,
    }));
    data.issues = [...data.issues, ...many];
    await start(data);
    const { code, report, q, log } = await run({ maxIssues: 2000 }, withProject());
    expect(code).toBe(EXIT.OK);
    const issues = report.projects[0]?.issues;
    expect(issues).toMatchObject({ notSent: 1001, competitorsUnknown: 0, applied: 2 });
    expect(issues?.items.filter((i) => i.outcome === 'not_sent')).toHaveLength(1001);
    expect(q.statusCalls.flatMap((c) => c.items).some((i) => i.path === 'src/big.ts')).toBe(false);
    expect(report.warnings.map((w) => w.code)).toContain('ISSUE_STATUSES_NOT_SENT');
    expect(log).toContain('1,001 not sent');
  });

  it('exits 5 when the Qualor user is not an admin of the organisation, before reading SonarQube', async () => {
    await start();
    const q = new MemoryQualor();
    q.identity = {
      isInstanceAdmin: false,
      memberships: [{ organizationId: ORG_ID, organizationKey: 'default', role: 'member' }],
    };
    const dir = mkdtempSync(path.join(os.tmpdir(), 'qualor-import-'));
    await expect(
      runImportSonarqube(
        { ...baseFlags(fake!.url), only: ['profiles'], maxIssues: 10 },
        {
          cwd: dir,
          env: { SONAR_TOKEN: fake!.data.token, QUALOR_URL: 'https://q.test', QUALOR_TOKEN },
          stdout: () => {},
          stderr: () => {},
        },
        createLogger('error', () => {}),
        { qualor: q },
      ),
    ).rejects.toMatchObject({ exitCode: EXIT.AUTH });
    expect(fake!.requests).toHaveLength(0);
  });

  it('refuses plain http to a remote SonarQube before any request (exit 2, ruling S9)', async () => {
    await start();
    const dir = mkdtempSync(path.join(os.tmpdir(), 'qualor-import-'));
    const io = {
      cwd: dir,
      env: { SONAR_TOKEN: fake!.data.token, QUALOR_URL: 'https://q.test', QUALOR_TOKEN },
      stdout: () => {},
      stderr: () => {},
    };
    await expect(
      runImportSonarqube(
        { ...baseFlags('http://sonar.example.test') },
        io,
        createLogger('error', () => {}),
        { qualor: new MemoryQualor() },
      ),
    ).rejects.toMatchObject({
      exitCode: EXIT.USAGE,
      message: expect.stringContaining('--allow-insecure-http') as unknown,
    });
    expect(fake!.requests).toHaveLength(0);
  });

  it('exits 4 when a step failed, after running the others', async () => {
    await start();
    const q = withProject();
    q.failOn.add('createGate');
    const { code, report } = await run({}, q);
    expect(code).toBe(EXIT.SERVER);
    expect(report.gates.some((g) => g.outcome === 'failed')).toBe(true);
    expect(report.profiles.find((p) => p.name === 'Team Java')?.outcome).toBe('created');
    expect(report.projects[0]?.issues?.applied).toBe(2);
  });

  it('records a project whose SonarQube settings cannot be read as failed and goes on (exit 4)', async () => {
    const data = sampleSonarData();
    data.projects.push({ key: 'acme:other', name: 'Other' });
    const f = await start(data);
    f.fault = (r) =>
      r.path === 'api/qualitygates/get_by_project' && r.query['project'] === 'acme:other'
        ? { status: 500 }
        : null;
    const { code, report } = await run({}, withProject());
    expect(code).toBe(EXIT.SERVER);
    expect(report.projects.find((p) => p.key === 'acme:other')).toMatchObject({
      outcome: 'failed',
      reason: expect.stringContaining('500') as unknown,
    });
    expect(report.projects.find((p) => p.key === 'acme:shop')?.issues?.applied).toBe(2);
  });

  it('reads only issues under --only issues', async () => {
    await start();
    const { code, report } = await run({ only: ['issues'] }, withProject());
    expect(code).toBe(EXIT.OK);
    expect(fake!.requests.some((r) => r.path === 'api/qualityprofiles/search')).toBe(false);
    expect(fake!.requests.some((r) => r.path === 'api/qualitygates/get_by_project')).toBe(false);
    expect(report.profiles).toEqual([]);
    expect(report.gates).toEqual([]);
    expect(report.projects[0]).toMatchObject({ profiles: [], gate: null });
    expect(report.projects[0]?.issues?.applied).toBe(2);
  });

  it('fails an assignment whose profile Qualor could not look up under --only projects (exit 4)', async () => {
    const data = sampleSonarData();
    data.profiles.push({
      key: 'p-java-team',
      name: 'Java Team',
      language: 'java',
      active: { 'pmd:SystemPrintln': {} },
    });
    data.projects[0]!.profiles = { java: 'p-java-team' };
    await start(data);
    const q = withProject();
    q.failOn.add('profiles');
    const { code, report } = await run({ only: ['projects'] }, q);
    expect(code).toBe(EXIT.SERVER);
    expect(report.profiles).toEqual([]);
    expect(report.projects[0]?.profiles).toMatchObject([
      {
        profile: 'Java Team',
        outcome: 'failed',
        reason: expect.stringContaining('500') as unknown,
      },
    ]);
    expect(q.writes).toEqual([]);
  });

  it('reads every setting from SonarQube before writing anything to Qualor (ruling S13)', async () => {
    const f = await start();
    f.fault = (r) => (r.path === 'api/qualitygates/get_by_project' ? { status: 401 } : null);
    const q = withProject();
    const r = await attempt({}, q);
    expect(r.error).toMatchObject({ exitCode: EXIT.AUTH });
    expect(q.writes).toEqual([]);
    expect(r.reportText).toBeNull();
  });

  it('still prints the summary and writes a report marked aborted when SonarQube refuses the token during the issue reads (ruling S13)', async () => {
    const f = await start();
    f.fault = (r) => (r.path === 'api/issues/search' ? { status: 401 } : null);
    const q = withProject();
    const r = await attempt({}, q);
    expect(r.code).toBeNull();
    expect(r.error).toMatchObject({ exitCode: EXIT.AUTH });
    expect(q.writes).toContain('createProfile');
    expect(r.report?.aborted?.reason).toMatch(/SonarQube/);
    expect(r.report?.profiles.find((p) => p.name === 'Team Java')?.outcome).toBe('created');
    expect(r.report?.projects[0]).toMatchObject({
      key: 'acme:shop',
      issues: { outcome: 'failed' },
    });
    expect(r.log).toContain('profile Team Java (java): created');
    expect(r.log).toContain('the import stopped before it finished');
  });

  it('reports a --project key SonarQube does not have as missing', async () => {
    await start();
    const { code, report } = await run({ projects: ['acme:shop', 'acme:gone'] }, withProject());
    expect(code).toBe(EXIT.OK);
    expect(report.projects.find((p) => p.key === 'acme:gone')).toMatchObject({
      outcome: 'missing',
      reason: expect.stringContaining('SonarQube') as unknown,
      qualorProjectId: null,
      issues: { outcome: 'skipped' },
    });
    expect(report.aborted).toBeNull();
  });

  it('reads only profiles under --only profiles, and only gates under --only gates', async () => {
    await start();
    await run({ only: ['profiles'] }, withProject());
    expect(fake!.requests.some((r) => r.path.startsWith('api/qualitygates/'))).toBe(false);
    fake!.requests.length = 0;
    await run({ only: ['gates'] }, withProject());
    expect(fake!.requests.some((r) => r.path === 'api/qualityprofiles/search')).toBe(false);
    expect(fake!.requests.some((r) => r.path === 'api/rules/search')).toBe(false);
  });

  it('exits 4 when --output cannot be written at the end, and keeps a worse code', async () => {
    await start();
    const dir = mkdtempSync(path.join(os.tmpdir(), 'qualor-import-'));
    const q = withProject();
    const answer = q.statusHandler;
    // The report's place becomes a directory during the run: renaming over it fails.
    q.statusHandler = (p, items, dryRun) => {
      mkdirSync(path.join(dir, 'report.json'), { recursive: true });
      return answer(p, items, dryRun);
    };
    const r = await attempt({}, q, {}, dir);
    expect(r.code).toBe(EXIT.SERVER);
    expect(r.log).toContain('cannot write --output');
    expect(r.log).toContain('issues done');
    const d2 = mkdtempSync(path.join(os.tmpdir(), 'qualor-import-'));
    const f = fake!;
    f.fault = (req) => {
      if (req.path !== 'api/issues/search') return null;
      mkdirSync(path.join(d2, 'report.json'), { recursive: true });
      return { status: 401 };
    };
    const aborted = await attempt({}, withProject(), {}, d2);
    expect(aborted.error).toMatchObject({ exitCode: EXIT.AUTH });
    expect(aborted.log).toContain('cannot write --output');
  });

  it('imports from SonarQube Cloud with --organization', async () => {
    await start(sampleSonarData({ kind: 'cloud', organization: 'acme' }));
    const { code, report } = await run(
      { sonarKind: 'cloud', organization: 'acme', dryRun: true },
      withProject(),
    );
    expect(code).toBe(EXIT.OK);
    expect(report.source).toMatchObject({ edition: 'cloud', organization: 'acme', version: null });
    const orgScoped = fake!.requests.filter((r) =>
      ['api/qualityprofiles/search', 'api/rules/search', 'api/issues/search'].includes(r.path),
    );
    expect(orgScoped.every((r) => r.query['organization'] === 'acme')).toBe(true);
    // Finding L1: Cloud's resolved issues and its reviewed hotspots are both read.
    expect(report.projects[0]?.issues).toMatchObject({
      outcome: 'done',
      read: 3,
      wouldApply: 2,
      hotspotsNotImported: 2,
    });
    expect(report.warnings.map((w) => w.code)).not.toContain('HOTSPOTS_NOT_COUNTED');
  });

  it('keeps the issues when SonarQube refuses the hotspot count: unknown, and a warning (finding L1)', async () => {
    await start(sampleSonarData({ kind: 'cloud', organization: 'acme' }));
    fake!.fault = (r) => (r.path === 'api/hotspots/search' ? { status: 400, body: '{}' } : null);
    const { code, report, log } = await run(
      { sonarKind: 'cloud', organization: 'acme' },
      withProject(),
    );
    expect(code).toBe(EXIT.OK);
    expect(report.projects[0]?.issues).toMatchObject({
      outcome: 'done',
      read: 3,
      applied: 2,
      hotspotsNotImported: null,
    });
    expect(report.warnings.filter((w) => w.code === 'HOTSPOTS_NOT_COUNTED')).toHaveLength(1);
    expect(log).toMatch(/reviewed hotspots not counted/);
  });

  it('never writes either token to stdout, stderr or the --output report', async () => {
    await start(sampleSonarData(), { echoCredentials: true });
    // An error answer that echoes the request's credentials, on the resolved-issue read.
    fake!.fault = (r) =>
      r.path === 'api/issues/search' && r.query['additionalFields'] === 'comments'
        ? { status: 500 }
        : null;
    const sonarToken = fake!.data.token;
    const basic = Buffer.from(`${sonarToken}:`).toString('base64');
    const tokenFile = path.join(mkdtempSync(path.join(os.tmpdir(), 'qualor-tok-')), 'q');
    writeFileSync(tokenFile, `${QUALOR_TOKEN}\n`);
    for (const r of [
      await run({}, withProject()),
      await run({ token: sonarToken, qualorTokenFile: tokenFile }, withProject(), {
        SONAR_TOKEN: '',
      }),
    ]) {
      expect(r.code).toBe(EXIT.SERVER);
      expect(r.report.projects[0]?.issues?.outcome).toBe('failed');
      for (const secret of [sonarToken, basic, QUALOR_TOKEN]) {
        expect(r.log).not.toContain(secret);
        expect(r.stdout).not.toContain(secret);
        expect(r.reportText).not.toContain(secret);
      }
    }
  });
});
