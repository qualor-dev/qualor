import { cpSync, existsSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { gunzipSync } from 'node:zlib';
import {
  compareFixture,
  REDACTED,
  reportFingerprints,
  reportSchema,
  type Report,
} from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { FIXTURES_DIR, loadFixture } from '../../test/fixtures';
import {
  codeQualityValidator,
  dependencyScanningValidator,
  sastValidator,
} from '../../test/gitlab-schema';
import { commitAll, initRepo, SCAN_TEST_ENV } from '../../test/git';
import { json, useTestServers } from '../../test/http';
import { captureIO } from '../../test/io';
import { useTempDirs, writeTree } from '../../test/tmp';
import { parseCommandLine, type ScanFlags } from '../args';
import { CliError } from '../errors';
import { VERSION } from '../index';
import { createLogger, silentLogger } from '../log';
import { main } from '../main';
import { pmdAnalyzer } from '../analyzers/pmd';
import { builtinAnalyzers } from '../analyzers/registry';
import { trivyJsonToSarif } from '../analyzers/trivy-output';
import type { Analyzer } from '../analyzers/types';
import { ANALYZER_OUTPUT_DIR } from '../../test/analyzers';
import { runScan } from './run';

const tmp = useTempDirs();
const serve = useTestServers();
const SECRET = 'Zx9Qe4Lr8Tn2Vb7Mk3Hs6Jp1';

function fixtureRepo(name: string): string {
  const repo = path.join(tmp(), 'repo');
  cpSync(path.join(FIXTURES_DIR, name), repo, { recursive: true });
  initRepo(repo);
  commitAll(repo, 'fixture');
  return repo;
}

function scanFlags(argv: string[]): ScanFlags {
  const command = parseCommandLine(['scan', ...argv]);
  if (command.name !== 'scan') throw new Error('not a scan');
  return command.flags;
}

function readReport(file: string): Report {
  return reportSchema.parse(JSON.parse(gunzipSync(readFileSync(file)).toString('utf8')));
}

describe('qualor scan --dry-run', () => {
  it(
    'scans ts-basic offline into a valid report that matches expected.json apart from analyzer findings',
    { timeout: 60_000 },
    async () => {
      const repo = fixtureRepo('ts-basic');
      const c = captureIO({ cwd: repo, env: SCAN_TEST_ENV });
      // No analyzers: this is the pipeline without tools (the adapters have their own tests and
      // the fixture harness runs them for real), so the result cannot depend on what is installed.
      const code = await runScan(
        scanFlags([
          '--dry-run',
          '--output',
          'out/report.json.gz',
          '--project-key',
          'fixtures/ts-basic',
        ]),
        c.io,
        silentLogger,
        { analyzers: [] },
      );
      expect(code, c.stderr()).toBe(0);
      const report = readReport(path.join(repo, 'out', 'report.json.gz'));
      expect(report.scanner).toMatchObject({ name: 'qualor-cli', version: VERSION });
      expect(report.project).toEqual({ key: 'fixtures/ts-basic', name: 'ts-basic' });
      expect(report.scm).toMatchObject({
        provider: 'none',
        branch: 'main',
        mainBranch: 'main',
        baseline: { revision: null, kind: 'server_baseline', status: 'unavailable' },
      });
      expect(report.files.every((f) => f.newLines === undefined)).toBe(true);
      expect(report.engines).toEqual([]);
      expect(report.warnings.map((w) => w.code)).toContain('BASELINE_SERVER_NOT_CONFIGURED');
      const mismatches = compareFixture(loadFixture('ts-basic').expected, report);
      expect(mismatches.filter((m) => m.kind !== 'engine' && m.kind !== 'missing-finding')).toEqual(
        [],
      );
      expect(new Set(mismatches.map((m) => m.kind))).toEqual(
        new Set(['engine', 'missing-finding']),
      );
    },
  );

  it('main() scans with the default analyzer registry', { timeout: 60_000 }, async () => {
    // The other dry-run tests pass analyzers: [] so their results cannot depend on installed tools;
    // this one keeps main() wired to builtinAnalyzers(). The repository has no TypeScript,
    // JavaScript, Java, Kotlin, C#, HTML or CSS, so ESLint, sonarjs, PMD, SpotBugs, detekt, roslyn,
    // stylelint and htmlhint are skipped wherever it runs; Gitleaks is auto so a missing binary is
    // a skip, not exit 3; Trivy runs where its database is installed and finds no lockfile (plan 2B).
    const repo = path.join(tmp(), 'repo');
    writeTree(repo, {
      'README.md': '# docs only\n',
      'qualor.yml': 'version: 1\nanalyzers:\n  gitleaks:\n    enabled: auto\n',
    });
    initRepo(repo);
    commitAll(repo, 'docs');
    const c = captureIO({ cwd: repo, env: SCAN_TEST_ENV });
    const code = await main(
      ['scan', '--dry-run', '--output', 'out/r.json.gz', '--project-key', 'docs'],
      c.io,
    );
    expect(code, c.stderr()).toBe(0);
    const report = readReport(path.join(repo, 'out', 'r.json.gz'));
    expect(report.engines.map((e) => e.id)).toEqual(builtinAnalyzers().map((a) => a.id));
    expect(report.engines.map((e) => e.id)).toEqual(
      expect.arrayContaining(['stylelint', 'htmlhint']),
    );
    const skipped = [
      'eslint',
      'sonarjs',
      'ruff',
      'pmd',
      'spotbugs',
      'detekt',
      'stylelint',
      'htmlhint',
    ];
    expect(report.engines.filter((e) => skipped.includes(e.id)).map((e) => e.status)).toEqual(
      skipped.map(() => 'skipped'),
    );
  });

  it(
    'keeps the mixed-secrets secret out of the report when Gitleaks SARIF comes in via --sarif',
    { timeout: 60_000 },
    async () => {
      const repo = fixtureRepo('mixed-secrets');
      const sample = readFileSync(
        path.join(
          FIXTURES_DIR,
          '..',
          'packages',
          'shared',
          'test',
          'sarif-samples',
          'gitleaks.sarif',
        ),
        'utf8',
      ).replaceAll('file:///fixture-root', pathToFileURL(repo).href);
      const out = tmp();
      writeTree(out, { 'gitleaks.sarif': sample });
      const c = captureIO({ cwd: repo, env: SCAN_TEST_ENV });
      const code = await runScan(
        scanFlags([
          '--dry-run',
          '--output',
          path.join(out, 'r.json.gz'),
          '--project-key',
          'fixtures/mixed-secrets',
          '--sarif',
          path.join(out, 'gitleaks.sarif'),
        ]),
        c.io,
        silentLogger,
        { analyzers: [] },
      );
      expect(code, c.stderr()).toBe(0);
      const bytes = readFileSync(path.join(out, 'r.json.gz'));
      expect(bytes.includes(SECRET)).toBe(false);
      const json = gunzipSync(bytes).toString('utf8');
      expect(json).not.toContain(SECRET);
      const report = reportSchema.parse(JSON.parse(json));
      expect(report.findings).toEqual([
        expect.objectContaining({
          engineId: 'ext-gitleaks',
          ruleId: 'generic-api-key',
          severity: 'blocker',
          location: expect.objectContaining({ path: 'src/config.ts', startLine: 2 }),
        }),
      ]);
    },
  );

  it(
    'writes the GitLab Code Quality and SAST reports from the redacted report, without the secret (scm.md §9)',
    { timeout: 60_000 },
    async () => {
      const repo = fixtureRepo('mixed-secrets');
      const sample = readFileSync(
        path.join(
          FIXTURES_DIR,
          '..',
          'packages',
          'shared',
          'test',
          'sarif-samples',
          'gitleaks.sarif',
        ),
        'utf8',
      ).replaceAll('file:///fixture-root', pathToFileURL(repo).href);
      const out = tmp();
      // A second, non-secret engine whose rule is named after the secret and whose message quotes
      // it: only the redaction keeps the secret out of the GitLab files.
      const lint = JSON.stringify({
        version: '2.1.0',
        runs: [
          {
            tool: {
              driver: {
                name: 'team-lint',
                rules: [
                  {
                    id: 'config-literal',
                    name: `Config literal ${SECRET}`,
                    properties: { qualor: { quality: 'security' } },
                  },
                ],
              },
            },
            results: [
              {
                ruleId: 'config-literal',
                level: 'warning',
                message: { text: `the key ${SECRET} is inlined` },
                locations: [
                  {
                    physicalLocation: {
                      artifactLocation: { uri: 'src/config.ts' },
                      region: { startLine: 4 },
                    },
                  },
                ],
              },
            ],
          },
        ],
      });
      writeTree(out, { 'gitleaks.sarif': sample, 'lint.sarif': lint });
      const scan = async (codeQuality: string, sast: string) => {
        const c = captureIO({ cwd: repo, env: SCAN_TEST_ENV });
        const code = await runScan(
          scanFlags([
            '--dry-run',
            '--output',
            path.join(out, 'r.json.gz'),
            '--project-key',
            'fixtures/mixed-secrets',
            '--sarif',
            path.join(out, 'gitleaks.sarif'),
            '--sarif',
            path.join(out, 'lint.sarif'),
            '--gitlab-code-quality',
            codeQuality,
            '--gitlab-sast',
            sast,
          ]),
          c.io,
          silentLogger,
          { analyzers: [] },
        );
        expect(code, c.stderr()).toBe(0);
        const bytes = readFileSync(path.join(repo, codeQuality));
        expect(bytes.includes(SECRET)).toBe(false);
        expect(bytes.includes(REDACTED)).toBe(true);
        const sastBytes = readFileSync(path.join(repo, sast));
        expect(sastBytes.includes(SECRET)).toBe(false);
        expect(sastBytes.includes(REDACTED)).toBe(true);
        expect(gunzipSync(readFileSync(path.join(out, 'r.json.gz'))).includes(SECRET)).toBe(false);
        return { text: bytes.toString('utf8'), sastText: sastBytes.toString('utf8') };
      };
      // In the working directory, as the CI component writes them.
      const { text, sastText } = await scan('gl-code-quality-report.json', 'gl-sast-report.json');
      const sast = JSON.parse(sastText) as {
        scan: { status: string };
        vulnerabilities: { id: string; name: string; description: string; severity: string }[];
      };
      const validateSast = sastValidator();
      expect(validateSast(sast), JSON.stringify(validateSast.errors)).toBe(true);
      expect(sast.scan.status).toBe('success');
      expect(sast.vulnerabilities).toEqual([
        expect.objectContaining({
          severity: 'Critical',
          location: expect.objectContaining({ file: 'src/config.ts', start_line: 2 }),
        }),
        // The rule name held the secret, so the rule key stands in for it.
        expect.objectContaining({
          name: 'team-lint:config-literal',
          description: '` the key «redacted» is inlined `',
          severity: 'Medium',
          location: expect.objectContaining({ file: 'src/config.ts', start_line: 4 }),
        }),
      ]);
      const validateCodeQuality = codeQualityValidator();
      expect(
        validateCodeQuality(JSON.parse(text)),
        JSON.stringify(validateCodeQuality.errors),
      ).toBe(true);
      const report = readReport(path.join(out, 'r.json.gz'));
      const fingerprints = reportFingerprints(report.findings);
      const at = (engineId: string) => report.findings.findIndex((f) => f.engineId === engineId);
      expect(JSON.parse(text)).toEqual([
        {
          description: report.findings[at('ext-gitleaks')]?.message,
          check_name: 'ext-gitleaks:generic-api-key',
          fingerprint: fingerprints[at('ext-gitleaks')],
          severity: 'blocker',
          location: { path: 'src/config.ts', lines: { begin: 2 } },
        },
        {
          description: 'the key «redacted» is inlined',
          check_name: 'team-lint:config-literal',
          fingerprint: fingerprints[at('team-lint')],
          severity: 'major',
          location: { path: 'src/config.ts', lines: { begin: 4 } },
        },
      ]);
      // A second run of the same commit gives GitLab the same fingerprints.
      const again = await scan('again-cq.json', 'again-sast.json');
      expect(
        (JSON.parse(again.text) as { fingerprint: string }[]).map((e) => e.fingerprint),
      ).toEqual((JSON.parse(text) as { fingerprint: string }[]).map((e) => e.fingerprint));
      expect((JSON.parse(again.sastText) as typeof sast).vulnerabilities.map((v) => v.id)).toEqual(
        sast.vulnerabilities.map((v) => v.id),
      );
    },
  );

  it(
    'writes no Code Quality file and a failed SAST scan when an engine did not complete (ruling G6)',
    { timeout: 60_000 },
    async () => {
      const repo = fixtureRepo('ts-basic');
      const run = async (analyzers: Analyzer[]) => {
        const lines: string[] = [];
        const c = captureIO({ cwd: repo, env: SCAN_TEST_ENV });
        rmSync(path.join(repo, 'cq.json'), { force: true });
        const code = await runScan(
          scanFlags([
            '--dry-run',
            '--output',
            'r.json.gz',
            '--project-key',
            'fixtures/ts-basic',
            '--gitlab-code-quality',
            'cq.json',
            '--gitlab-sast',
            'sast.json',
          ]),
          c.io,
          createLogger('info', (t) => lines.push(t)),
          { analyzers },
        );
        expect(code, c.stderr()).toBe(0);
        const sast = JSON.parse(readFileSync(path.join(repo, 'sast.json'), 'utf8')) as {
          scan: { status: string };
        };
        expect(sastValidator()(sast)).toBe(true);
        return {
          lines: lines.join(''),
          status: sast.scan.status,
          cq: existsSync(path.join(repo, 'cq.json')),
        };
      };
      // A tool that could not run: its findings are missing, not fixed.
      const missing = await run([
        {
          ...pmdAnalyzer,
          languages: [],
          prepare: () => Promise.resolve({ unavailable: 'PMD is not installed' }),
        },
      ]);
      expect(missing).toMatchObject({ status: 'failure', cq: false });
      expect(missing.lines).toContain(
        'warn: --gitlab-code-quality: not written, because not every analyzer completed (pmd)',
      );
      expect(missing.lines).toContain(
        'warn: --gitlab-sast: the scan is marked failed, because not every analyzer completed (pmd)',
      );
      // PMD with no Java file to analyse had nothing to do: that is complete.
      expect(await run([pmdAnalyzer])).toMatchObject({ status: 'success', cq: true });
      // A configuration skip (no ESLint configuration, no rulesets, no compiled classes...) did
      // what the configuration asked: complete.
      const configured = await run([
        {
          ...pmdAnalyzer,
          languages: [],
          prepare: () => Promise.resolve({ skip: 'no PMD rulesets configured' }),
        },
      ]);
      expect(configured).toMatchObject({ status: 'success', cq: true });
      expect(configured.lines).not.toContain('not every analyzer completed');
      // Disabled in qualor.yml: complete, whatever the tool would do.
      writeTree(repo, { 'qualor.yml': 'version: 1\nanalyzers:\n  pmd:\n    enabled: false\n' });
      expect(
        await run([
          {
            ...pmdAnalyzer,
            languages: [],
            prepare: () => Promise.resolve({ unavailable: 'PMD is not installed' }),
          },
        ]),
      ).toMatchObject({ status: 'success', cq: true });
    },
  );

  it(
    'warns and still finishes the scan when a GitLab file cannot be written after the scan',
    { timeout: 60_000 },
    async () => {
      const repo = fixtureRepo('ts-basic');
      const lines: string[] = [];
      const c = captureIO({ cwd: repo, env: SCAN_TEST_ENV });
      const code = await runScan(
        scanFlags([
          '--dry-run',
          '--output',
          'r.json.gz',
          '--project-key',
          'fixtures/ts-basic',
          '--gitlab-sast',
          'sast.json',
        ]),
        c.io,
        createLogger('info', (t) => lines.push(t)),
        {
          analyzers: [
            {
              ...pmdAnalyzer,
              languages: [],
              // Something in the job puts a directory where the file goes, after the first check.
              prepare: () => {
                mkdirSync(path.join(repo, 'sast.json'));
                return Promise.resolve({ skip: 'test' });
              },
            },
          ],
        },
      );
      expect(code, c.stderr()).toBe(0);
      expect(existsSync(path.join(repo, 'r.json.gz'))).toBe(true);
      expect(lines.join('')).toContain(
        'warn: --gitlab-sast sast.json: is a directory; the analysis goes on without it',
      );
    },
  );

  it('exits 2 before scanning when a GitLab report cannot be written', async () => {
    const repo = fixtureRepo('ts-basic');
    const c = captureIO({ cwd: repo, env: SCAN_TEST_ENV });
    const scanned: string[] = [];
    const run = (file: string) =>
      runScan(
        scanFlags(['--dry-run', '--output', 'r.json.gz', '--gitlab-code-quality', file]),
        c.io,
        silentLogger,
        {
          analyzers: [
            {
              ...pmdAnalyzer,
              prepare: () => {
                scanned.push('pmd');
                return Promise.resolve({ kind: 'skip', reason: 'test' } as never);
              },
            },
          ],
        },
      );
    await expect(run('no/such/dir/cq.json')).rejects.toMatchObject({
      exitCode: 2,
      message: '--gitlab-code-quality no/such/dir/cq.json: its directory does not exist',
    });
    await expect(run('../cq.json')).rejects.toMatchObject({
      exitCode: 2,
      message: '--gitlab-code-quality ../cq.json: is outside the working directory',
    });
    await expect(
      runScan(
        scanFlags(['--dry-run', '--output', 'r.json.gz', '--gitlab-sast', 'src']),
        c.io,
        silentLogger,
        { analyzers: [] },
      ),
    ).rejects.toMatchObject({ exitCode: 2, message: '--gitlab-sast src: is a directory' });
    expect(scanned).toEqual([]);
  });

  it(
    'never writes QUALOR_TOKEN into the report, even through a double-interpolation trick in qualor.yml',
    { timeout: 60_000 },
    async () => {
      const TOKEN = 'qlr_pat_e2e_bypass_token_value';
      const repo = path.join(tmp(), 'repo');
      writeTree(repo, {
        'qualor.yml':
          'version: 1\n' +
          'project:\n' +
          '  key: acme/app\n' +
          '  version: "$${QUALOR_TOKEN}{QUALOR_TOKEN}"\n' +
          '  name: "x-${INDIRECT}"\n' +
          // No analyzer runs (Gitleaks is required by default and may not be installed here), so
          // the scan is complete and both GitLab files are always written (ruling G6). sonarjs is
          // left on auto: without /opt/qualor/sonarjs it is skipped, not unavailable (fix round 1,
          // controller ruling 12), so it does not need disabling here either.
          'analyzers:\n' +
          ['eslint', 'pmd', 'spotbugs', 'semgrep', 'gitleaks']
            .map((id) => `  ${id}:\n    enabled: false\n`)
            .join(''),
        'src/a.ts': 'export const a = 1;\n',
        [`src/${TOKEN}.ts`]: 'export const b = 2;\n',
      });
      initRepo(repo);
      commitAll(repo, 'init');
      const c = captureIO({
        cwd: repo,
        env: { ...SCAN_TEST_ENV, QUALOR_TOKEN: TOKEN, INDIRECT: '${QUALOR_TOKEN}' },
      });
      const code = await main(
        [
          'scan',
          '--dry-run',
          '--output',
          'r.json.gz',
          '--gitlab-code-quality',
          'cq.json',
          '--gitlab-sast',
          'sast.json',
        ],
        c.io,
      );
      expect(code, c.stderr()).toBe(0);
      const json = gunzipSync(readFileSync(path.join(repo, 'r.json.gz'))).toString('utf8');
      expect(json).not.toContain(TOKEN);
      for (const file of ['cq.json', 'sast.json']) {
        expect(readFileSync(path.join(repo, file)).includes(TOKEN)).toBe(false);
      }
      const report = reportSchema.parse(JSON.parse(json));
      expect(report.project.version).toBe('${QUALOR_TOKEN}');
      expect(report.files.map((f) => f.path)).toContain('src/«redacted».ts');
      expect(c.stderr()).not.toContain(TOKEN);
    },
  );

  it(
    'rejects a bad --sarif file with exit 2 before running git or asking the server anything',
    { timeout: 60_000 },
    async () => {
      const repo = path.join(tmp(), 'repo');
      writeTree(repo, { 'src/a.ts': 'export const a = 1;\n', 'bad.sarif': 'not json' });
      const calls: string[] = [];
      const c = captureIO({ cwd: repo, env: SCAN_TEST_ENV });
      const run = (sarif: string) =>
        runScan(
          {
            sarif: [sarif],
            coverage: [],
            wait: true,
            dryRun: true,
            output: 'r.json.gz',
            projectKey: 'acme/a',
          },
          c.io,
          createLogger('error', c.io.stderr),
          {
            git: (args) => {
              calls.push(`git ${args.join(' ')}`);
              return Promise.resolve({ code: 1, stdout: '', stderr: 'unexpected' });
            },
            baselineClient: {
              fetchBaseline: () => {
                calls.push('baseline');
                return Promise.resolve({ revision: null, warnings: [] });
              },
            },
          },
        ).catch((err: unknown) => err);
      for (const sarif of ['missing.sarif', 'bad.sarif']) {
        const err = await run(sarif);
        expect(err, sarif).toMatchObject({ exitCode: 2 });
        expect((err as Error).message, sarif).toContain(sarif);
      }
      expect(calls).toEqual([]);
    },
  );

  it(
    'warns when the token would go to a server.url that only qualor.yml set',
    { timeout: 60_000 },
    async () => {
      const repo = path.join(tmp(), 'repo');
      writeTree(repo, {
        'qualor.yml': 'version: 1\nserver:\n  url: https://repo-chosen.invalid\n',
        'src/a.ts': 'export const a = 1;\n',
      });
      initRepo(repo);
      commitAll(repo, 'init');
      const scan = async (env: Record<string, string>) => {
        const c = captureIO({ cwd: repo, env: { ...SCAN_TEST_ENV, ...env } });
        const code = await runScan(
          {
            sarif: [],
            coverage: [],
            wait: true,
            dryRun: true,
            output: 'r.json.gz',
            projectKey: 'acme/a',
          },
          c.io,
          createLogger('warn', c.io.stderr),
          { baselineClient: null, analyzers: [] },
        );
        expect(code).toBe(0);
        return c.stderr();
      };
      expect(await scan({ QUALOR_TOKEN: 'qlr_x' })).toContain('or pass --server-url');
      expect(await scan({ QUALOR_TOKEN: 'qlr_x', QUALOR_URL: 'https://ci.invalid' })).not.toContain(
        'or pass --server-url',
      );
      expect(await scan({})).not.toContain('or pass --server-url');
    },
  );

  it(
    'sends the token only to a URL from --server-url or QUALOR_URL, never to one only qualor.yml names',
    { timeout: 60_000 },
    async () => {
      const server = await serve((_req, res) => json(res, 200, { revision: null, warnings: [] }));
      const repo = path.join(tmp(), 'repo');
      writeTree(repo, {
        'qualor.yml': `version: 1\nserver:\n  url: ${server.url}\nscm:\n  mainBranch: main\n`,
        'src/a.ts': 'export const a = 1;\n',
      });
      initRepo(repo);
      commitAll(repo, 'init');
      const TOKEN = 'qlr_prj_q_b9_token_value';
      const scan = async (argv: string[], env: Record<string, string> = {}) => {
        const c = captureIO({ cwd: repo, env: { ...SCAN_TEST_ENV, QUALOR_TOKEN: TOKEN, ...env } });
        const log = createLogger('warn', c.io.stderr);
        const code = await runScan(scanFlags([...argv, '--project-key', 'acme/a']), c.io, log, {
          analyzers: [],
        }).catch((err: unknown) => {
          if (!(err instanceof CliError)) throw err;
          log.error(err.message);
          return err.exitCode;
        });
        expect(c.stderr()).not.toContain(TOKEN);
        return { code, stderr: c.stderr() };
      };
      // Upload to a repo-chosen URL: exit 2 before any request.
      const upload = await scan([]);
      expect(upload.code).toBe(2);
      expect(upload.stderr).toContain('or pass --server-url');
      // --dry-run: a warning, and still no request.
      const dry = await scan(['--dry-run', '--output', 'r.json.gz']);
      expect(dry.code).toBe(0);
      expect(dry.stderr).toContain('or pass --server-url');
      expect(readReport(path.join(repo, 'r.json.gz')).warnings).toContainEqual(
        expect.objectContaining({ code: 'BASELINE_SERVER_NOT_CONFIGURED' }),
      );
      expect(server.requests).toHaveLength(0);
      // The same URL from the command line or from QUALOR_URL receives the token.
      const flag = await scan(['--dry-run', '--output', 'r.json.gz', '--server-url', server.url]);
      expect([flag.code, flag.stderr]).toEqual([0, '']);
      const env = await scan(['--dry-run', '--output', 'r.json.gz'], { QUALOR_URL: server.url });
      expect([env.code, env.stderr]).toEqual([0, '']);
      expect(server.requests.map((r) => r.headers.authorization)).toEqual([
        `Bearer ${TOKEN}`,
        `Bearer ${TOKEN}`,
      ]);
      expect(readReport(path.join(repo, 'r.json.gz')).scm.baseline.status).toBe('first_analysis');
    },
  );

  it(
    'refuses an upload with a server.caFile only qualor.yml names, and ignores it under --dry-run (V8)',
    { timeout: 60_000 },
    async () => {
      const server = await serve((_req, res) => json(res, 200, { revision: null, warnings: [] }));
      const repo = path.join(tmp(), 'repo');
      writeTree(repo, {
        'qualor.yml':
          'version: 1\nserver:\n  caFile: certs/repo-ca.pem\nscm:\n  mainBranch: main\n',
        'src/a.ts': 'export const a = 1;\n',
      });
      initRepo(repo);
      commitAll(repo, 'init');
      const scan = async (argv: string[]) => {
        const c = captureIO({
          cwd: repo,
          env: { ...SCAN_TEST_ENV, QUALOR_TOKEN: 'qlr_prj_v8', QUALOR_URL: server.url },
        });
        const log = createLogger('warn', c.io.stderr);
        const code = await runScan(scanFlags([...argv, '--project-key', 'acme/a']), c.io, log, {
          analyzers: [],
        }).catch((err: unknown) => {
          if (!(err instanceof CliError)) throw err;
          log.error(err.message);
          return err.exitCode;
        });
        return { code, stderr: c.stderr() };
      };
      const upload = await scan([]);
      expect(upload.code).toBe(2);
      expect(upload.stderr).toContain('QUALOR_CA_FILE');
      expect(server.requests).toHaveLength(0);
      // --dry-run: a warning, the file is never read (it does not exist), the request still goes out.
      const dry = await scan(['--dry-run', '--output', 'r.json.gz']);
      expect(dry.code).toBe(0);
      expect(dry.stderr).toContain('QUALOR_CA_FILE');
      expect(server.requests).toHaveLength(1);
      expect(readReport(path.join(repo, 'r.json.gz')).scm.baseline.status).toBe('first_analysis');
    },
  );

  it(
    'writes the report and exits 3 when a required analyzer cannot run',
    { timeout: 60_000 },
    async () => {
      const repo = path.join(tmp(), 'repo');
      writeTree(repo, {
        'qualor.yml': 'version: 1\nanalyzers:\n  pmd:\n    enabled: true\n',
        'src/A.java': 'class A {}\n',
      });
      initRepo(repo);
      commitAll(repo, 'init');
      const c = captureIO({ cwd: repo, env: SCAN_TEST_ENV });
      const code = await runScan(
        {
          sarif: [],
          coverage: [],
          wait: true,
          dryRun: true,
          output: 'r.json.gz',
          projectKey: 'acme/a',
        },
        c.io,
        createLogger('error', c.io.stderr),
        {
          analyzers: [
            {
              id: 'pmd',
              languages: ['java'],
              prepare: () => Promise.resolve({ skip: 'pmd binary not found' }),
            },
          ],
        },
      );
      expect(code).toBe(3);
      expect(readReport(path.join(repo, 'r.json.gz')).engines).toEqual([
        expect.objectContaining({ id: 'pmd', status: 'failed', reason: 'pmd binary not found' }),
      ]);
      expect(c.stderr()).toContain('required analyzers failed: pmd');
    },
  );

  it(
    'exits 2 before scanning when a PMD ruleset references a URL (ruling V4), unless PMD is disabled',
    { timeout: 60_000 },
    async () => {
      const repo = path.join(tmp(), 'repo');
      const ruleset =
        '<?xml version="1.0"?>\n<ruleset name="r" xmlns="http://pmd.sourceforge.net/ruleset/2.0.0">\n' +
        '  <description>r</description>\n  <rule ref="http://127.0.0.1:8123/remote.xml"/>\n</ruleset>\n';
      writeTree(repo, {
        'qualor.yml': 'version: 1\nanalyzers:\n  pmd:\n    rulesets: [config/r.xml]\n',
        'config/r.xml': ruleset,
        'src/A.java': 'class A {}\n',
      });
      initRepo(repo);
      commitAll(repo, 'init');
      const c = captureIO({ cwd: repo, env: SCAN_TEST_ENV });
      expect(
        await main(['scan', '--dry-run', '--output', 'r.json.gz', '--project-key', 'a/b'], c.io),
      ).toBe(2);
      expect(c.stderr()).toContain(
        'analyzers.pmd: ruleset config/r.xml: rule ref "http://127.0.0.1:8123/remote.xml" is a URL',
      );
      writeTree(repo, {
        'qualor.yml':
          'version: 1\nanalyzers:\n  pmd:\n    enabled: false\n    rulesets: [config/r.xml]\n',
      });
      const off = captureIO({ cwd: repo, env: SCAN_TEST_ENV });
      const code = await runScan(
        scanFlags(['--dry-run', '--output', 'r.json.gz', '--project-key', 'a/b']),
        off.io,
        silentLogger,
        { analyzers: [pmdAnalyzer] },
      );
      expect(code, off.stderr()).toBe(0);
    },
  );

  it(
    'exits 2 without a server (unless --dry-run), without a project key and for a bad --output',
    { timeout: 60_000 },
    async () => {
      const repo = fixtureRepo('ts-basic');
      const noServer = captureIO({ cwd: repo, env: SCAN_TEST_ENV });
      expect(await main(['scan'], noServer.io)).toBe(2);
      expect(noServer.stderr()).toContain('QUALOR_URL');
      const noKey = captureIO({ cwd: repo, env: SCAN_TEST_ENV });
      expect(await main(['scan', '--dry-run', '--output', 'r.gz'], noKey.io)).toBe(2);
      expect(noKey.stderr()).toContain('no project key');
      const badOutput = captureIO({ cwd: repo, env: SCAN_TEST_ENV });
      expect(
        await main(['scan', '--dry-run', '--output', 'src', '--project-key', 'a/b'], badOutput.io),
      ).toBe(2);
      expect(badOutput.stderr()).toContain('cannot write the report');
    },
  );
});

describe('qualor scan --gitlab-dependency-scanning (scm.md §9, plan 2B)', () => {
  /** Trivy as the runner sees it: a process writing its recorded JSON, converted like the adapter. */
  const recordedTrivy = (tool: string, edit: (sarif: unknown) => unknown = (x) => x): Analyzer => ({
    id: 'trivy',
    languages: [],
    prepare: (ctx) => {
      const out = path.join(ctx.workDir, 'trivy.json');
      return Promise.resolve({
        run: {
          command: process.execPath,
          args: [tool, out],
          cwd: ctx.root,
          sarifPath: out,
          okExitCodes: [0],
          database: { name: 'trivy-db', updatedAt: '2026-09-25T06:36:11.019457553Z' },
          transform: (output) => edit(trivyJsonToSarif(output, ctx.root)),
        },
      });
    },
  });

  it(
    'writes the three GitLab files: the vulnerable dependencies in Dependency Scanning, not in SAST',
    { timeout: 60_000 },
    async () => {
      const repo = fixtureRepo('deps-vulnerable');
      const tool = path.join(tmp(), 'trivy.mjs');
      writeTree(path.dirname(tool), {
        'trivy.mjs': `import { copyFileSync } from 'node:fs';\ncopyFileSync(${JSON.stringify(
          path.join(ANALYZER_OUTPUT_DIR, 'trivy-deps-vulnerable.json'),
        )}, process.argv[2]);\n`,
      });
      const c = captureIO({ cwd: repo, env: SCAN_TEST_ENV });
      const code = await runScan(
        scanFlags([
          '--dry-run',
          '--output',
          'r.json.gz',
          '--project-key',
          'fixtures/deps-vulnerable',
          '--gitlab-code-quality',
          'gl-code-quality-report.json',
          '--gitlab-sast',
          'gl-sast-report.json',
          '--gitlab-dependency-scanning',
          'gl-dependency-scanning-report.json',
        ]),
        c.io,
        silentLogger,
        { analyzers: [recordedTrivy(tool)] },
      );
      expect(code, c.stderr()).toBe(0);
      const read = (file: string) =>
        JSON.parse(readFileSync(path.join(repo, file), 'utf8')) as unknown;
      const ds = read('gl-dependency-scanning-report.json') as {
        scan: { status: string };
        vulnerabilities: { name: string; location: unknown }[];
      };
      const validate = dependencyScanningValidator();
      expect(validate(ds), JSON.stringify(validate.errors)).toBe(true);
      expect(ds.scan.status).toBe('success');
      expect(ds.vulnerabilities.map((v) => [v.name, v.location])).toEqual([
        [
          'CVE-2015-7501',
          {
            file: 'java/gradle.lockfile',
            dependency: {
              package: { name: 'commons-collections:commons-collections' },
              version: '3.2.1',
            },
          },
        ],
        [
          'CVE-2021-44906',
          {
            file: 'tools/pnpm-lock.yaml',
            dependency: { package: { name: 'minimist' }, version: '1.2.5', direct: true },
          },
        ],
        [
          'CVE-2021-44906',
          {
            file: 'web/package-lock.json',
            dependency: { package: { name: 'minimist' }, version: '1.2.5', direct: true },
          },
        ],
        [
          'CVE-2015-6420',
          {
            file: 'java/gradle.lockfile',
            dependency: {
              package: { name: 'commons-collections:commons-collections' },
              version: '3.2.1',
            },
          },
        ],
      ]);
      expect(
        (read('gl-sast-report.json') as { vulnerabilities: unknown[] }).vulnerabilities,
      ).toEqual([]);
      const cq = read('gl-code-quality-report.json');
      expect(codeQualityValidator()(cq)).toBe(true);
      expect(cq).toHaveLength(4);
      const report = readReport(path.join(repo, 'r.json.gz'));
      expect(report.engines).toEqual([
        expect.objectContaining({
          id: 'trivy',
          status: 'ok',
          version: '0.74.0',
          database: { name: 'trivy-db', updatedAt: '2026-09-25T06:36:11.019457553Z' },
        }),
      ]);
    },
  );

  it(
    'warns when a finding without its package makes the Dependency Scanning scan a failure',
    { timeout: 60_000 },
    async () => {
      const repo = fixtureRepo('deps-vulnerable');
      const tool = path.join(tmp(), 'trivy.mjs');
      writeTree(path.dirname(tool), {
        'trivy.mjs': `import { copyFileSync } from 'node:fs';
copyFileSync(${JSON.stringify(
          path.join(ANALYZER_OUTPUT_DIR, 'trivy-deps-vulnerable.json'),
        )}, process.argv[2]);
`,
      });
      // The first result loses its package, as when a finding's properties were dropped.
      const drop = (sarif: unknown) => {
        const run = (sarif as { runs: { results: { properties?: Record<string, unknown> }[] }[] })
          .runs[0]!;
        delete run.results[0]!.properties!['dependency'];
        return sarif;
      };
      const c = captureIO({ cwd: repo, env: SCAN_TEST_ENV });
      const code = await runScan(
        scanFlags([
          '--dry-run',
          '--output',
          'r.json.gz',
          '--project-key',
          'fixtures/deps-vulnerable',
          '--gitlab-dependency-scanning',
          'gl-dependency-scanning-report.json',
        ]),
        c.io,
        createLogger('warn', c.io.stderr),
        { analyzers: [recordedTrivy(tool, drop)] },
      );
      expect(code, c.stderr()).toBe(0);
      const ds = JSON.parse(
        readFileSync(path.join(repo, 'gl-dependency-scanning-report.json'), 'utf8'),
      ) as { scan: { status: string }; vulnerabilities: unknown[] };
      expect(ds.scan.status).toBe('failure');
      expect(ds.vulnerabilities).toHaveLength(3);
      expect(c.stderr()).toContain(
        '--gitlab-dependency-scanning: the scan is marked failed, because 1 dependency finding(s) have no package: GitLab would take them as fixed',
      );
    },
  );

  it('refuses a Dependency Scanning path it cannot write, before any analyzer runs', async () => {
    const repo = fixtureRepo('deps-vulnerable');
    await expect(
      runScan(
        scanFlags(['--dry-run', '--output', 'r.json.gz', '--gitlab-dependency-scanning', 'web']),
        captureIO({ cwd: repo, env: SCAN_TEST_ENV }).io,
        silentLogger,
        { analyzers: [] },
      ),
    ).rejects.toMatchObject({
      exitCode: 2,
      message: '--gitlab-dependency-scanning web: is a directory',
    });
  });
});
