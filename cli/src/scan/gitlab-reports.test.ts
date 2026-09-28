import { createHash } from 'node:crypto';
import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { reportFingerprints, type Report } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import {
  codeQualityValidator,
  DEPENDENCY_SCANNING_SCHEMA_FILE,
  dependencyScanningValidator,
  SCHEMA_DIR,
  SCHEMA_FILE,
  SCHEMA_SOURCE_TAG,
  sastValidator,
} from '../../test/gitlab-schema';
import { useTempDirs } from '../../test/tmp';
import { CliError } from '../errors';
import {
  boundedJson,
  checkReportPath,
  codeQualityReport,
  DEPENDENCY_SCANNING_SCHEMA_URL,
  dependencyScanningReport,
  SAST_SCHEMA_URL,
  SAST_SCHEMA_VERSION,
  sastReport,
  sastTime,
  writeGitLabReport,
} from './gitlab-reports';

const SCHEMA_SHA256 = '2d488750975f48c816dffb81a0a582c0579843f9b52b86b61791d8c0c157304c';
const LICENSE_SHA256 = '5a56186a3e6ed84c58dfa3b3baad940d105c7e041bb00c0333ef88306f2214e7';

const tmp = useTempDirs();

/** File symlinks need Developer Mode or elevation on Windows; probe once, like eslint.test.ts. */
function canCreateFileSymlinks(): boolean {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'qualor-symlink-check-'));
  try {
    writeFileSync(path.join(dir, 'target.txt'), 'x');
    symlinkSync(path.join(dir, 'target.txt'), path.join(dir, 'link.txt'), 'file');
    return true;
  } catch {
    return false;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
const CAN_SYMLINK_FILES = canCreateFileSymlinks();

/** A small valid report: one file, one ESLint rule with metadata, no findings. */
function makeReport(): Report {
  return {
    schemaVersion: 1,
    scanner: { name: 'qualor-cli', version: '0.0.0' },
    project: { key: 'acme/demo', name: 'Demo' },
    scm: {
      provider: 'gitlab',
      revision: 'a'.repeat(40),
      branch: 'main',
      mainBranch: 'main',
      mergeRequest: null,
      baseline: { revision: null, kind: 'none', status: 'unavailable' },
      renames: [],
    },
    analysisDate: '2026-09-22T10:15:00Z',
    engines: [
      {
        id: 'eslint',
        kind: 'builtin',
        version: '9.0.0',
        status: 'ok',
        durationMs: 10,
        rules: [{ id: 'no-console', defaultSeverity: 'medium', quality: 'maintainability' }],
      },
    ],
    files: [
      { path: 'src/a.ts', language: 'typescript', kind: 'main', sha256: 'c'.repeat(64), lines: 10 },
    ],
    findings: [
      {
        engineId: 'eslint',
        ruleId: 'no-console',
        message: 'Unexpected console statement.',
        severity: 'medium',
        location: { path: 'src/a.ts', startLine: 3 },
        lineHash: 'd'.repeat(32),
        contextHash: 'e'.repeat(32),
      },
    ],
    duplications: [],
    warnings: [],
  };
}

function withFindings(findings: Report['findings'], engines?: Report['engines']): Report {
  const base = makeReport();
  return { ...base, findings, ...(engines ? { engines } : {}) };
}

/** The exit code and message of a CliError thrown by `run`, or 'no error'. */
function usage(run: () => unknown): string {
  try {
    run();
  } catch (err) {
    if (err instanceof CliError) return `${err.exitCode}: ${err.message}`;
    throw err;
  }
  return 'no error';
}

async function usageAsync(run: () => Promise<unknown>): Promise<string> {
  try {
    await run();
  } catch (err) {
    if (err instanceof CliError) return `${err.exitCode}: ${err.message}`;
    throw err;
  }
  return 'no error';
}

describe('GitLab Code Quality report (scm.md §9)', () => {
  const base = makeReport();
  const finding = base.findings[0]!;

  it('writes one entry per located finding with the server fingerprint and mapped severity, most severe first', () => {
    const report = withFindings([
      { ...finding, severity: 'high', message: '@all `x` <img src=x>' },
      { ...finding, severity: 'info', location: null },
      { ...finding, severity: 'blocker', lineHash: 'f'.repeat(32) },
    ]);
    const fingerprints = reportFingerprints(report.findings);
    expect(codeQualityReport(report)).toEqual([
      expect.objectContaining({ severity: 'blocker', fingerprint: fingerprints[2] }),
      {
        description: '@all `x` <img src=x>',
        check_name: `${finding.engineId}:${finding.ruleId}`,
        fingerprint: fingerprints[0],
        severity: 'critical',
        location: { path: finding.location!.path, lines: { begin: finding.location!.startLine } },
      },
    ]);
    const validate = codeQualityValidator();
    expect(validate(codeQualityReport(report)), JSON.stringify(validate.errors)).toBe(true);
    expect(validate([{ ...codeQualityReport(report)[0], severity: 'high' }])).toBe(false);
  });

  it('keeps its fingerprints stable across runs: they depend on the finding, not the scan', () => {
    const report = withFindings([finding, { ...finding, lineHash: 'f'.repeat(32) }]);
    const again: Report = {
      ...structuredClone(report),
      analysisDate: '2026-09-23T08:00:00Z',
      scm: { ...report.scm, revision: 'b'.repeat(40) },
      findings: structuredClone(report.findings).map((f) => ({ ...f, message: 'reworded' })),
    };
    const fingerprints = codeQualityReport(report).map((e) => e.fingerprint);
    expect(codeQualityReport(again).map((e) => e.fingerprint)).toEqual(fingerprints);
    expect(new Set(fingerprints).size).toBe(2);
    for (const f of fingerprints) expect(f).toMatch(/^[0-9a-f]{32}$/);
  });

  it('maps every severity, and falls back to the rule default, then medium', () => {
    const map = (severity: NonNullable<Report['findings'][number]['severity']>) =>
      codeQualityReport(withFindings([{ ...finding, severity }]))[0]?.severity;
    expect([map('blocker'), map('high'), map('medium'), map('low'), map('info')]).toEqual([
      'blocker',
      'critical',
      'major',
      'minor',
      'info',
    ]);
    const bare = { ...finding };
    delete bare.severity;
    const engines = base.engines.map((e) =>
      e.id === finding.engineId
        ? { ...e, rules: [{ id: finding.ruleId, defaultSeverity: 'low' as const }] }
        : e,
    );
    expect(codeQualityReport(withFindings([bare], engines))[0]?.severity).toBe('minor');
    expect(
      codeQualityReport(
        withFindings(
          [bare],
          base.engines.map((e) => ({ ...e, rules: [] })),
        ),
      )[0]?.severity,
    ).toBe('major');
  });

  it('keeps the most severe entries when the size bound cuts the file', () => {
    const findings = (['info', 'low', 'blocker', 'medium', 'high'] as const).map((severity, i) => ({
      ...finding,
      severity,
      lineHash: String(i).repeat(32),
    }));
    const entries = codeQualityReport(withFindings(findings));
    expect(entries.map((e) => e.severity)).toEqual([
      'blocker',
      'critical',
      'major',
      'minor',
      'info',
    ]);
    const one = Math.max(...entries.map((e) => Buffer.byteLength(JSON.stringify(e))));
    const { text, kept } = boundedJson(entries, (x) => x, 3 + 2 * one + 1);
    expect(kept).toBe(2);
    expect((JSON.parse(text) as { severity: string }[]).map((e) => e.severity)).toEqual([
      'blocker',
      'critical',
    ]);
  });

  it('scrubs the analyzers’ secrets from the rule key', () => {
    // Any text an analyzer reported as a secret (a plain one, so the repository's Gitleaks scan
    // has nothing to report here).
    const secret = 'found-by-an-analyzer';
    const report = withFindings([{ ...finding, ruleId: `leak-${secret}` }]);
    const [entry] = codeQualityReport(report, { texts: [secret], unknown: false });
    expect(entry?.check_name).toBe('eslint:leak-«redacted»');
    expect(JSON.stringify(entry)).not.toContain(secret);
    // The fingerprint is still the server's: it hashes the key, it does not show it.
    expect(entry?.fingerprint).toBe(reportFingerprints(report.findings)[0]);
  });

  it('refuses a report path in a missing directory or on a directory', () => {
    const dir = tmp();
    mkdirSync(path.join(dir, 'out'));
    expect(checkReportPath('gitlab-code-quality', dir, 'out/cq.json')).toBe(
      path.join(dir, 'out', 'cq.json'),
    );
    const check = (file: string) => usage(() => checkReportPath('gitlab-code-quality', dir, file));
    expect(check('missing/cq.json')).toBe(
      '2: --gitlab-code-quality missing/cq.json: its directory does not exist',
    );
    expect(check('out')).toBe('2: --gitlab-code-quality out: is a directory');
  });
});

describe('writing a GitLab report file', () => {
  it('refuses a path outside the working directory, also through a linked directory', () => {
    const outside = tmp();
    const dir = tmp();
    symlinkSync(outside, path.join(dir, 'linked'), 'junction');
    mkdirSync(path.join(dir, 'real'));
    const check = (file: string) => usage(() => checkReportPath('gitlab-sast', dir, file));
    expect(check('../sast.json')).toBe(
      '2: --gitlab-sast ../sast.json: is outside the working directory',
    );
    expect(check(path.join(outside, 'sast.json'))).toMatch(/is outside the working directory$/);
    expect(check('linked/sast.json')).toBe(
      '2: --gitlab-sast linked/sast.json: is outside the working directory',
    );
    // A link at the file's own place is never followed, wherever it points.
    symlinkSync(path.join(dir, 'real'), path.join(dir, 'here.json'), 'junction');
    expect(check('here.json')).toBe('2: --gitlab-sast here.json: is a symbolic link');
    expect(check('real/sast.json')).toBe('no error');
  });

  it.skipIf(!CAN_SYMLINK_FILES)('refuses a file symlink, even one pointing inside', () => {
    const dir = tmp();
    writeFileSync(path.join(dir, 'target.json'), '[]');
    symlinkSync(path.join(dir, 'target.json'), path.join(dir, 'cq.json'), 'file');
    expect(usage(() => checkReportPath('gitlab-code-quality', dir, 'cq.json'))).toBe(
      '2: --gitlab-code-quality cq.json: is a symbolic link',
    );
    expect(readFileSync(path.join(dir, 'target.json'), 'utf8')).toBe('[]');
  });

  it('replaces the file atomically through a temporary file it removes', async () => {
    const dir = tmp();
    writeFileSync(path.join(dir, 'cq.json'), 'old');
    const written = await writeGitLabReport(
      'gitlab-code-quality',
      dir,
      'cq.json',
      [1, 2],
      (x) => x,
    );
    expect(written).toEqual({
      target: path.join(dir, 'cq.json'),
      bytes: 6,
      kept: 2,
      dropped: 0,
    });
    expect(readFileSync(path.join(dir, 'cq.json'), 'utf8')).toBe('[1,2]\n');
    expect(readdirSync(dir)).toEqual(['cq.json']);
  });

  it('checks the path again when it writes: a link placed during the scan is refused', async () => {
    const dir = tmp();
    const outside = tmp();
    expect(checkReportPath('gitlab-sast', dir, 'sast.json')).toBe(path.join(dir, 'sast.json'));
    symlinkSync(outside, path.join(dir, 'sast.json'), 'junction');
    expect(
      await usageAsync(() => writeGitLabReport('gitlab-sast', dir, 'sast.json', [], (x) => x)),
    ).toBe('2: --gitlab-sast sast.json: is a symbolic link');
    expect(readdirSync(outside)).toEqual([]);
    expect(readdirSync(dir)).toEqual(['sast.json']);
  });

  it('bounds the size: whole entries are left out from the end, the file stays valid', async () => {
    const dir = tmp();
    const items = Array.from({ length: 10 }, (_, i) => ({ n: i, pad: 'x'.repeat(40) }));
    const wrap = (kept: typeof items) => ({ version: '1', vulnerabilities: kept });
    const one = Buffer.byteLength(JSON.stringify(items[0]));
    const shell = Buffer.byteLength(JSON.stringify(wrap([]))) + 1;
    const max = shell + 3 * one + 2 + 5;
    expect(boundedJson(items, wrap, max).kept).toBe(3);
    const written = await writeGitLabReport('gitlab-sast', dir, 's.json', items, wrap, max);
    expect(written).toMatchObject({ kept: 3, dropped: 7 });
    expect(statSync(path.join(dir, 's.json')).size).toBeLessThanOrEqual(max);
    expect(JSON.parse(readFileSync(path.join(dir, 's.json'), 'utf8'))).toEqual(
      wrap(items.slice(0, 3)),
    );
    expect(boundedJson(items, wrap, 1e6)).toMatchObject({ kept: 10 });
    expect(() => boundedJson(items, wrap, shell - 1)).toThrow();
  });
});

describe('GitLab SAST report (scm.md §9)', () => {
  const times = {
    start: new Date('2026-09-22T10:15:00.123Z'),
    end: new Date('2026-09-22T10:16:30Z'),
  };
  const secure = (): Report => {
    const base = makeReport();
    return {
      ...base,
      engines: [
        ...base.engines,
        {
          id: 'semgrep',
          kind: 'builtin',
          version: '1.0.0',
          status: 'ok',
          durationMs: 1,
          rules: [{ id: 'ts-eval', name: 'Eval of user input', quality: 'security', cwe: [95] }],
        },
        {
          id: 'gitleaks',
          kind: 'builtin',
          version: '8.30.1',
          status: 'ok',
          durationMs: 1,
          rules: [],
        },
      ],
      findings: [
        ...base.findings,
        {
          engineId: 'semgrep',
          ruleId: 'ts-eval',
          message: 'eval() of <b>input</b> @all',
          severity: 'high',
          location: { path: 'src/a.ts', startLine: 2, endLine: 4 },
          lineHash: '1'.repeat(32),
          contextHash: '2'.repeat(32),
        },
        {
          engineId: 'gitleaks',
          ruleId: 'generic-api-key',
          message: 'Detected a Generic API Key.',
          location: { path: 'src/a.ts', startLine: 5 },
          lineHash: '3'.repeat(32),
          contextHash: '4'.repeat(32),
        },
        {
          engineId: 'semgrep',
          ruleId: 'ts-eval',
          message: 'file-less',
          location: null,
          lineHash: '5'.repeat(32),
          contextHash: '6'.repeat(32),
        },
      ],
    };
  };
  const uuid = (f: string) =>
    `${f.slice(0, 8)}-${f.slice(8, 12)}-${f.slice(12, 16)}-${f.slice(16, 20)}-${f.slice(20)}`;

  it('pins the vendored schema and its licence by SHA-256', () => {
    const sha = (file: string) => createHash('sha256').update(readFileSync(file)).digest('hex');
    expect(sha(SCHEMA_FILE)).toBe(SCHEMA_SHA256);
    expect(sha(path.join(SCHEMA_DIR, 'LICENSE.md'))).toBe(LICENSE_SHA256);
    expect(readFileSync(path.join(SCHEMA_DIR, 'LICENSE.md'), 'utf8')).toMatch(
      /^MIT License\n\nCopyright \(c\) 2017-present GitLab B\.V\.\n/,
    );
    expect(JSON.parse(readFileSync(SCHEMA_FILE, 'utf8'))).toMatchObject({
      self: { version: SAST_SCHEMA_VERSION },
    });
    expect(SCHEMA_SOURCE_TAG).toBe(`v${SAST_SCHEMA_VERSION}`);
    expect(SAST_SCHEMA_URL).toContain(`/-/raw/${SCHEMA_SOURCE_TAG}/dist/sast-report-format.json`);
  });

  it('writes one vulnerability per located security finding, valid against schema 15.1.4', () => {
    const report = secure();
    const sast = sastReport(report, times);
    const validate = sastValidator();
    expect(validate(sast), JSON.stringify(validate.errors)).toBe(true);
    const fingerprints = reportFingerprints(report.findings);
    expect(sast).toEqual({
      version: '15.1.4',
      schema: SAST_SCHEMA_URL,
      scan: {
        type: 'sast',
        status: 'success',
        start_time: '2026-09-22T10:15:00',
        end_time: '2026-09-22T10:16:30',
        analyzer: { id: 'qualor', name: 'Qualor', version: '0.0.0', vendor: { name: 'Qualor' } },
        scanner: { id: 'qualor', name: 'Qualor', version: '0.0.0', vendor: { name: 'Qualor' } },
      },
      vulnerabilities: [
        {
          id: uuid(fingerprints[2]!),
          name: 'gitleaks:generic-api-key',
          description: '` Detected a Generic API Key. `',
          severity: 'Critical',
          identifiers: [
            {
              type: 'qualor_rule',
              name: 'gitleaks:generic-api-key',
              value: 'gitleaks:generic-api-key',
            },
            {
              type: 'cwe',
              name: 'CWE-798',
              value: '798',
              url: 'https://cwe.mitre.org/data/definitions/798.html',
            },
          ],
          location: { file: 'src/a.ts', start_line: 5, end_line: 5 },
        },
        {
          id: uuid(fingerprints[1]!),
          name: 'Eval of user input',
          description: '` eval() of <b>input</b> @all `',
          severity: 'High',
          identifiers: [
            { type: 'qualor_rule', name: 'semgrep:ts-eval', value: 'semgrep:ts-eval' },
            {
              type: 'cwe',
              name: 'CWE-95',
              value: '95',
              url: 'https://cwe.mitre.org/data/definitions/95.html',
            },
          ],
          location: { file: 'src/a.ts', start_line: 2, end_line: 4 },
        },
      ],
    });
    expect(JSON.stringify(sast)).not.toMatch(/raw_source_code_extract|"links"|"solution"/);
  });

  it('puts a description in a code span GitLab cannot render out of (scm.md §6)', () => {
    const report = secure();
    const message = 'line one\n/merge @all ![x](http://evil) `tick` [l](http://evil)\u202e';
    report.findings[1] = { ...report.findings[1]!, message };
    const description = sastReport(report, times).vulnerabilities.find(
      (v) => v.name === 'Eval of user input',
    )?.description;
    expect(description).toBe(
      '`` line one /merge @all ![x](http://evil) `tick` [l](http://evil)  ``',
    );
  });

  it('gives way to the scrubbed rule key when a rule name holds a secret, or secrets are unknown', () => {
    // Any text an analyzer reported as a secret (a plain one, so the repository's Gitleaks scan
    // has nothing to report here).
    const secret = 'found-by-an-analyzer';
    const report = secure();
    const engines = report.engines.map((e) =>
      e.id === 'semgrep'
        ? {
            ...e,
            rules: [
              { id: 'ts-eval', name: `Uses ${secret}`, quality: 'security' as const },
              { id: `k-${secret}`, name: 'Plain name', quality: 'security' as const },
              { id: 'already', name: 'Was «redacted» here', quality: 'security' as const },
            ],
          }
        : e,
    );
    const extra = (ruleId: string, n: number) => ({
      ...report.findings[1]!,
      ruleId,
      lineHash: String(n).repeat(32),
    });
    const withRules: Report = {
      ...report,
      engines,
      findings: [...report.findings, extra(`k-${secret}`, 7), extra('already', 8)],
    };
    const redaction = { texts: [secret], unknown: false };
    const names = (r: typeof redaction) =>
      sastReport(withRules, times, { redaction: r })
        .vulnerabilities.filter((v) => v.identifiers[0]?.name.startsWith('semgrep:'))
        .map((v) => [v.name, v.identifiers[0]?.value]);
    expect(names(redaction)).toEqual([
      ['semgrep:ts-eval', 'semgrep:ts-eval'],
      ['Plain name', 'semgrep:k-«redacted»'],
      ['semgrep:already', 'semgrep:already'],
    ]);
    expect(JSON.stringify(sastReport(withRules, times, { redaction }))).not.toContain(secret);
    expect(names({ texts: [], unknown: true }).map(([name]) => name)).toEqual([
      'semgrep:ts-eval',
      `semgrep:k-${secret}`,
      'semgrep:already',
    ]);
  });

  it('marks the scan failed, still valid, when an engine did not complete (ruling G6)', () => {
    const sast = sastReport(secure(), times, { incomplete: ['semgrep', 'pmd'] });
    expect(sast.scan.status).toBe('failure');
    expect(sast.scan.messages).toEqual([
      {
        level: 'warn',
        value:
          'not every analyzer completed (semgrep, pmd): findings they would report are missing, not fixed',
      },
    ]);
    const validate = sastValidator();
    expect(validate(sast), JSON.stringify(validate.errors)).toBe(true);
    expect(sastReport(secure(), times, { incomplete: [] }).scan).not.toHaveProperty('messages');
  });

  it('is valid with no finding, and the schema refuses a report without its scan', () => {
    const validate = sastValidator();
    const empty = sastReport({ ...makeReport(), findings: [] }, times);
    expect(empty.vulnerabilities).toEqual([]);
    expect(validate(empty)).toBe(true);
    const broken: Record<string, unknown> = { ...empty };
    delete broken['scan'];
    expect(validate(broken)).toBe(false);
    expect(sastTime(new Date('2026-01-02T03:04:05.999Z'))).toBe('2026-01-02T03:04:05');
  });

  it('cuts a long rule name to the schema bound', () => {
    const report = secure();
    const engines = report.engines.map((e) =>
      e.id === 'semgrep'
        ? { ...e, rules: [{ id: 'ts-eval', name: 'n'.repeat(400), quality: 'security' as const }] }
        : e,
    );
    const sast = sastReport({ ...report, engines }, times);
    const semgrep = sast.vulnerabilities.find((v) => v.identifiers[0]?.name === 'semgrep:ts-eval');
    expect([...semgrep!.name]).toHaveLength(255);
    expect(sastValidator()(sast)).toBe(true);
  });

  it('stays valid when the size bound leaves vulnerabilities out', () => {
    const sast = sastReport(secure(), times);
    const { text, kept } = boundedJson(
      sast.vulnerabilities,
      (vulnerabilities) => ({ ...sast, vulnerabilities }),
      Buffer.byteLength(JSON.stringify({ ...sast, vulnerabilities: [] })) +
        1 +
        Buffer.byteLength(JSON.stringify(sast.vulnerabilities[0])),
    );
    expect(kept).toBe(1);
    expect(sastValidator()(JSON.parse(text))).toBe(true);
  });
});

describe('GitLab Dependency Scanning report (scm.md §9, plan 2B)', () => {
  const times = {
    start: new Date('2026-09-25T10:15:00Z'),
    end: new Date('2026-09-25T10:16:00Z'),
  };
  const DS_SCHEMA_SHA256 = 'c5066215a961ed06fac663a0fb6fcfd3e2725551df9a27d3dd11ec54084042a2';
  const vuln = (
    ruleId: string,
    dependency: Record<string, unknown> | undefined,
    extra: Partial<Report['findings'][number]> = {},
  ): Report['findings'][number] => ({
    engineId: 'trivy',
    ruleId,
    message: `${String(dependency?.['name'])} ${String(dependency?.['version'])}: ${ruleId}`,
    severity: 'blocker',
    location: { path: 'package-lock.json', startLine: 14, endLine: 19 },
    lineHash: '7'.repeat(32),
    contextHash: '7'.repeat(32),
    ...(dependency !== undefined && { properties: { trivySeverity: 'CRITICAL', dependency } }),
    ...extra,
  });
  const deps = (findings: Report['findings']): Report => {
    const base = makeReport();
    return {
      ...base,
      files: [
        ...base.files,
        {
          path: 'package-lock.json',
          language: 'other',
          kind: 'main',
          sha256: 'f'.repeat(64),
          lines: 40,
        },
      ],
      engines: [
        ...base.engines,
        {
          id: 'trivy',
          kind: 'builtin',
          version: '0.74.0',
          status: 'ok',
          durationMs: 1,
          rules: [
            { id: 'CVE-2021-44906', quality: 'security', cwe: [1321] },
            { id: 'GHSA-xvch-5gv4-984h', quality: 'security' },
          ],
        },
      ],
      findings: [...base.findings, ...findings],
    };
  };
  const uuid = (f: string) =>
    `${f.slice(0, 8)}-${f.slice(8, 12)}-${f.slice(12, 16)}-${f.slice(16, 20)}-${f.slice(20)}`;

  it('pins the vendored schema by SHA-256', () => {
    const sha = createHash('sha256')
      .update(readFileSync(DEPENDENCY_SCANNING_SCHEMA_FILE))
      .digest('hex');
    expect(sha).toBe(DS_SCHEMA_SHA256);
    expect(JSON.parse(readFileSync(DEPENDENCY_SCANNING_SCHEMA_FILE, 'utf8'))).toMatchObject({
      self: { version: '15.1.4' },
    });
    expect(DEPENDENCY_SCANNING_SCHEMA_URL).toContain(
      '/-/raw/v15.1.4/dist/dependency-scanning-report-format.json',
    );
  });

  it('writes one vulnerability per located Trivy finding, valid, and keeps them out of SAST', () => {
    const report = deps([
      vuln(
        'CVE-2021-44906',
        { name: 'minimist', version: '1.2.5', fixedVersion: '1.2.6', direct: true },
        {
          message: 'minimist 1.2.5: CVE-2021-44906 minimist: prototype pollution (fixed in 1.2.6)',
        },
      ),
      vuln('GHSA-xvch-5gv4-984h', { name: 'minimist', version: '1.2.5' }, { severity: 'low' }),
      vuln('CVE-2021-44906', { name: 'minimist', version: '1.2.5' }, { location: null }),
    ]);
    const ds = dependencyScanningReport(report, times);
    const validate = dependencyScanningValidator();
    expect(validate(ds), JSON.stringify(validate.errors)).toBe(true);
    const fingerprints = reportFingerprints(report.findings);
    expect(ds).toEqual({
      version: '15.1.4',
      schema: DEPENDENCY_SCANNING_SCHEMA_URL,
      scan: {
        type: 'dependency_scanning',
        status: 'success',
        start_time: '2026-09-25T10:15:00',
        end_time: '2026-09-25T10:16:00',
        analyzer: { id: 'qualor', name: 'Qualor', version: '0.0.0', vendor: { name: 'Qualor' } },
        scanner: { id: 'qualor', name: 'Qualor', version: '0.0.0', vendor: { name: 'Qualor' } },
      },
      vulnerabilities: [
        {
          id: uuid(fingerprints[1]!),
          name: 'CVE-2021-44906',
          description:
            '` minimist 1.2.5: CVE-2021-44906 minimist: prototype pollution (fixed in 1.2.6) `',
          severity: 'Critical',
          identifiers: [
            { type: 'cve', name: 'CVE-2021-44906', value: 'CVE-2021-44906' },
            { type: 'qualor_rule', name: 'trivy:CVE-2021-44906', value: 'trivy:CVE-2021-44906' },
            {
              type: 'cwe',
              name: 'CWE-1321',
              value: '1321',
              url: 'https://cwe.mitre.org/data/definitions/1321.html',
            },
          ],
          location: {
            file: 'package-lock.json',
            dependency: { package: { name: 'minimist' }, version: '1.2.5', direct: true },
          },
        },
        expect.objectContaining({
          name: 'GHSA-xvch-5gv4-984h',
          severity: 'Low',
          identifiers: [
            { type: 'ghsa', name: 'GHSA-xvch-5gv4-984h', value: 'GHSA-xvch-5gv4-984h' },
            {
              type: 'qualor_rule',
              name: 'trivy:GHSA-xvch-5gv4-984h',
              value: 'trivy:GHSA-xvch-5gv4-984h',
            },
          ],
          location: {
            file: 'package-lock.json',
            dependency: { package: { name: 'minimist' }, version: '1.2.5' },
          },
        }),
      ],
    });
    expect(JSON.stringify(ds)).not.toMatch(/"links"|"solution"|"remediations"/);
    // SAST is for the project's own code: the dependency findings are not in it.
    const sast = sastReport(report, times);
    expect(sast.vulnerabilities).toEqual([]);
    expect(sastValidator()(sast)).toBe(true);
    // Code Quality keeps every located finding, a vulnerable dependency too.
    expect(codeQualityReport(report).map((e) => e.check_name)).toEqual([
      'trivy:CVE-2021-44906',
      'eslint:no-console',
      'trivy:GHSA-xvch-5gv4-984h',
    ]);
  });

  it('fails the scan, still valid, when a finding lacks its package or an engine did not complete', () => {
    const report = deps([
      vuln('CVE-2021-44906', { name: 'minimist', version: '1.2.5' }),
      vuln('CVE-2021-44906', undefined),
      vuln('CVE-2021-44906', { name: 'minimist' }),
    ]);
    const ds = dependencyScanningReport(report, times, { incomplete: ['semgrep'] });
    expect(dependencyScanningValidator()(ds)).toBe(true);
    expect(ds.vulnerabilities).toHaveLength(1);
    expect(ds.scan.status).toBe('failure');
    expect(ds.scan.messages).toEqual([
      {
        level: 'warn',
        value:
          'not every analyzer completed (semgrep): findings they would report are missing, not fixed',
      },
      {
        level: 'warn',
        value:
          '2 dependency finding(s) could not be written without their package: they are missing, not fixed',
      },
    ]);
  });

  it('writes package names and versions as plain text and scrubs found secrets from them', () => {
    const report = deps([
      vuln(
        'CVE-2021-44906',
        {
          name: 'evil\n/merge\u202e',
          version: '1.0.0-Zx9Qe4Lr8Tn2Vb7Mk3Hs6Jp1',
        },
        // The normaliser has already scrubbed the message; the package fields come from properties.
        { message: 'evil 1.0.0-«redacted»: CVE-2021-44906' },
      ),
    ]);
    const ds = dependencyScanningReport(report, times, {
      redaction: { texts: ['Zx9Qe4Lr8Tn2Vb7Mk3Hs6Jp1'], unknown: false },
    });
    expect(ds.vulnerabilities[0]!.location.dependency).toEqual({
      package: { name: 'evil /merge ' },
      version: '1.0.0-«redacted»',
    });
    expect(JSON.stringify(ds)).not.toContain('Zx9Qe4Lr8Tn2Vb7Mk3Hs6Jp1');
    expect(dependencyScanningValidator()(ds)).toBe(true);
  });

  it('is valid with no finding', () => {
    const ds = dependencyScanningReport(makeReport(), times);
    expect(ds.vulnerabilities).toEqual([]);
    expect(ds.scan.status).toBe('success');
    expect(dependencyScanningValidator()(ds)).toBe(true);
  });
});
