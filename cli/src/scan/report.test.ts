import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { gunzipSync } from 'node:zlib';
import { parseConfig, REPORT_BOUNDS, reportSchema, type Report } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { useTempDirs } from '../../test/tmp';
import type { FileCoverage } from '../coverage/model';
import { CliError } from '../errors';
import { VERSION } from '../index';
import type { ScmResolution } from '../git/scm';
import { Warnings } from '../warnings';
import type { AnalyzedFile } from './analyze-files';
import {
  assembleReport,
  reportJsonChunks,
  scrubRuleIds,
  scrubSecretValues,
  validateReport,
  withPrivateReportFile,
  writeReport,
} from './report';

const tmp = useTempDirs();
const SHA = 'a'.repeat(64);

function parts(files: AnalyzedFile[]) {
  const scm: ScmResolution = {
    scm: {
      provider: 'none',
      revision: 'b'.repeat(40),
      branch: 'feature',
      mainBranch: 'main',
      mergeRequest: null,
      baseline: { revision: 'c'.repeat(40), kind: 'merge_base', status: 'ok' },
      renames: [],
    },
    newLines: (p) => (p === 'src/a.ts' ? [[2, 3]] : 'all'),
  };
  const warnings = new Warnings();
  warnings.add('FILE_TOO_LARGE', 'big');
  return {
    config: parseConfig({ version: 1, project: { key: 'acme/payments-api', version: '' } }),
    projectKey: 'acme/payments-api',
    scm,
    analysisDate: new Date('2026-09-23T10:15:00.000Z'),
    files,
    coverage: new Map<string, FileCoverage>([
      ['src/a.ts', { covered: [[1, 2]], uncovered: [], branches: [] }],
    ]),
    duplications: [],
    engines: { engines: [], findings: [], warnings: [] },
    warnings,
  };
}

const file = (p: string, extra: Partial<AnalyzedFile> = {}): AnalyzedFile => ({
  file: {
    path: p,
    absPath: `/x/${p}`,
    language: 'typescript',
    grammar: 'typescript',
    kind: 'main',
    size: 1,
  },
  sha256: SHA,
  lines: 5,
  ...extra,
});

describe('assembleReport', () => {
  it('builds a schema-valid report with metrics, newLines and coverage', () => {
    const metrics = {
      ncloc: 4,
      commentLines: 0,
      functions: 1,
      classes: 0,
      statements: 2,
      complexity: 1,
      cognitiveComplexity: 0,
    };
    const report = validateReport(
      assembleReport(
        parts([
          file('src/a.ts', { metrics }),
          file('README.md', {
            file: { ...file('README.md').file, language: 'other', grammar: null },
          }),
        ]),
      ),
    );
    expect(report.schemaVersion).toBe(1);
    expect(report.scanner).toEqual({
      name: 'qualor-cli',
      version: VERSION,
      platform: `${process.platform}-${process.arch}`,
    });
    expect(report.project).toEqual({ key: 'acme/payments-api', name: 'payments-api' });
    expect(report.analysisDate).toBe('2026-09-23T10:15:00.000Z');
    expect(report.files).toEqual([
      {
        path: 'src/a.ts',
        language: 'typescript',
        kind: 'main',
        sha256: SHA,
        lines: 5,
        metrics,
        newLines: [[2, 3]],
        coverage: { covered: [[1, 2]], uncovered: [], branches: [] },
      },
      {
        path: 'README.md',
        language: 'other',
        kind: 'main',
        sha256: SHA,
        lines: 5,
        newLines: 'all',
      },
    ]);
    expect(report.warnings).toEqual([{ code: 'FILE_TOO_LARGE', message: 'big', count: 1 }]);
  });

  it('keeps only renames onto reported files, and truncates past the bound with a warning', () => {
    const p = parts([file('src/a.ts')]);
    p.scm.scm.renames = [
      { from: 'src/old.ts', to: 'src/a.ts' },
      { from: 'docs/x.md', to: 'docs/y.md' },
    ];
    expect(assembleReport(p).scm.renames).toEqual([{ from: 'src/old.ts', to: 'src/a.ts' }]);
    expect(assembleReport(p).warnings.map((w) => w.code)).not.toContain('RENAMES_TRUNCATED');

    const many = parts([file('src/a.ts')]);
    many.scm.scm.renames = Array.from({ length: REPORT_BOUNDS.renames + 5 }, (_, i) => ({
      from: `old/${i}.ts`,
      to: 'src/a.ts',
    }));
    const report = validateReport(assembleReport(many));
    expect(report.scm.renames).toHaveLength(REPORT_BOUNDS.renames);
    expect(report.warnings.find((w) => w.code === 'RENAMES_TRUNCATED')?.message).toContain(
      `5 of ${REPORT_BOUNDS.renames + 5} renames were dropped`,
    );
  });

  it('omits newLines unless the baseline is ok', () => {
    const p = parts([file('src/a.ts')]);
    p.scm.scm.baseline = { revision: null, kind: 'server_baseline', status: 'first_analysis' };
    expect(assembleReport(p).files[0]?.newLines).toBeUndefined();
  });

  it('exits 4 when the report breaks the schema (e.g. duplicate paths)', () => {
    const report = assembleReport(parts([file('src/a.ts'), file('src/a.ts')]));
    let err: unknown;
    try {
      validateReport(report);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(CliError);
    expect((err as CliError).exitCode).toBe(4);
    expect((err as CliError).message).toContain('files.1.path');
  });
});

describe('scrubSecretValues', () => {
  it('replaces every occurrence of a secret (8+ chars) in every string and key, leaving short ones', () => {
    const TOKEN = 'qlr_pat_0123456789';
    const p = parts([file(`src/${TOKEN}.ts`)]);
    p.config = parseConfig({
      version: 1,
      project: { key: 'acme/x', version: `v-${TOKEN}-${TOKEN}` },
    });
    p.warnings.add('FILE_TOO_LARGE', `mentions ${TOKEN}`);
    const report = scrubSecretValues(assembleReport(p), [TOKEN, 'short', null]);
    const json = JSON.stringify(report);
    expect(json).not.toContain(TOKEN);
    expect(report.project.version).toBe('v-«redacted»-«redacted»');
    expect(report.files[0]?.path).toBe('src/«redacted».ts');
    expect(validateReport(report).project.version).toBe('v-«redacted»-«redacted»');
    const untouched = assembleReport(parts([file('src/a.ts')]));
    expect(scrubSecretValues(untouched, ['short', null])).toEqual(untouched);
  });
});

describe('scrubRuleIds (scm.md §6)', () => {
  it('replaces a found secret inside a rule id, in the findings and the rule metadata alike', () => {
    const SECRET = 'found-by-an-analyzer';
    const base = validateReport(assembleReport(parts([file('src/a.ts')])));
    const finding = {
      engineId: 'semgrep',
      ruleId: `custom.leak-${SECRET}`,
      message: 'm',
      location: { path: 'src/a.ts', startLine: 1 },
      lineHash: 'a'.repeat(32),
      contextHash: 'b'.repeat(32),
    };
    const report = {
      ...base,
      engines: [
        {
          id: 'semgrep',
          version: '1',
          status: 'ok' as const,
          rules: [{ id: `custom.leak-${SECRET}` }, { id: 'plain' }],
        },
      ],
      findings: [finding, { ...finding, ruleId: 'plain', message: `keeps ${SECRET}` }],
    } as unknown as typeof base;
    const scrubbed = scrubRuleIds(report, [SECRET, 'short']);
    expect(scrubbed.findings.map((f) => f.ruleId)).toEqual(['custom.leak-«redacted»', 'plain']);
    expect(scrubbed.engines[0]?.rules?.map((r) => r.id)).toEqual([
      'custom.leak-«redacted»',
      'plain',
    ]);
    // Only rule ids: every other field is the redaction's business (report-format.md §7).
    expect(scrubbed.findings[1]?.message).toBe(`keeps ${SECRET}`);
    expect(scrubRuleIds(report, ['short'])).toBe(report);
  });
});

describe('reportJsonChunks', () => {
  it('streams exactly JSON.stringify(report), in bounded chunks', () => {
    const base = validateReport(assembleReport(parts([file('src/a.ts')])));
    const finding = {
      engineId: 'eslint',
      ruleId: 'no-console',
      message: 'Unexpected console statement.',
      location: { path: 'src/a.ts', startLine: 1 },
      lineHash: 'a'.repeat(32),
      contextHash: 'b'.repeat(32),
    };
    const report = { ...base, findings: Array.from({ length: 5_000 }, () => finding) };
    const chunks = [...reportJsonChunks(report)];
    expect(chunks.join('')).toBe(JSON.stringify(report));
    expect(chunks.length).toBeGreaterThan(5);
    expect(Math.max(...chunks.map((c) => c.length))).toBeLessThan(70 * 1024);
  });

  it('streams engine rules and scm.renames one element at a time too', () => {
    const base = validateReport(assembleReport(parts([file('src/a.ts')])));
    const rule = {
      id: 'no-console',
      name: 'n'.repeat(400),
      shortDescription: 'd'.repeat(2_000),
      tags: ['a', 'b'],
      extra: undefined,
    };
    const engine = { id: 'eslint', kind: 'builtin', status: 'ok', rules: Array(2_000).fill(rule) };
    const report = {
      ...base,
      engines: [engine, { ...engine, id: 'semgrep' }],
      scm: {
        ...base.scm,
        renames: Array.from({ length: 5_000 }, (_, i) => ({ from: `a/${i}.ts`, to: `b/${i}.ts` })),
      },
    } as unknown as Report;
    const chunks = [...reportJsonChunks(report)];
    expect(chunks.join('')).toBe(JSON.stringify(report));
    // One engine alone is about 5 MB of JSON: it must not be one piece.
    expect(Math.max(...chunks.map((c) => c.length))).toBeLessThan(70 * 1024);
  });

  it('matches JSON.stringify for empty arrays, undefined keys and non-ASCII text', () => {
    const base = validateReport(assembleReport(parts([file('src/a.ts')])));
    const report = {
      ...base,
      findings: [],
      duplications: [],
      extra: undefined,
      note: '\u00e9 "q" \u2028 \ud83d\ude00',
    } as unknown as Report;
    expect([...reportJsonChunks(report)].join('')).toBe(JSON.stringify(report));
  });
});

describe('writeReport', () => {
  it('writes gzipped JSON atomically and round-trips', async () => {
    const report = validateReport(assembleReport(parts([file('src/a.ts')])));
    const out = path.join(tmp(), 'nested', 'dir', 'report.json.gz');
    const bytes = await writeReport(report, out);
    const raw = readFileSync(out);
    expect(raw.length).toBe(bytes);
    expect(reportSchema.parse(JSON.parse(gunzipSync(raw).toString('utf8')))).toEqual(report);
    expect(readdirSync(path.dirname(out))).toEqual(['report.json.gz']);
  });

  it('overwrites an existing report and leaves no temporary file', async () => {
    const report = validateReport(assembleReport(parts([file('src/a.ts')])));
    const dir = tmp();
    const out = path.join(dir, 'report.json.gz');
    writeFileSync(out, 'old content');
    await writeReport(report, out);
    expect(reportSchema.parse(JSON.parse(gunzipSync(readFileSync(out)).toString('utf8')))).toEqual(
      report,
    );
    expect(readdirSync(dir)).toEqual(['report.json.gz']);
  });

  it('exits 2 for an --output that is a directory or lies under a file, and leaves no .partial behind', async () => {
    const report = validateReport(assembleReport(parts([file('src/a.ts')])));
    const dir = tmp();
    mkdirSync(path.join(dir, 'is-a-dir'));
    writeFileSync(path.join(dir, 'a-file'), 'x');
    for (const out of [path.join(dir, 'is-a-dir'), path.join(dir, 'a-file', 'report.json.gz')]) {
      const err: unknown = await writeReport(report, out).catch((e: unknown) => e);
      expect(err, out).toBeInstanceOf(CliError);
      expect((err as CliError).exitCode, out).toBe(2);
      expect((err as CliError).message, out).toContain('cannot write the report');
    }
    expect(readdirSync(dir).sort()).toEqual(['a-file', 'is-a-dir']);
    expect(readdirSync(path.join(dir, 'is-a-dir'))).toEqual([]);
  });

  it('removes the partial file when serialisation fails midway (exit 4)', async () => {
    const report = validateReport(assembleReport(parts([file('src/a.ts')])));
    const dir = tmp();
    const out = path.join(dir, 'report.json.gz');
    const bad = { ...report, findings: [{ n: BigInt(1) }] } as unknown as Report;
    const err: unknown = await writeReport(bad, out).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(CliError);
    expect((err as CliError).exitCode).toBe(4);
    expect(readdirSync(dir)).toEqual([]);
  });
});

describe('withPrivateReportFile', () => {
  const report = () => validateReport(assembleReport(parts([file('src/a.ts')])));

  it('writes the report into a fresh private directory and removes it afterwards', async () => {
    const root = tmp();
    let seen: { file: string; size: number } | undefined;
    const result = await withPrivateReportFile(
      report(),
      (f) => {
        seen = f;
        const raw = readFileSync(f.file);
        expect(raw.length).toBe(f.size);
        expect(reportSchema.parse(JSON.parse(gunzipSync(raw).toString('utf8')))).toEqual(report());
        expect(path.dirname(path.dirname(f.file))).toBe(root);
        expect(readdirSync(path.dirname(f.file))).toEqual(['report.json.gz']);
        if (process.platform !== 'win32') {
          expect(statSync(path.dirname(f.file)).mode & 0o777).toBe(0o700);
          expect(statSync(f.file).mode & 0o777).toBe(0o600);
        }
        return Promise.resolve('uploaded');
      },
      { tempRoot: root },
    );
    expect(result).toBe('uploaded');
    expect(seen).toBeDefined();
    expect(existsSync(path.dirname(seen!.file))).toBe(false);
    expect(readdirSync(root)).toEqual([]);
  });

  it('uses a different directory every time', async () => {
    const root = tmp();
    const files: string[] = [];
    for (let i = 0; i < 2; i++) {
      await withPrivateReportFile(
        report(),
        (f) => {
          files.push(f.file);
          return Promise.resolve();
        },
        { tempRoot: root },
      );
    }
    expect(files[0]).not.toBe(files[1]);
  });

  it('removes the directory when the upload fails, and rethrows', async () => {
    const root = tmp();
    const err: unknown = await withPrivateReportFile(
      report(),
      () => Promise.reject(new CliError(4, 'server down')),
      { tempRoot: root },
    ).catch((e: unknown) => e);
    expect(err).toMatchObject({ exitCode: 4, message: 'server down' });
    expect(readdirSync(root)).toEqual([]);
  });

  it('removes the directory when writing the report fails', async () => {
    const root = tmp();
    const bad = { ...report(), findings: [{ n: BigInt(1) }] } as unknown as Report;
    let called = false;
    const err: unknown = await withPrivateReportFile(
      bad,
      () => {
        called = true;
        return Promise.resolve();
      },
      { tempRoot: root },
    ).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(CliError);
    expect(called).toBe(false);
    expect(readdirSync(root)).toEqual([]);
  });

  it('installs SIGINT/SIGTERM (and on POSIX SIGHUP) handlers only while the file exists', async () => {
    const signals = ['SIGINT', 'SIGTERM', 'SIGHUP'] as const;
    const count = () => signals.map((s) => process.listenerCount(s));
    const before = count();
    const extra = process.platform === 'win32' ? [1, 1, 0] : [1, 1, 1];
    await withPrivateReportFile(
      report(),
      () => {
        expect(count()).toEqual(before.map((n, i) => n + extra[i]!));
        return Promise.resolve();
      },
      { tempRoot: tmp() },
    );
    expect(count()).toEqual(before);
  });

  it.runIf(process.platform !== 'win32')(
    'removes the directory when the CLI is interrupted by SIGTERM, SIGINT or SIGHUP (exit 143/130/129)',
    { timeout: 30_000 },
    async () => {
      for (const [signal, code] of [
        ['SIGTERM', 143],
        ['SIGINT', 130],
        ['SIGHUP', 129],
      ] as const) {
        const root = tmp();
        const script = path.join(tmp(), 'hold.mts');
        const reportModule = pathToFileURL(path.join(import.meta.dirname, 'report.ts')).href;
        writeFileSync(
          script,
          `import { withPrivateReportFile } from ${JSON.stringify(reportModule)};\n` +
            `await withPrivateReportFile({ schemaVersion: 1 } as never, (f) => {\n` +
            `  console.log(f.file);\n` +
            `  return new Promise(() => setInterval(() => undefined, 1000));\n` +
            `}, { tempRoot: ${JSON.stringify(root)} });\n`,
        );
        const child = spawn(process.execPath, ['--import', 'tsx', script], {
          cwd: path.join(import.meta.dirname, '..', '..'),
          stdio: ['ignore', 'pipe', 'inherit'],
        });
        const exited = new Promise<number | null>((resolve) => child.on('exit', (c) => resolve(c)));
        const held = await new Promise<string>((resolve, reject) => {
          let out = '';
          child.stdout.on('data', (d: Buffer) => {
            out += d.toString('utf8');
            if (out.includes('\n')) resolve(out.trim());
          });
          void exited.then((c) => reject(new Error(`the child exited early (${String(c)})`)));
        });
        expect(existsSync(held), signal).toBe(true);
        child.kill(signal);
        expect(await exited, signal).toBe(code);
        expect(readdirSync(root), signal).toEqual([]);
      }
    },
  );
});
