import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { buildSbom } from './sbom';
import { createTrivyRunner, parseTrivyOutput, removeStaleWorkDirs } from './trivy';

const here = path.dirname(fileURLToPath(import.meta.url));
const fake = path.resolve(here, '../../test/fake-trivy.mjs');
const fixture = readFileSync(path.join(here, '__fixtures__/trivy-sbom-output.json'), 'utf8');
const sbom = buildSbom([{ purl: 'pkg:npm/lodash@4.17.20', name: 'lodash', version: '4.17.20' }]);

/** This file's own QUALOR_VULNDB_DIR: the runs' work directories go below it. */
const base = mkdtempSync(path.join(os.tmpdir(), 'qualor-trivy-test-'));
afterAll(() => rmSync(base, { recursive: true, force: true }));

const runner = (mode: string, timeoutMs = 20_000) =>
  createTrivyRunner({
    command: [process.execPath, fake, mode],
    workDir: base,
    timeoutMs,
    maxOutputBytes: 1024 * 1024,
  });

const workdirs = () => readdirSync(base).filter((n) => n.startsWith('work-'));

describe('parseTrivyOutput', () => {
  it('keys vulnerabilities by purl', () => {
    const map = parseTrivyOutput(fixture);
    expect(map.size).toBeGreaterThanOrEqual(2);
    const lodash = map.get('pkg:npm/lodash@4.17.20');
    expect(lodash?.length).toBeGreaterThan(1);
    const v = lodash?.[0];
    expect(v?.vulnerabilityId).toMatch(/^(CVE|GHSA)-/);
    expect(['critical', 'high', 'medium', 'low', 'unknown']).toContain(v?.severity);
    expect(v?.publishedAt === null || !Number.isNaN(Date.parse(v?.publishedAt ?? ''))).toBe(true);
    expect([...map.values()].some((l) => l.some((m) => m.fixedVersion !== null))).toBe(true);
    expect([...map.values()].some((l) => l.some((m) => m.primaryUrl !== null))).toBe(true);
  });

  it('maps severity and nulls', () => {
    const json = JSON.stringify({
      Results: [
        {
          Vulnerabilities: [
            { VulnerabilityID: 'A', Severity: 'UNKNOWN', PkgIdentifier: { PURL: 'pkg:x/a@1' } },
            {
              VulnerabilityID: 'B',
              Severity: 'WEIRD',
              FixedVersion: '2',
              PkgIdentifier: { PURL: 'pkg:x/a@1' },
            },
            { VulnerabilityID: 'C', Severity: 'HIGH' },
          ],
        },
        {},
      ],
    });
    expect(parseTrivyOutput(json).get('pkg:x/a@1')).toEqual([
      {
        vulnerabilityId: 'A',
        severity: 'unknown',
        title: null,
        fixedVersion: null,
        primaryUrl: null,
        publishedAt: null,
      },
      {
        vulnerabilityId: 'B',
        severity: 'unknown',
        title: null,
        fixedVersion: '2',
        primaryUrl: null,
        publishedAt: null,
      },
    ]);
  });

  it('keys by the bom-ref and falls back to the purl', () => {
    const json = JSON.stringify({
      Results: [
        {
          Vulnerabilities: [
            {
              VulnerabilityID: 'A',
              Severity: 'LOW',
              PkgIdentifier: { PURL: 'pkg:npm/%40a/b@1', BOMRef: 'pkg:npm/@a/b@1' },
            },
            { VulnerabilityID: 'B', Severity: 'LOW', PkgIdentifier: { PURL: 'pkg:x/c@1' } },
            {
              VulnerabilityID: 'C',
              Severity: 'LOW',
              PkgIdentifier: { PURL: 'pkg:x/d@1', BOMRef: '' },
            },
          ],
        },
      ],
    });
    expect([...parseTrivyOutput(json).keys()]).toEqual([
      'pkg:npm/@a/b@1',
      'pkg:x/c@1',
      'pkg:x/d@1',
    ]);
  });

  it('gives an empty map when there are no results, and throws on garbage', () => {
    expect(parseTrivyOutput('{"SchemaVersion":2}').size).toBe(0);
    expect(() => parseTrivyOutput('not json')).toThrow();
  });
});

describe('createTrivyRunner', () => {
  it('runs the fake and parses its output', async () => {
    const before = workdirs().length;
    const r = await runner('ok').run(sbom, os.tmpdir());
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.matches.get('pkg:npm/lodash@4.17.20')?.length).toBeGreaterThan(0);
    expect(workdirs().length).toBe(before);
  });

  it('passes the offline flags, a minimal env and the cache dir', async () => {
    const r = await runner('echo').run(sbom, '/some/cache');
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const seen = JSON.parse(r.matches.get('echo')?.[0]?.title ?? '{}');
    expect(seen.args[0]).toBe('sbom');
    for (const f of [
      '--skip-db-update',
      '--skip-java-db-update',
      '--offline-scan',
      '--disable-telemetry',
      '--skip-version-check',
      '--quiet',
    ])
      expect(seen.args).toContain(f);
    expect(seen.args[seen.args.indexOf('--cache-dir') + 1]).toBe('/some/cache');
    expect(seen.args[seen.args.indexOf('--scanners') + 1]).toBe('vuln');
    expect(seen.inputIsSbom).toBe(true);
    const keys = Object.keys(seen.env).map((k) => k.toUpperCase());
    // Windows adds its own variables (SystemRoot, TEMP, ...) to every child; elsewhere it is exact.
    if (process.platform === 'win32')
      expect(keys).toEqual(expect.arrayContaining(['HOME', 'PATH', 'TMPDIR']));
    else expect(keys.sort()).toEqual(['HOME', 'PATH', 'TMPDIR']);
    expect(seen.env.HOME).toBe(seen.env.TMPDIR);
    // The run's work directory: work-<12 hex> below the base directory, gone after the run.
    expect(path.dirname(seen.env.HOME)).toBe(base);
    expect(path.basename(seen.env.HOME)).toMatch(/^work-[0-9a-f]{12}$/);
    expect(workdirs()).toEqual([]);
  });

  it('reports FAILED when its work directory cannot be created', async () => {
    const file = path.join(base, 'a-file');
    writeFileSync(file, 'x');
    const r = await createTrivyRunner({
      command: [process.execPath, fake, 'ok'],
      workDir: path.join(file, 'sub'),
      timeoutMs: 20_000,
      maxOutputBytes: 1024 * 1024,
    }).run(sbom, os.tmpdir());
    expect(r).toMatchObject({ ok: false, code: 'FAILED' });
    if (!r.ok) expect(r.message).toMatch(/work directory/);
    rmSync(file);
  });

  it('reports NOT_INSTALLED for a missing binary', async () => {
    const r = await createTrivyRunner({
      command: [path.join(os.tmpdir(), 'no-such-trivy-binary')],
      workDir: base,
      timeoutMs: 5000,
      maxOutputBytes: 1000,
    }).run(sbom, os.tmpdir());
    expect(r).toMatchObject({ ok: false, code: 'NOT_INSTALLED' });
  });

  it('reports TIMEOUT and cleans up', async () => {
    const before = workdirs().length;
    const r = await runner('sleep', 100).run(sbom, os.tmpdir());
    expect(r).toMatchObject({ ok: false, code: 'TIMEOUT' });
    expect(workdirs().length).toBe(before);
  });

  it('a stop kills the run at once and cleans up', async () => {
    const before = workdirs().length;
    const stop = new AbortController();
    setTimeout(() => stop.abort(), 300);
    const started = Date.now();
    const r = await runner('sleep').run(sbom, os.tmpdir(), stop.signal);
    expect(r).toMatchObject({ ok: false, code: 'ABORTED' });
    expect(Date.now() - started).toBeLessThan(5_000);
    expect(workdirs().length).toBe(before);
    // Already stopped: Trivy is not started.
    expect(await runner('ok').run(sbom, os.tmpdir(), stop.signal)).toMatchObject({
      ok: false,
      code: 'ABORTED',
    });
  });

  it('reports BAD_OUTPUT on garbage, FAILED on a non-zero exit', async () => {
    expect(await runner('garbage').run(sbom, os.tmpdir())).toMatchObject({
      ok: false,
      code: 'BAD_OUTPUT',
    });
    expect(await runner('fail').run(sbom, os.tmpdir())).toMatchObject({
      ok: false,
      code: 'FAILED',
    });
  });

  it('reports BAD_OUTPUT when the output exceeds the cap', async () => {
    const r = await createTrivyRunner({
      command: [process.execPath, fake, 'ok'],
      workDir: base,
      timeoutMs: 20_000,
      maxOutputBytes: 10,
    }).run(sbom, os.tmpdir());
    expect(r).toMatchObject({ ok: false, code: 'BAD_OUTPUT' });
  });
});

describe('removeStaleWorkDirs', () => {
  it('removes only work-<12 hex> directories', async () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'qualor-trivy-stale-'));
    try {
      for (const name of ['work-0123456789ab', 'work-ffffffffffff', 'work-xyz', 'other']) {
        mkdirSync(path.join(dir, name, 'nested'), { recursive: true });
      }
      writeFileSync(path.join(dir, 'work-aaaaaaaaaaaa'), 'a file, not ours');
      await removeStaleWorkDirs(dir);
      expect(readdirSync(dir).sort()).toEqual(['other', 'work-aaaaaaaaaaaa', 'work-xyz']);
      // A directory that does not exist is no problem.
      await removeStaleWorkDirs(path.join(dir, 'missing'));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
