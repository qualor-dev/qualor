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
        vendorIds: [],
      },
      {
        vulnerabilityId: 'B',
        severity: 'unknown',
        title: null,
        fixedVersion: '2',
        primaryUrl: null,
        publishedAt: null,
        vendorIds: [],
      },
    ]);
  });

  it("reads Trivy's vendor ids, none where the key is missing", () => {
    const log4j = parseTrivyOutput(fixture).get(
      'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
    );
    expect(log4j?.find((m) => m.vulnerabilityId === 'CVE-2021-44228')?.vendorIds).toEqual([
      'GHSA-jfh8-c2jp-5v3q',
    ]);
    const json = JSON.stringify({
      Results: [
        {
          Vulnerabilities: [
            { VulnerabilityID: 'NSWG-ECO-516', PkgIdentifier: { PURL: 'pkg:npm/lodash@4.17.15' } },
          ],
        },
      ],
    });
    expect(parseTrivyOutput(json).get('pkg:npm/lodash@4.17.15')?.[0]?.vendorIds).toEqual([]);
  });

  it('keeps the first 16 vendor ids, and only ids that are text of at most 4096 characters', () => {
    const many = Array.from({ length: 20 }, (_, i) => `GHSA-${String(i).padStart(4, '0')}`);
    const of = (VendorIDs: unknown) =>
      parseTrivyOutput(
        JSON.stringify({
          Results: [
            {
              Vulnerabilities: [
                { VulnerabilityID: 'CVE-1', VendorIDs, PkgIdentifier: { PURL: 'pkg:x/a@1' } },
              ],
            },
          ],
        }),
      ).get('pkg:x/a@1')?.[0]?.vendorIds;
    expect(of(many)).toEqual(many.slice(0, 16));
    expect(of([' GO-2021-0238 ', '', 7, null, 'x'.repeat(4097), 'GHSA-p6mc-m468-83gw'])).toEqual([
      'GO-2021-0238',
      'GHSA-p6mc-m468-83gw',
    ]);
    expect(of('GHSA-p6mc-m468-83gw')).toEqual([]);
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
            {
              VulnerabilityID: 'D',
              Severity: 'LOW',
              PkgIdentifier: { PURL: 'pkg:x/e@1', BOMRef: '   ' },
            },
          ],
        },
      ],
    });
    expect([...parseTrivyOutput(json).keys()]).toEqual([
      'pkg:npm/@a/b@1',
      'pkg:x/c@1',
      'pkg:x/d@1',
      'pkg:x/e@1',
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
    if (!r.ok) {
      expect(r.message).toMatch(/work directory/);
      // Not Trivy's answer: the re-check never takes it for a package's fault (R16).
      expect(r.exitCode).toBeUndefined();
    }
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

  it('a stop that arrives while the run is being set up still kills Trivy', async () => {
    // Not aborted at the first look, aborted by the time the listener is added: no event follows.
    let looks = 0;
    const late = {
      get aborted() {
        return ++looks > 1;
      },
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
    } as unknown as AbortSignal;
    const before = workdirs().length;
    const started = Date.now();
    const r = await runner('sleep').run(sbom, os.tmpdir(), late);
    expect(r).toMatchObject({ ok: false, code: 'ABORTED' });
    expect(Date.now() - started).toBeLessThan(5_000);
    expect(workdirs().length).toBe(before);
  });

  it('reports BAD_OUTPUT on garbage, FAILED on a non-zero exit', async () => {
    expect(await runner('garbage').run(sbom, os.tmpdir())).toMatchObject({
      ok: false,
      code: 'BAD_OUTPUT',
    });
    expect(await runner('fail').run(sbom, os.tmpdir())).toMatchObject({
      ok: false,
      code: 'FAILED',
      // Trivy itself ran and failed: what the re-check may judge by its stderr (R16).
      exitCode: 1,
      stderr: expect.stringContaining('FATAL fake failure') as unknown,
    });
  });

  it('reports TOO_LARGE, unread, when the output exceeds the cap', async () => {
    const r = await createTrivyRunner({
      command: [process.execPath, fake, 'ok'],
      workDir: base,
      timeoutMs: 20_000,
      maxOutputBytes: 10,
    }).run(sbom, os.tmpdir());
    expect(r).toMatchObject({ ok: false, code: 'TOO_LARGE' });
  });

  it('kills Trivy as soon as its output passes the cap', async () => {
    const before = workdirs().length;
    const started = Date.now();
    const r = await createTrivyRunner({
      command: [process.execPath, fake, 'flood'],
      workDir: base,
      timeoutMs: 20_000,
      maxOutputBytes: 1024,
    }).run(sbom, os.tmpdir());
    expect(r).toMatchObject({ ok: false, code: 'TOO_LARGE' });
    expect(Date.now() - started).toBeLessThan(5_000);
    expect(workdirs().length).toBe(before);
  });

  it('answers FAILED, not a rejection, when spawn throws', async () => {
    const before = workdirs().length;
    // A NUL byte in an argument makes spawn throw synchronously.
    const r = await runner('ok').run(sbom, 'a\u0000b');
    expect(r).toMatchObject({ ok: false, code: 'FAILED' });
    expect(workdirs().length).toBe(before);
  });

  it.skipIf(process.platform === 'win32')(
    'answers FAILED for a Trivy that is not executable',
    async () => {
      const file = path.join(base, 'not-executable');
      writeFileSync(file, '#!/bin/sh\n', { mode: 0o644 });
      const r = await createTrivyRunner({
        command: [file],
        workDir: base,
        timeoutMs: 5000,
        maxOutputBytes: 1000,
      }).run(sbom, os.tmpdir());
      rmSync(file);
      expect(r).toMatchObject({ ok: false, code: 'FAILED', message: 'Trivy is not executable' });
    },
  );
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
