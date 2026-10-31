import { readFileSync, readdirSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { buildSbom } from './sbom';
import { createTrivyRunner, parseTrivyOutput } from './trivy';

const here = path.dirname(fileURLToPath(import.meta.url));
const fake = path.resolve(here, '../../test/fake-trivy.mjs');
const fixture = readFileSync(path.join(here, '__fixtures__/trivy-sbom-output.json'), 'utf8');
const sbom = buildSbom([{ purl: 'pkg:npm/lodash@4.17.20', name: 'lodash', version: '4.17.20' }]);

const runner = (mode: string, timeoutMs = 20_000) =>
  createTrivyRunner({
    command: [process.execPath, fake, mode],
    timeoutMs,
    maxOutputBytes: 1024 * 1024,
  });

const workdirs = () => readdirSync(os.tmpdir()).filter((n) => n.startsWith('qualor-trivy-'));

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
  });

  it('reports NOT_INSTALLED for a missing binary', async () => {
    const r = await createTrivyRunner({
      command: [path.join(os.tmpdir(), 'no-such-trivy-binary')],
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
      timeoutMs: 20_000,
      maxOutputBytes: 10,
    }).run(sbom, os.tmpdir());
    expect(r).toMatchObject({ ok: false, code: 'BAD_OUTPUT' });
  });
});
