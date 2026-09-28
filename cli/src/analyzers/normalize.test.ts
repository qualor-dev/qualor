import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { useTempDirs, writeTree } from '../../test/tmp';
import { silentLogger } from '../log';
import { fileLines, normalizeCaptures } from './normalize';
import type { SarifCapture } from './types';

const LINES: Record<string, string[]> = { 'src/a.ts': ['const a = 1;', 'console.log(a);'] };
const opts = {
  repoRoot: '/repo',
  readLines: (p: string) => LINES[p] ?? null,
  knownPaths: new Set(['src/a.ts']),
  log: silentLogger,
};

function sarif(uri: string) {
  return {
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: 'ESLint', version: '9.1.0', rules: [{ id: 'no-console' }] } },
        results: [
          {
            ruleId: 'no-console',
            level: 'warning',
            message: { text: 'Unexpected console statement.' },
            locations: [
              { physicalLocation: { artifactLocation: { uri }, region: { startLine: 2 } } },
            ],
          },
        ],
      },
    ],
  };
}

const capture = (extra: Partial<SarifCapture>): SarifCapture => ({
  engineId: 'eslint',
  kind: 'builtin',
  status: 'ok',
  reason: null,
  durationMs: 12.6,
  version: null,
  required: false,
  ...extra,
});

describe('normalizeCaptures', () => {
  it('turns captures into engines and findings', () => {
    const out = normalizeCaptures([capture({ sarif: sarif('src/a.ts') })], opts);
    expect(out.engines).toEqual([
      {
        id: 'eslint',
        kind: 'builtin',
        version: '9.1.0',
        status: 'ok',
        reason: null,
        durationMs: 13,
        rules: [expect.objectContaining({ id: 'no-console' })],
      },
    ]);
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0]).toMatchObject({
      engineId: 'eslint',
      ruleId: 'no-console',
      location: { path: 'src/a.ts', startLine: 2 },
    });
    expect(out.findings[0]?.snippet?.lines).toEqual(['const a = 1;', 'console.log(a);']);
  });

  it('drops an adapter version that does not fit the report, keeping the SARIF one', () => {
    const out = normalizeCaptures(
      [
        capture({ sarif: sarif('src/a.ts'), version: '9'.repeat(200) }),
        capture({ engineId: 'pmd', status: 'skipped', reason: 'x', version: 'v1\u0007' }),
      ],
      opts,
    );
    expect(out.engines.map((e) => e.version)).toEqual(['9.1.0', null]);
  });

  it("puts a capture's database on its engine and its warnings in the report (plan 2B)", () => {
    const database = { name: 'trivy-db', updatedAt: '2026-09-25T06:36:11Z' };
    const stale = { code: 'VULNERABILITY_DB_STALE', message: 'old', count: 1 };
    const out = normalizeCaptures(
      [
        capture({ sarif: sarif('src/a.ts'), database, warnings: [stale] }),
        capture({ engineId: 'pmd', status: 'skipped', reason: 'x' }),
      ],
      opts,
    );
    expect(out.engines.map((e) => e.database)).toEqual([database, undefined]);
    expect(out.engines[1]).not.toHaveProperty('database');
    expect(out.warnings).toEqual([stale]);
  });

  it('adds the capture rule languages to every rule that has none', () => {
    const out = normalizeCaptures(
      [capture({ sarif: sarif('src/a.ts'), ruleLanguages: ['typescript', 'javascript'] })],
      opts,
    );
    expect(out.engines[0]?.rules).toEqual([
      expect.objectContaining({ id: 'no-console', languages: ['typescript', 'javascript'] }),
    ]);
  });

  it('keeps skipped and failed engines without findings, and fails an engine on invalid SARIF', () => {
    const out = normalizeCaptures(
      [
        capture({
          engineId: 'pmd',
          status: 'skipped',
          reason: 'no java files in scope',
          durationMs: 0,
        }),
        capture({ engineId: 'semgrep', sarif: { version: '1.0' } }),
      ],
      opts,
    );
    expect(out.engines.map((e) => [e.id, e.status, e.rules.length])).toEqual([
      ['pmd', 'skipped', 0],
      ['semgrep', 'failed', 0],
    ]);
    expect(out.engines[1]?.reason).toBe('SARIF output does not match SARIF 2.1.0');
    expect(out.findings).toEqual([]);
  });

  it('drops findings outside the analysed files with a warning', () => {
    const out = normalizeCaptures([capture({ sarif: sarif('src/elsewhere.ts') })], opts);
    expect(out.findings).toEqual([]);
    expect(out.warnings).toContainEqual(expect.objectContaining({ code: 'FINDING_OUT_OF_SCOPE' }));
  });

  it('never leaks a fragment of the input into the report when SARIF fails schema validation (fix-round-2 finding 1)', () => {
    const SECRET = 'ghp_SUPERSECRETTOKENVALUE1234567890';
    // A malformed run whose only content is the fake secret: if zod's rejection message were
    // copied into `reason` verbatim, it would very likely quote this string back.
    const out = normalizeCaptures(
      [capture({ engineId: 'semgrep', sarif: { version: '2.1.0', runs: [{ secret: SECRET }] } })],
      opts,
    );
    expect(out.engines[0]?.status).toBe('failed');
    expect(out.engines[0]?.reason).toBe('SARIF output does not match SARIF 2.1.0');
    expect(JSON.stringify(out)).not.toContain(SECRET);
  });

  it('fails only that engine, with a fixed reason, when normalising throws anything else (fix round 2 of tasks 5-6)', () => {
    const SECRET = 'ghp_SUPERSECRETTOKENVALUE1234567890';
    const lines: string[] = [];
    const out = normalizeCaptures(
      [
        capture({ engineId: 'semgrep', sarif: sarif('src/boom.ts') }),
        capture({ sarif: sarif('src/a.ts') }),
      ],
      {
        ...opts,
        knownPaths: new Set(['src/a.ts', 'src/boom.ts']),
        readLines: (p: string) => {
          if (p === 'src/boom.ts') throw new RangeError(`unexpected ${SECRET}`);
          return LINES[p] ?? null;
        },
        log: { ...silentLogger, debug: (m: string) => lines.push(m) },
      },
    );
    expect(out.engines.map((e) => [e.id, e.status, e.reason])).toEqual([
      ['semgrep', 'failed', 'SARIF output could not be normalised'],
      ['eslint', 'ok', null],
    ]);
    expect(out.findings.map((f) => f.engineId)).toEqual(['eslint']);
    expect(JSON.stringify(out)).not.toContain(SECRET);
    expect(lines.join('\n')).toContain('RangeError');
  });
});

describe('normalizeCaptures cross-engine secret redaction (fix-round finding 1)', () => {
  const SECRET = 'SuperSecretLiteral1234567';
  const FILES: Record<string, string[]> = {
    'src/config.ts': [`const secret = "${SECRET}";`],
    'src/other.ts': [`// copy of the same secret: ${SECRET}`],
  };
  const crossOpts = {
    repoRoot: '/repo',
    readLines: (p: string) => FILES[p] ?? null,
    knownPaths: new Set(['src/config.ts', 'src/other.ts']),
    log: silentLogger,
  };

  const gitleaksSarif = () => ({
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: 'gitleaks', rules: [{ id: 'generic-api-key' }] } },
        results: [
          {
            ruleId: 'generic-api-key',
            message: { text: 'secret found' },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: 'src/config.ts' },
                  region: { startLine: 1, snippet: { text: SECRET } },
                },
              },
            ],
          },
        ],
      },
    ],
  });

  const otherSarif = () => ({
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: 'OtherTool', rules: [{ id: 'copy-check' }] } },
        results: [
          {
            ruleId: 'copy-check',
            message: { text: `found a duplicate of ${SECRET} elsewhere` },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: 'src/other.ts' },
                  region: { startLine: 1 },
                },
              },
            ],
          },
        ],
      },
    ],
  });

  it('scrubs a secret literal from another engine’s message and snippet, even in a different file', () => {
    const out = normalizeCaptures(
      [
        capture({ engineId: 'gitleaks', mapping: { redactRegion: true }, sarif: gitleaksSarif() }),
        capture({ engineId: 'other', sarif: otherSarif() }),
      ],
      crossOpts,
    );
    const json = JSON.stringify(out);
    expect(json).not.toContain(SECRET);
    const otherFinding = out.findings.find((f) => f.engineId === 'other');
    expect(otherFinding?.message).not.toContain(SECRET);
    expect(otherFinding?.message).toContain('«redacted»');
    expect(otherFinding?.snippet?.lines.join('\n')).not.toContain(SECRET);
  });

  /** otherSarif with a rule description, properties and a secondary-location message. */
  const detailedOtherSarif = () => {
    const log = otherSarif();
    const run = log.runs[0]!;
    return {
      ...log,
      runs: [
        {
          tool: {
            driver: {
              name: 'OtherTool',
              rules: [{ id: 'copy-check', shortDescription: { text: 'Duplicated literal' } }],
            },
          },
          results: run.results.map((r) => ({
            ...r,
            properties: { note: `copy: ${SECRET}` },
            partialFingerprints: { hash: 'abc' },
            relatedLocations: [
              { ...r.locations[0], message: { text: `the other copy of ${SECRET}` } },
            ],
          })),
        },
      ],
    };
  };

  it('fails closed when a secret engine cannot be normalised: no other engine keeps a snippet or its own message text', () => {
    const warnings: string[] = [];
    const broken = { version: '2.1.0', runs: [{ secret: SECRET }] };
    const out = normalizeCaptures(
      [
        capture({ engineId: 'gitleaks', mapping: { redactRegion: true }, sarif: broken }),
        capture({ engineId: 'other', sarif: detailedOtherSarif() }),
      ],
      { ...crossOpts, log: { ...silentLogger, warn: (m: string) => warnings.push(m) } },
    );
    expect(out.engines.map((e) => [e.id, e.status])).toEqual([
      ['gitleaks', 'failed'],
      ['other', 'ok'],
    ]);
    const finding = out.findings[0]!;
    expect(finding.message).toBe('Duplicated literal');
    expect(finding).not.toHaveProperty('snippet');
    expect(finding).not.toHaveProperty('properties');
    expect(finding).not.toHaveProperty('partialFingerprints');
    expect(finding.location).toMatchObject({ path: 'src/other.ts', startLine: 1 });
    expect(finding.secondaryLocations).toEqual([
      { path: 'src/other.ts', startLine: 1, endLine: 1 },
    ]);
    expect(JSON.stringify(out)).not.toContain(SECRET);
    expect(warnings.join('\n')).toContain('gitleaks');
  });

  it('does not fail closed when a failing engine is not a secret engine', () => {
    const out = normalizeCaptures(
      [
        capture({ engineId: 'eslint', sarif: { version: '2.1.0', runs: [{ x: 1 }] } }),
        capture({ engineId: 'other', sarif: detailedOtherSarif() }),
      ],
      crossOpts,
    );
    expect(out.findings[0]?.message).toBe(`found a duplicate of ${SECRET} elsewhere`);
    expect(out.findings[0]?.snippet).toBeDefined();
  });
});

/**
 * A *file* symlink (unlike a directory junction) needs Developer Mode or elevation on Windows.
 * Probing once lets the file-symlink test below run wherever the platform actually allows it and
 * skip only where it does not, instead of assuming based on `process.platform` alone (same
 * pattern as `cli/src/discovery/discover.test.ts` and `cli/src/analyzers/external.test.ts`).
 */
function canCreateFileSymlinks(): boolean {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'qualor-symlink-check-'));
  try {
    const target = path.join(dir, 'target.txt');
    writeFileSync(target, 'x');
    symlinkSync(target, path.join(dir, 'link.txt'), 'file');
    return true;
  } catch {
    return false;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const CAN_SYMLINK_FILES = canCreateFileSymlinks();

describe('fileLines (fix-round-3 finding 1)', () => {
  const tmp = useTempDirs();

  it('reads a normal in-repo file', () => {
    const root = tmp();
    writeTree(root, { 'src/a.ts': 'line1\nline2\n' });
    expect(fileLines(root)('src/a.ts')).toEqual(['line1', 'line2']);
  });

  it('refuses a path through a junction segment, even without special privileges', () => {
    const root = tmp();
    const outside = tmp();
    writeTree(outside, { 'secret.txt': 'outside-secret\n' });
    // A junction needs no privileges on Windows; on Linux the type argument is ignored.
    symlinkSync(outside, path.join(root, 'j'), 'junction');
    expect(fileLines(root)('j/secret.txt')).toBeNull();
  });

  it.skipIf(!CAN_SYMLINK_FILES)('refuses a path whose final segment is a file symlink', () => {
    const root = tmp();
    const outside = tmp();
    writeTree(outside, { 'secret.txt': 'outside-secret\n' });
    symlinkSync(path.join(outside, 'secret.txt'), path.join(root, 'link.txt'), 'file');
    expect(fileLines(root)('link.txt')).toBeNull();
  });

  it('refuses a path whose final segment is a directory (stand-in for a FIFO/device)', () => {
    const root = tmp();
    writeTree(root, { 'a-directory/.keep': '' });
    expect(fileLines(root)('a-directory')).toBeNull();
  });

  it('refuses a file larger than the 1 MiB analysis bound', () => {
    const root = tmp();
    writeTree(root, { 'huge.txt': 'x'.repeat(1024 * 1024 + 1) });
    expect(fileLines(root)('huge.txt')).toBeNull();
  });
});
