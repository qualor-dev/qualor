import { spawnSync } from 'node:child_process';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import {
  appendFileSync,
  existsSync,
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';

/**
 * Plan 1G: the repository's own `.gitleaks.toml` allows exactly the fake secrets its tests,
 * and fixtures hold, by value, path and rule, and nothing else: a real secret added to one of
 * those files is still found. Runs the real Gitleaks (the pinned
 * one of tools/analyzers/install.sh) over a copy of the tracked files; skipped where Gitleaks is
 * not installed, unless QUALOR_REQUIRE_ANALYZERS=1 (the CI test jobs, plan 1B ruling T4).
 */
// The pinned Gitleaks of tools/analyzers/install.sh lives in /opt/qualor/bin, which is not always
// on PATH (the CI test job); otherwise the one on PATH.
const GITLEAKS = existsSync('/opt/qualor/bin/gitleaks') ? '/opt/qualor/bin/gitleaks' : 'gitleaks';
const installed = spawnSync(GITLEAKS, ['version']).status === 0;
const required = process.env['QUALOR_REQUIRE_ANALYZERS'] === '1';
const work = mkdtempSync(path.join(os.tmpdir(), 'qualor-gitleaks-'));
afterAll(() => rmSync(work, { recursive: true, force: true }));

interface Leak {
  RuleID: string;
  File: string;
}

function trackedCopy(): string {
  const root = mkdtempSync(path.join(work, 'repo-'));
  const ls = spawnSync('git', ['ls-files', '-z'], { encoding: 'utf8' });
  expect(ls.status, ls.stderr).toBe(0);
  const files = ls.stdout.split('\0').filter((f) => f !== '');
  expect(files.length).toBeGreaterThan(100);
  for (const file of files) {
    mkdirSync(path.join(root, path.dirname(file)), { recursive: true });
    copyFileSync(file, path.join(root, file));
  }
  return root;
}

function leaks(root: string): Leak[] {
  const report = path.join(work, 'report.json');
  const r = spawnSync(
    GITLEAKS,
    [
      'dir',
      '.',
      '--config',
      '.gitleaks.toml',
      '--report-format',
      'json',
      '--report-path',
      report,
      '--exit-code',
      '0',
      '--no-banner',
      '--log-level',
      'error',
    ],
    { cwd: root, encoding: 'utf8' },
  );
  expect(r.status, r.stderr).toBe(0);
  return (JSON.parse(readFileSync(report, 'utf8')) as Leak[]).map((l) => ({
    RuleID: l.RuleID,
    File: l.File.split(path.sep).join('/'),
  }));
}

describe.runIf(installed || required)('the repository Gitleaks allowlist', () => {
  it(
    'finds nothing in the repository, and still finds a secret anywhere else',
    { timeout: 120_000 },
    () => {
      const root = trackedCopy();
      expect(leaks(root)).toEqual([]);
      // Built at run time, so this file holds no key itself.
      const key = `AKIA${'QWERTYUIOPASDFGH'}`;
      appendFileSync(path.join(root, 'cli/test/tls.ts'), `export const other = "${key}";\n`);
      writeFileSync(path.join(root, 'cli/src/leak.ts'), `export const key = "${key}";\n`);
      // The llm-prompts fixture's fake key (plan 3B) is allowed in that file only.
      const fixtureKey = readFileSync(
        path.join(root, 'fixtures/llm-prompts/src/compare.ts'),
        'utf8',
      )
        .split('\n')
        .find((l) => l.startsWith('const apiKey'));
      writeFileSync(path.join(root, 'fixtures/llm-prompts/src/other.ts'), `${fixtureKey}\n`);
      // The recorded GitHub installation token (plan 2C) is allowed in its file only; the fake
      // webhook secret of the tests is allowed in no file.
      const ghs = ['ghs', '16C7e42F292c6912E7710c838347Ae178B4a'].join('_');
      const shape = readFileSync(
        path.join(root, 'server/test/github-shapes/installation_token.json'),
        'utf8',
      );
      expect(shape).toContain(ghs);
      writeFileSync(path.join(root, 'server/test/github-shapes/other.json'), shape);
      const whsec = ['whsec-', '0123456789abcdef'].join('');
      writeFileSync(path.join(root, 'server/test/other.ts'), `export const secret = '${whsec}';\n`);
      // A SCIM token (plan 4D): `qlr_scim_` and 32 random base62 characters, built at run time.
      const base62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
      const scim = `qlr_scim_${Array.from(randomBytes(32), (b) => base62.charAt(b % 62)).join('')}`;
      writeFileSync(
        path.join(root, 'server/src/scim/leak.ts'),
        `export const token = '${scim}';\n`,
      );
      // The qualor-token rule finds it with no keyword nearby, too.
      writeFileSync(path.join(root, 'docs/guide/scim-leak.md'), `Paste ${scim} into the IdP.\n`);
      // The allow-listed fake stays allowed in its file; the all-zero test token only in its files.
      const fake = ['qlr_scim_', '0123456789abcdef'].join('');
      appendFileSync(
        path.join(root, 'cli/src/config/settings.test.ts'),
        `export const token = '${fake}';\n`,
      );
      const zero = `qlr_prj_${'0'.repeat(32)}`;
      appendFileSync(
        path.join(root, 'server/test/cli-e2e.db.test.ts'),
        `export const other = '${zero}';\n`,
      );
      writeFileSync(path.join(root, 'docs/guide/zero-token.md'), `Bearer ${zero}\n`);
      expect(leaks(root).sort((a, b) => a.File.localeCompare(b.File))).toEqual([
        { RuleID: 'aws-access-token', File: 'cli/src/leak.ts' },
        { RuleID: 'aws-access-token', File: 'cli/test/tls.ts' },
        { RuleID: 'qualor-token', File: 'docs/guide/scim-leak.md' },
        { RuleID: 'qualor-token', File: 'docs/guide/zero-token.md' },
        { RuleID: 'generic-api-key', File: 'fixtures/llm-prompts/src/other.ts' },
        { RuleID: 'qualor-token', File: 'server/src/scim/leak.ts' },
        { RuleID: 'github-app-token', File: 'server/test/github-shapes/other.json' },
        { RuleID: 'generic-api-key', File: 'server/test/other.ts' },
      ]);
    },
  );

  it(
    'still finds a real secret of an allowed rule in a file that holds allowed fakes',
    { timeout: 120_000 },
    () => {
      const root = trackedCopy();
      // Built at run time, so this file holds none of them itself.
      const aws = `AKIA${'ZXCVBNMLKJHGFDSA'}`;
      const generic = ['Hq7Wm2Rt9Xc4', 'Vb8Nz3Lk6Pd5'].join('');
      const pem = generateKeyPairSync('ec', { namedCurve: 'P-256' })
        .privateKey.export({ type: 'pkcs8', format: 'pem' })
        .toString();
      appendFileSync(
        path.join(root, 'packages/shared/src/sarif/normalize.test.ts'),
        `export const aws = "${aws}";\n`,
      );
      const apiKeyLine = `export const apiKey = "${generic}";\n`;
      appendFileSync(path.join(root, 'server/scripts/e2e/serve.ts'), apiKeyLine);
      appendFileSync(path.join(root, 'cli/src/analyzers/gitleaks.test.ts'), apiKeyLine);
      appendFileSync(path.join(root, 'fixtures/llm-prompts/src/compare.ts'), apiKeyLine);
      appendFileSync(path.join(root, 'cli/test/tls.ts'), `export const other = \`${pem}\`;\n`);
      const found = leaks(root)
        .map((l) => `${l.RuleID} ${l.File}`)
        .sort();
      expect(found).toEqual([
        'generic-api-key cli/src/analyzers/gitleaks.test.ts',
        'generic-api-key fixtures/llm-prompts/src/compare.ts',
        'generic-api-key server/scripts/e2e/serve.ts',
        'aws-access-token packages/shared/src/sarif/normalize.test.ts',
        'private-key cli/test/tls.ts',
      ]);
    },
  );
});
