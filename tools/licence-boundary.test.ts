import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { REPO_ROOT } from './deploy/stack';

const read = (p: string) => readFileSync(path.join(REPO_ROOT, p), 'utf8');
const tracked = (...patterns: string[]): string[] =>
  execFileSync('git', ['ls-files', '--', ...patterns], { cwd: REPO_ROOT, encoding: 'utf8' })
    .split('\n')
    .filter((p) => p !== '');

/** The SPDX id of the enterprise licence (enterprise.md §13); spelled in two parts so this file is not a hit. */
const ENTERPRISE_ID = ['LicenseRef', 'Qualor-Enterprise'].join('-');

describe('the licence boundary (AGENTS.md rule 8, enterprise.md §16)', () => {
  it('keeps every package outside enterprise/ MIT', () => {
    const manifests = tracked('*package.json')
      .filter((p) => !p.startsWith('enterprise/') && !p.startsWith('fixtures/'))
      // Analyzer test data (copies of fixtures/ projects) is not a Qualor package.
      .filter((p) => !p.startsWith('cli/test/analyzer-output/'));
    expect(manifests).toEqual(
      expect.arrayContaining([
        'package.json',
        'cli/package.json',
        'server/package.json',
        'ui/package.json',
        'packages/shared/package.json',
      ]),
    );
    for (const m of manifests) expect(JSON.parse(read(m)).license, m).toBe('MIT');
    expect(read('LICENSE')).toMatch(/^MIT License/);
  });

  it('gives enterprise/ its own licence, titled with no draft banner (enterprise.md §1.5, §16)', () => {
    expect(JSON.parse(read('enterprise/package.json')).license).toBe(ENTERPRISE_ID);
    const text = read('enterprise/LICENSE');
    expect(text.split('\n')[0]).toBe('Qualor Enterprise Licence');
    expect(text).not.toMatch(/draft|not final/i);
    expect(text).not.toMatch(/PLACEHOLDER/);
    expect(text).toMatch(/Source-available, not open source/);
    expect(text).toMatch(/Everything outside enterprise\/ is licensed under the MIT licence/);
    expect(text).toMatch(/development and testing/);
    expect(text).toMatch(/production/i);
    expect(text).toMatch(/licence key/);
  });

  it('matches the product decisions: one image, inert without a key, grace, no organisation limit', () => {
    const text = read('enterprise/LICENSE').replace(/\s+/g, ' ');
    // One image: carrying, running, building and mirroring it unused is not use of the Software.
    expect(text).toMatch(
      /While no licence key is configured and the server does not load the Software, possessing it, running Qualor, building Qualor from unmodified source, and mirroring or redistributing the unmodified Software is not use of the Software/,
    );
    // Forks and mirrors may carry it.
    expect(text).toMatch(/complete copy of the Qualor repository \(a fork/);
    expect(text).toMatch(/\(a mirror\)/);
    expect(text).not.toMatch(/except as part of an unmodified release/);
    // Production use is what the key enables: features and validity with grace; no organisation
    // limit and nothing read-only (enterprise.md §1.3).
    expect(text).toMatch(/Production use is limited to what that key enables/);
    expect(text).not.toMatch(/number of organisations|read-only/);
    expect(text).toMatch(/14-day grace period/);
    // The README says the same.
    const readme = read('enterprise/README.md').replace(/\s+/g, ' ');
    expect(readme).toMatch(/only while a licence key is valid, including its 14-day grace period/);
    expect(readme).toMatch(/fork of this repository or a mirror/);
    expect(readme).toMatch(/enables: its features and its validity, grace period included/);
    expect(readme).not.toMatch(/organisation limit|read-only/);
  });

  it('marks every enterprise source file with its licence', () => {
    const files = tracked('enterprise').filter((p) => /\.(?:[cm]?[jt]s|tsx|jsx)$/.test(p));
    expect(files).toEqual(
      expect.arrayContaining([
        'enterprise/src/plugin.ts',
        'enterprise/scripts/bundle.ts',
        'enterprise/test/enterprise.db.test.ts',
      ]),
    );
    for (const f of files) {
      expect(read(f), f).toMatch(new RegExp(`^// SPDX-License-Identifier: ${ENTERPRISE_ID}\n`));
    }
  });

  it('uses the enterprise licence id only in enterprise/ and the docs', () => {
    const hits = execFileSync('git', ['grep', '-l', '-F', ENTERPRISE_ID], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
    })
      .split('\n')
      .filter((p) => p !== '');
    expect(hits).toContain('enterprise/package.json');
    expect(hits.filter((p) => !p.startsWith('enterprise/') && !p.startsWith('docs/'))).toEqual([]);
  });
});
