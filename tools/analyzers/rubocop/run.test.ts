import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
// @ts-expect-error: a plain ES module of the repository's tooling, without type declarations
import { ALLOWED, dependenciesText, gemspecLicences } from './licences.mjs';

const DIR = '/opt/qualor/rubocop';
const RUBY = path.join(DIR, 'ruby', 'bin', 'ruby');
const installed = existsSync(path.join(DIR, 'run.rb')) && existsSync(RUBY);
const require = process.env['QUALOR_REQUIRE_ANALYZERS'] === '1';
const pin = (name: string) =>
  new RegExp(`^${name}=(.+)$`, 'm').exec(
    readFileSync('tools/analyzers/install-rubocop.sh', 'utf8'),
  )?.[1];

function run(args: string[], cwd: string, env: NodeJS.ProcessEnv = {}) {
  return spawnSync(RUBY, [path.join(DIR, 'run.rb'), ...args], {
    cwd,
    encoding: 'utf8',
    timeout: 120_000,
    env: { PATH: '/usr/bin:/bin', HOME: cwd, LC_ALL: 'C.UTF-8', ...env },
  });
}

describe('licences.mjs', () => {
  it('reads the licence ids of an installed gemspec', () => {
    expect(gemspecLicences('  s.licenses = ["Ruby".freeze, "BSD-2-Clause".freeze]\n')).toEqual([
      'Ruby',
      'BSD-2-Clause',
    ]);
    expect(gemspecLicences('  s.license = "MIT"\n')).toEqual(['MIT']);
    expect(gemspecLicences('  s.name = "x"\n')).toEqual([]);
    expect([...ALLOWED].sort()).toEqual(['BSD-2-Clause', 'MIT', 'Ruby']);
  });
});

describe.runIf(installed || require)('the installed RuboCop pass (plan 9B)', () => {
  it('reports the pinned versions, and VERSION says the same', () => {
    const want = `rubocop ${pin('RUBOCOP_VERSION')} ruby ${pin('RUBY_VERSION')}`;
    expect(run(['--version'], os.tmpdir()).stdout.trim()).toBe(want);
    expect(readFileSync(path.join(DIR, 'VERSION'), 'utf8').trim()).toBe(want);
  });

  it('prints the cop table', () => {
    const r = run(['--cops'], os.tmpdir());
    expect(r.status).toBe(0);
    const t = JSON.parse(r.stdout) as {
      version: string;
      targetRubies: string[];
      cops: Record<string, string>;
    };
    expect(t.version).toBe(pin('RUBOCOP_VERSION'));
    expect(t.targetRubies).toContain('4.0');
    expect(t.cops['Lint/UselessAssignment']).toBe('enabled');
    expect(Object.keys(t.cops).length).toBeGreaterThan(500);
  });

  it('refuses a bad command line and a .rubocop options file, and ignores RUBOCOP_OPTS', () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'rubocop-run-'));
    expect(run(['x'], dir).status).toBe(2);
    writeFileSync(path.join(dir, 'a.rb'), 'def f\n  y = 2\nend\n');
    writeFileSync(path.join(dir, 'list.txt'), 'a.rb\n');
    writeFileSync(
      path.join(dir, 'c.yml'),
      'AllCops:\n  DisabledByDefault: true\n  NewCops: disable\n  SuggestExtensions: false\nLint/UselessAssignment:\n  Enabled: true\n',
    );
    writeFileSync(
      path.join(dir, 'evil.rb'),
      `File.write(${JSON.stringify(path.join(dir, 'ran-opts'))}, "x")\n`,
    );
    const out = path.join(dir, 'out.json');
    const ok = run(['c.yml', 'list.txt', out, path.join(dir, 'cache')], dir, {
      RUBOCOP_OPTS: `--require ${path.join(dir, 'evil.rb')}`,
    });
    expect(ok.status, ok.stderr).toBe(1);
    expect(existsSync(path.join(dir, 'ran-opts'))).toBe(false);
    expect(readFileSync(out, 'utf8')).toContain('Lint/UselessAssignment');
    writeFileSync(path.join(dir, '.rubocop'), `--require ${path.join(dir, 'evil.rb')}\n`);
    const refused = run(['c.yml', 'list.txt', out, path.join(dir, 'cache')], dir);
    expect(refused.status).toBe(2);
    expect(refused.stderr).toContain('rubocop: fatal: a .rubocop options file');
    expect(existsSync(path.join(dir, 'ran-opts'))).toBe(false);
  });

  it('keeps only racc of the bundled gems, and no default json', () => {
    const specs = path.join(
      DIR,
      'ruby/lib/ruby/gems',
      readdirSync(path.join(DIR, 'ruby/lib/ruby/gems'))[0]!,
      'specifications',
    );
    expect(readdirSync(specs).filter((f) => f.endsWith('.gemspec'))).toEqual([
      expect.stringMatching(/^racc-/),
    ]);
    expect(readdirSync(path.join(specs, 'default')).some((f) => f.startsWith('json-'))).toBe(false);
  });

  it('matches the committed licence files', () => {
    expect(readFileSync('deploy/scanner/licenses/RUBOCOP-DEPENDENCIES.txt', 'utf8')).toBe(
      dependenciesText(DIR),
    );
    for (const [file, committed] of [
      ['COPYING', 'RUBY-COPYING.txt'],
      ['BSDL', 'RUBY-BSDL.txt'],
      ['LEGAL', 'RUBY-LEGAL.txt'],
    ] as const) {
      expect(readFileSync(`deploy/scanner/licenses/${committed}`, 'utf8'), committed).toBe(
        readFileSync(path.join(DIR, 'licenses', file), 'utf8'),
      );
    }
  });
});
