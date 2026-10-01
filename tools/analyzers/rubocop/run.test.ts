import { spawnSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  ALLOWED,
  defaultGems,
  dependenciesText,
  gemspecLicences,
  licenceFiles,
  // @ts-expect-error: a plain ES module of the repository's tooling, without type declarations
} from './licences.mjs';

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

  it('lints a listed path with glob characters as that one file, never what it would match', () => {
    // RuboCop globs an explicit path with a `*` (B9-14): `{,/}tmp/…/x*.rb` would reach /tmp and
    // `**` every file below, and a FIFO there would block the run.
    const outside = mkdtempSync(path.join(os.tmpdir(), 'rubocop-outside-'));
    const secret = 'def f\n  secret_value = 2\nend\n';
    mkdirSync(path.join(outside, 'sub'));
    writeFileSync(path.join(outside, 'xsecret.rb'), secret);
    writeFileSync(path.join(outside, 'sub', 'deep.rb'), secret);
    expect(spawnSync('mkfifo', [path.join(outside, 'xfifo.rb')]).status).toBe(0);
    const dir = mkdtempSync(path.join(os.tmpdir(), 'rubocop-run-'));
    const src = path.join(dir, 'src');
    const mirror = `{,/}${outside.slice(1)}`;
    const listed = ['app/a.rb', `${mirror}/x*.rb`, `${mirror}/**/*.rb`, 'g/[ab]?.rb'];
    for (const [i, file] of listed.entries()) {
      mkdirSync(path.dirname(path.join(src, file)), { recursive: true });
      writeFileSync(path.join(src, file), `def g\n  listed${i} = 1\nend\n`);
    }
    writeFileSync(path.join(src, 'g', 'a1.rb'), secret);
    writeFileSync(path.join(dir, 'list.txt'), listed.map((f) => `${f}\n`).join(''));
    writeFileSync(
      path.join(dir, 'c.yml'),
      'AllCops:\n  DisabledByDefault: true\n  NewCops: disable\n  SuggestExtensions: false\n  Exclude: []\nLint/UselessAssignment:\n  Enabled: true\n',
    );
    const out = path.join(dir, 'out.json');
    const r = spawnSync(
      RUBY,
      [
        path.join(DIR, 'run.rb'),
        path.join(dir, 'c.yml'),
        path.join(dir, 'list.txt'),
        out,
        path.join(dir, 'cache'),
      ],
      {
        cwd: src,
        encoding: 'utf8',
        timeout: 60_000,
        env: { PATH: '/usr/bin:/bin', HOME: dir, LC_ALL: 'C.UTF-8' },
      },
    );
    expect(r.error, 'RuboCop blocked (a FIFO outside the copy)').toBeUndefined();
    expect(r.status, r.stderr).toBe(1);
    const report = JSON.parse(readFileSync(out, 'utf8')) as {
      files: { path: string; offenses: { message: string }[] }[];
    };
    expect(report.files.map((f) => f.path).sort()).toEqual([...listed].sort());
    for (const f of report.files)
      expect(f.offenses.map((o) => o.message).join()).not.toContain('secret_value');
    expect(JSON.stringify(report)).toContain('listed1');
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
    const committed = readFileSync('deploy/scanner/licenses/RUBOCOP-DEPENDENCIES.txt', 'utf8');
    expect(committed).toBe(dependenciesText(DIR));
    // B9-15: every default gem of the built Ruby outside Ruby's licence ships its own licence
    // text (prism and syntax_suggest among them), and the committed file carries it.
    const own = (defaultGems(DIR) as { own: { name: string; version: string; dir: string }[] }).own;
    expect(own.map((g) => g.name)).toEqual(expect.arrayContaining(['prism', 'syntax_suggest']));
    for (const g of own) {
      const files = licenceFiles(g.dir) as string[];
      expect(files.length, `${g.name} ${g.version}`).toBeGreaterThan(0);
      expect(committed).toContain(`${g.name} ${g.version} (`);
      for (const f of files) {
        expect(committed).toContain(readFileSync(path.join(g.dir, f), 'utf8').trimEnd());
      }
    }
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
