import { mkdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { parseConfig, RUBOCOP_VERSION, rubocopSelection } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { fakeContext } from '../../test/analyzers';
import { useTempDirs } from '../../test/tmp';
import type { ScopeFile } from '../discovery/discover';
import { createLogger, silentLogger } from '../log';
import { parseRubocopVersion, rubocopAnalyzer, rubocopConfigYaml } from './rubocop';
import { runAnalyzers } from './runner';

const tmp = useTempDirs();
const [MAJOR, MINOR] = RUBOCOP_VERSION.split('.').map(Number) as [number, number];

/** A fake install: the files prepare() checks for, and a VERSION line. */
function install(version = `rubocop ${RUBOCOP_VERSION} ruby 4.0.7`): string {
  const dir = tmp();
  mkdirSync(path.join(dir, 'ruby', 'bin'), { recursive: true });
  writeFileSync(path.join(dir, 'ruby', 'bin', 'ruby'), '');
  writeFileSync(path.join(dir, 'run.rb'), '');
  writeFileSync(path.join(dir, 'VERSION'), `${version}\n`);
  return dir;
}

function repo(files: string[]): { root: string; scope: ScopeFile[] } {
  const root = tmp();
  const scope = files.map((p) => {
    const abs = path.join(root, ...p.split('/'));
    mkdirSync(path.dirname(abs), { recursive: true });
    writeFileSync(abs, 'x = 1\n');
    return {
      path: p,
      absPath: abs,
      language: 'ruby' as const,
      grammar: 'ruby' as const,
      kind: 'main' as const,
      size: 6,
    };
  });
  return { root, scope };
}

describe('rubocopAnalyzer.prepare', () => {
  it('runs Qualor’s runner on a checked copy with Qualor’s configuration only', async () => {
    const dir = install();
    const { root, scope } = repo(['app/a.rb', 'b c/#d.rb', 'Gemfile']);
    const work = tmp();
    const p = await rubocopAnalyzer.prepare({
      ...fakeContext(root, { workDir: work, env: { QUALOR_RUBOCOP_DIR: dir } }),
      files: [...scope, { ...scope[0]!, path: 'README.md', language: 'other', grammar: null }],
    });
    if (!('run' in p)) throw new Error(JSON.stringify(p));
    const input = path.join(work, 'src');
    expect(p.run).toMatchObject({
      command: path.join(dir, 'ruby', 'bin', 'ruby'),
      args: [
        path.join(dir, 'run.rb'),
        path.join(work, 'rubocop.yml'),
        path.join(work, 'rubocop-files.txt'),
        path.join(work, 'rubocop.json'),
        path.join(work, 'rubocop-cache'),
      ],
      cwd: input,
      sarifPath: path.join(work, 'rubocop.json'),
      okExitCodes: [0, 1],
      version: RUBOCOP_VERSION,
    });
    expect(readFileSync(path.join(work, 'rubocop-files.txt'), 'utf8')).toBe(
      'app/a.rb\nb c/#d.rb\nGemfile\n',
    );
    expect(readFileSync(path.join(input, 'b c', '#d.rb'), 'utf8')).toBe('x = 1\n');
    expect(readFileSync(path.join(work, 'rubocop.yml'), 'utf8')).toBe(
      rubocopConfigYaml(rubocopSelection(['qualor-default'], []), '4.0'),
    );
    expect(p.run.env).toMatchObject({
      HOME: work,
      LC_ALL: 'C.UTF-8',
      HTTPS_PROXY: 'http://127.0.0.1:9',
    });
    for (const name of [
      'RUBYOPT',
      'RUBYLIB',
      'GEM_HOME',
      'GEM_PATH',
      'BUNDLE_GEMFILE',
      'RUBOCOP_OPTS',
      'XDG_CONFIG_HOME',
      'CI_JOB_TOKEN',
    ])
      expect(p.run.dropEnv?.(name), name).toBe(true);
    for (const name of ['PATH', 'TMPDIR', 'LANG', 'HOME', 'HTTPS_PROXY'])
      expect(p.run.dropEnv?.(name), name).toBe(false);
  });

  it('writes the project’s selection and target Ruby (a YAML number too)', async () => {
    const dir = install();
    const { root, scope } = repo(['a.rb']);
    const work = tmp();
    const p = await rubocopAnalyzer.prepare({
      ...fakeContext(root, {
        workDir: work,
        env: { QUALOR_RUBOCOP_DIR: dir },
        config: {
          analyzers: {
            rubocop: {
              select: ['qualor-default', 'Style/StringLiterals'],
              ignore: ['Security'],
              targetRubyVersion: 3.3,
            },
          },
        },
      }),
      files: scope,
    });
    if (!('run' in p)) throw new Error(JSON.stringify(p));
    const yaml = readFileSync(path.join(work, 'rubocop.yml'), 'utf8');
    expect(yaml).toContain('  TargetRubyVersion: 3.3\n');
    expect(yaml).toContain('Style/StringLiterals:\n  Enabled: true\n');
    expect(yaml).not.toContain('Security/');
  });

  it('writes the configuration RuboCop needs, nothing else', () => {
    expect(rubocopConfigYaml(['Lint/A', 'Security/B'], '4.0')).toBe(
      '# Written by Qualor (config.md §6): the only RuboCop configuration this scan reads.\n' +
        'AllCops:\n  DisabledByDefault: true\n  NewCops: disable\n  SuggestExtensions: false\n  TargetRubyVersion: 4.0\n  Exclude: []\n' +
        'Lint/A:\n  Enabled: true\nSecurity/B:\n  Enabled: true\n',
    );
  });

  it('leaves out names with a line break, and links, with a warning', async () => {
    const dir = install();
    const { root, scope } = repo(['ok.rb']);
    const lines: string[] = [];
    const extra: ScopeFile[] = [
      { ...scope[0]!, path: 'bad\nname.rb', absPath: path.join(root, 'bad\nname.rb') },
    ];
    try {
      const outside = path.join(tmp(), 'secret.rb');
      writeFileSync(outside, 'x = 1\n');
      symlinkSync(outside, path.join(root, 'link.rb'), 'file');
      extra.push({ ...scope[0]!, path: 'link.rb', absPath: path.join(root, 'link.rb') });
    } catch {
      // No file symlinks here (Windows without Developer Mode): the line-break case still runs.
    }
    const work = tmp();
    const p = await rubocopAnalyzer.prepare({
      ...fakeContext(root, { workDir: work, env: { QUALOR_RUBOCOP_DIR: dir } }),
      log: createLogger('debug', (t) => lines.push(t)),
      files: [...scope, ...extra],
    });
    if (!('run' in p)) throw new Error(JSON.stringify(p));
    expect(readFileSync(path.join(work, 'rubocop-files.txt'), 'utf8')).toBe('ok.rb\n');
    expect(lines.join('')).toContain(
      'rubocop: 1 Ruby file(s) whose path has a line break were left out',
    );
  });

  it('is skipped without Ruby files, without an install, or with another RuboCop minor', async () => {
    const { root, scope } = repo(['a.rb']);
    expect(
      await rubocopAnalyzer.prepare({
        ...fakeContext(root, { env: { QUALOR_RUBOCOP_DIR: install() } }),
        files: [],
      }),
    ).toEqual({
      skip: 'no Ruby files in scope',
    });
    expect(
      await rubocopAnalyzer.prepare({
        ...fakeContext(root, { env: { QUALOR_RUBOCOP_DIR: tmp() } }),
        files: scope,
      }),
    ).toEqual({
      skip: 'RuboCop is not installed (the qualor/scanner image keeps it in /opt/qualor/rubocop)',
    });
    for (const other of [`${MAJOR}.${MINOR + 1}.0`, `${MAJOR}.${MINOR - 1}.4`]) {
      const p = await rubocopAnalyzer.prepare({
        ...fakeContext(root, {
          env: { QUALOR_RUBOCOP_DIR: install(`rubocop ${other} ruby 4.0.7`) },
        }),
        files: scope,
      });
      expect(p).toEqual({
        skip: `RuboCop ${other} is not supported: this Qualor runs RuboCop ${MAJOR}.${MINOR}.x (the qualor/scanner image's ${RUBOCOP_VERSION})`,
      });
    }
    const none = await rubocopAnalyzer.prepare({
      ...fakeContext(root, {
        env: { QUALOR_RUBOCOP_DIR: install() },
        config: { analyzers: { rubocop: { select: ['Security'], ignore: ['Security'] } } },
      }),
      files: scope,
    });
    expect(none).toEqual({
      skip: 'no RuboCop cop is selected (analyzers.rubocop select minus ignore)',
    });
  });

  it('is unavailable with a relative or in-repository QUALOR_RUBOCOP_DIR, or a VERSION that names no version', async () => {
    const { root, scope } = repo(['a.rb']);
    const unavailable = {
      unavailable: 'QUALOR_RUBOCOP_DIR must be an absolute path outside the repository',
    };
    expect(
      await rubocopAnalyzer.prepare({
        ...fakeContext(root, { env: { QUALOR_RUBOCOP_DIR: 'tools/rubocop' } }),
        files: scope,
      }),
    ).toEqual(unavailable);
    expect(
      await rubocopAnalyzer.prepare({
        ...fakeContext(root, { env: { QUALOR_RUBOCOP_DIR: path.join(root, 'x') } }),
        files: scope,
      }),
    ).toEqual(unavailable);
    const broken = install('');
    expect(
      await rubocopAnalyzer.prepare({
        ...fakeContext(root, { env: { QUALOR_RUBOCOP_DIR: broken } }),
        files: scope,
      }),
    ).toEqual({
      unavailable: `${path.join(broken, 'VERSION')} does not name a RuboCop version`,
    });
  });

  it('fails (not merely skips) under enabled: true without an install', async () => {
    const { root, scope } = repo(['a.rb']);
    const [capture] = await runAnalyzers([rubocopAnalyzer], {
      root,
      config: parseConfig({ version: 1, analyzers: { rubocop: { enabled: true } } }),
      files: scope,
      log: silentLogger,
      env: { ...process.env, QUALOR_RUBOCOP_DIR: tmp() },
    });
    expect(capture).toMatchObject({
      status: 'failed',
      reason: 'RuboCop is not installed (the qualor/scanner image keeps it in /opt/qualor/rubocop)',
    });
  });

  it('reads the VERSION line', () => {
    expect(parseRubocopVersion('rubocop 1.91.0 ruby 4.0.7\n')).toBe('1.91.0');
    expect(parseRubocopVersion('rubocop 1.91.10 ruby 4.0.7')).toBe('1.91.10');
    expect(parseRubocopVersion('garbage')).toBeNull();
  });
});
