import { describe, expect, it, vi } from 'vitest';
import { RUBOCOP_DEFAULT_TARGET_RUBY } from '../rules/rubocop';
import { BUILTIN_EXCLUDES, ConfigError, interpolateEnv, parseConfig } from './schema';

function errorPaths(raw: unknown): string[] {
  try {
    parseConfig(raw);
    return [];
  } catch (e) {
    if (e instanceof ConfigError) return e.issues.map((i) => i.path);
    throw e;
  }
}

describe('parseConfig', () => {
  it('fills every default for a minimal file', () => {
    const c = parseConfig({ version: 1 });
    expect(c.languages).toBe('auto');
    expect(c.sources).toEqual({ include: ['**/*'], exclude: [], useGitignore: true });
    expect(c.analyzers.eslint).toEqual({
      enabled: 'auto',
      configFile: null,
      args: [],
      timeoutSeconds: 900,
    });
    expect(c.analyzers.gitleaks.enabled).toBe(true);
    expect(c.analyzers.trivy).toEqual({ enabled: 'auto', timeoutSeconds: 600 });
    expect(c.analyzers.semgrep.configs).toEqual(['qualor-default']);
    expect(c.analyzers.spotbugs.classDirs).toEqual(['target/classes', 'build/classes/java/main']);
    expect(c.duplication).toEqual({ enabled: true, minTokens: 100, minLines: 10, exclude: [] });
    expect(c.coverage).toEqual({ reports: [], pathPrefixes: [] });
    expect(c.gate).toEqual({ wait: true, timeoutSeconds: 300, failOnError: true });
    expect(c.scm).toEqual({ autoFetch: true, mainBranch: null });
    expect(c.sarif).toEqual([]);
    expect(c.server.timeoutSeconds).toBe(30);
  });

  it('has analyzers.sonarjs and roslyn.sonarAnalyzer with their defaults', () => {
    const c = parseConfig({ version: 1 });
    expect(c.analyzers.sonarjs).toEqual({
      enabled: 'auto',
      timeoutSeconds: 900,
      typeChecking: 'auto',
    });
    expect(c.analyzers.roslyn.sonarAnalyzer).toBe(true);
    expect(() => parseConfig({ version: 1, analyzers: { sonarjs: { rules: {} } } })).toThrow();
  });

  // The CLI's analyzer runner reads a timeout only when the key is literally named
  // `timeoutSeconds` (cli/src/analyzers/runner.ts): `'timeoutSeconds' in settings ? … : 0`. A
  // differently-named key (the spec's earlier `timeout` typo) would silently give sonarjs no
  // timeout at all.
  it("names sonarjs's timeout key timeoutSeconds, like every other analyzer, so the runner sees it", () => {
    const sonarjs = parseConfig({ version: 1 }).analyzers.sonarjs;
    expect('timeoutSeconds' in sonarjs).toBe(true);
    expect(sonarjs.timeoutSeconds).toBe(900);
  });

  it('requires version 1', () => {
    expect(errorPaths({})).toEqual(['version']);
    expect(errorPaths({ version: 2 })).toEqual(['version']);
  });

  it('rejects unknown keys with their full path', () => {
    expect(errorPaths({ version: 1, analyzers: { eslnt: {} } })).toContain('analyzers');
    expect(errorPaths({ version: 1, gate: { wiat: true } })).toContain('gate');
    // No Trivy config file (plan 2B ruling O4): the key does not exist.
    expect(
      errorPaths({ version: 1, analyzers: { trivy: { configFile: 'trivy.yaml' } } }),
    ).toContain('analyzers.trivy');
  });

  it('refuses a token anywhere in the file', () => {
    expect(errorPaths({ version: 1, token: 'x' })).toContain('token');
    expect(errorPaths({ version: 1, server: { url: 'https://q', token: 'x' } })).toContain(
      'server.token',
    );
  });

  it('accepts only http and https server URLs', () => {
    for (const url of ['https://qualor.example.com', 'http://localhost:8080/base']) {
      expect(errorPaths({ version: 1, server: { url } })).toEqual([]);
    }
    for (const url of ['ftp://q.example.com', 'file:///etc/passwd', 'javascript:alert(1)']) {
      expect(errorPaths({ version: 1, server: { url } })).toEqual(['server.url']);
    }
  });

  it('rejects semgrep registry configs (no network)', () => {
    for (const bad of [
      'p/default',
      'auto',
      'r/python.lang',
      'https://semgrep.dev/c/x',
      'git+https://example.com/rules.git',
      'file:///etc/rules.yml',
      'ftp://example.com/r.yml',
    ]) {
      expect(errorPaths({ version: 1, analyzers: { semgrep: { configs: [bad] } } })).toEqual([
        'analyzers.semgrep.configs.0',
      ]);
    }
    expect(
      errorPaths({
        version: 1,
        analyzers: { semgrep: { configs: ['rules/local.yml', 'C:\\rules\\a.yml', './p/r.yml'] } },
      }),
    ).toEqual([]);
  });

  it('rejects an empty semgrep config list (enabled: false turns Semgrep off)', () => {
    expect(errorPaths({ version: 1, analyzers: { semgrep: { configs: [] } } })).toEqual([
      'analyzers.semgrep.configs',
    ]);
  });

  it('rejects PMD rulesets that are URLs or contain a comma (no network)', () => {
    for (const bad of ['https://example.com/r.xml', 'jar:file:/x.jar!/r.xml', 'a.xml,b.xml']) {
      expect(errorPaths({ version: 1, analyzers: { pmd: { rulesets: [bad] } } }), bad).toEqual([
        'analyzers.pmd.rulesets.0',
      ]);
    }
    const message = (bad: string) => {
      try {
        parseConfig({ version: 1, analyzers: { pmd: { rulesets: [bad] } } });
      } catch (e) {
        if (e instanceof ConfigError) return e.issues.map((i) => i.message).join('; ');
      }
      return '';
    };
    expect(message('https://example.com/r.xml')).toBe(
      'use a local ruleset file or a PMD classpath ruleset, not a URL (PMD would download it)',
    );
    expect(message('a.xml,b.xml')).toBe(
      'a ruleset cannot contain a comma (PMD splits --rulesets on commas); list each ruleset as its own entry',
    );
    for (const good of ['config/pmd.xml', 'C:\\rules\\pmd.xml', 'category/java/errorprone.xml']) {
      expect(errorPaths({ version: 1, analyzers: { pmd: { rulesets: [good] } } }), good).toEqual(
        [],
      );
    }
  });

  it('validates the sarif engine override and coverage format', () => {
    expect(errorPaths({ version: 1, sarif: [{ path: 'a.sarif', engine: 'eslint' }] })).toEqual([
      'sarif.0.engine',
    ]);
    expect(
      errorPaths({ version: 1, coverage: { reports: [{ path: 'x', format: 'clover' }] } }),
    ).toEqual(['coverage.reports.0.format']);
    const c = parseConfig({ version: 1, coverage: { reports: [{ path: 'coverage/lcov.info' }] } });
    expect(c.coverage.reports[0]).toEqual({ path: 'coverage/lcov.info', format: 'auto' });
  });

  it('accepts an explicit language list', () => {
    expect(parseConfig({ version: 1, languages: ['typescript', 'java'] }).languages).toEqual([
      'typescript',
      'java',
    ]);
    expect(errorPaths({ version: 1, languages: ['cobol'] })).toEqual(['languages.0']);
  });

  it('reports every invalid element in a language list, not just the first', () => {
    expect(errorPaths({ version: 1, languages: ['cobol', 'rust'] })).toEqual([
      'languages.0',
      'languages.1',
    ]);
  });

  it('parses the config.md §9 Java example', () => {
    expect(
      errorPaths({
        version: 1,
        analyzers: {
          pmd: { rulesets: ['config/pmd.xml'] },
          spotbugs: { classDirs: ['target/classes'] },
        },
        sarif: [{ path: 'osv-scanner.sarif', engine: 'osv-scanner' }],
        coverage: { reports: [{ path: '**/jacoco.xml', format: 'jacoco' }] },
      }),
    ).toEqual([]);
  });

  it('knows C#: the language, the roslyn analyzer and the .NET excludes (config.md §3, §6.1)', () => {
    const config = parseConfig({ version: 1 });
    expect(config.analyzers.roslyn).toEqual({
      enabled: 'auto',
      bundledAnalyzers: true,
      sonarAnalyzer: true,
    });
    expect(parseConfig({ version: 1, languages: ['csharp'] }).languages).toEqual(['csharp']);
    expect(config.tests.include).toContain('**/*Tests/**');
    for (const glob of [
      '.qualor/**',
      '**/obj/**',
      '**/bin/Debug/**',
      '**/bin/Release/**',
      '**/*.g.cs',
      '**/*.g.i.cs',
      '**/*.Designer.cs',
    ]) {
      expect(BUILTIN_EXCLUDES).toContain(glob);
    }
    expect(BUILTIN_EXCLUDES).not.toContain('**/bin/**');
    expect(() =>
      parseConfig({ version: 1, analyzers: { roslyn: { timeoutSeconds: 5 } } }),
    ).toThrow();
  });

  it('reserves the roslyn engine id for the built-in analyzer', () => {
    expect(() =>
      parseConfig({ version: 1, sarif: [{ path: 'x.sarif', engine: 'roslyn' }] }),
    ).toThrow(/reserved/);
  });

  it('has analyzers.ruff with its defaults and knows Python (config.md §3, §3.1, §6)', () => {
    const c = parseConfig({ version: 1 });
    expect(c.analyzers.ruff).toEqual({
      enabled: 'auto',
      select: ['qualor-default'],
      ignore: [],
      timeoutSeconds: 600,
    });
    expect(parseConfig({ version: 1, languages: ['python'] }).languages).toEqual(['python']);
    for (const glob of ['**/test_*.py', '**/*_test.py', '**/conftest.py']) {
      expect(c.tests.include).toContain(glob);
    }
    for (const glob of [
      '**/.venv/**',
      '**/venv/**',
      '**/.tox/**',
      '**/.nox/**',
      '**/__pycache__/**',
      '**/__pypackages__/**',
      '**/.eggs/**',
      '**/site-packages/**',
    ]) {
      expect(BUILTIN_EXCLUDES).toContain(glob);
    }
  });

  it('validates Ruff selectors and reserves the ruff engine id', () => {
    const ruff = (r: object) => parseConfig({ version: 1, analyzers: { ruff: r } }).analyzers.ruff;
    expect(ruff({ select: ['qualor-default', 'UP', 'S608'], ignore: ['E731'] }).select).toEqual([
      'qualor-default',
      'UP',
      'S608',
    ]);
    expect(() => ruff({ select: [] })).toThrow(/at least one/);
    expect(() => ruff({ select: ['E4,E7'] })).toThrow(/Ruff rule/);
    expect(() => ruff({ ignore: ['qualor-default'] })).toThrow(/Ruff rule/);
    expect(() => ruff({ config: 'ruff.toml' })).toThrow();
    // Ruff 0.16.9 has no code starting with these: a config error naming the value, not a Ruff exit 2.
    expect(() => ruff({ select: ['ZZZ9'] })).toThrow(/unknown Ruff rule selector "ZZZ9"/);
    expect(() => ruff({ ignore: ['S9999'] })).toThrow(/unknown Ruff rule selector "S9999"/);
    expect(ruff({ select: ['ALL', 'C90', 'PL', 'RUF100', 'E'], ignore: ['ALL', 'D1'] })).toEqual(
      expect.objectContaining({
        select: ['ALL', 'C90', 'PL', 'RUF100', 'E'],
        ignore: ['ALL', 'D1'],
      }),
    );
    expect(() => parseConfig({ version: 1, sarif: [{ path: 'r.sarif', engine: 'ruff' }] })).toThrow(
      /reserved/,
    );
  });
});

describe('HTML and CSS settings (plan 8D)', () => {
  it('has analyzers.stylelint and analyzers.htmlhint with their defaults', () => {
    const c = parseConfig({ version: 1 });
    expect(c.analyzers.stylelint).toEqual({
      enabled: 'auto',
      configFile: null,
      timeoutSeconds: 600,
    });
    expect(c.analyzers.htmlhint).toEqual({
      enabled: 'auto',
      configFile: null,
      timeoutSeconds: 300,
    });
    expect(() => parseConfig({ version: 1, analyzers: { stylelint: { rules: {} } } })).toThrow();
    expect(() =>
      parseConfig({ version: 1, analyzers: { htmlhint: { configFile: '' } } }),
    ).toThrow();
  });

  it('accepts html and css in an explicit language list', () => {
    expect(parseConfig({ version: 1, languages: ['html', 'css'] }).languages).toEqual([
      'html',
      'css',
    ]);
  });

  it('excludes minified CSS like minified JS (config.md §3.1)', () => {
    expect(BUILTIN_EXCLUDES).toContain('**/*.min.css');
    expect(BUILTIN_EXCLUDES.indexOf('**/*.min.css')).toBe(
      BUILTIN_EXCLUDES.indexOf('**/*.min.js') + 1,
    );
  });
});

describe('interpolateEnv', () => {
  it('replaces ${VAR} and ${VAR:-default} recursively', () => {
    const warn = vi.fn();
    const out = interpolateEnv(
      { a: '${A}', b: ['x-${B:-fallback}'], c: 3, d: '${MISSING}' },
      { A: 'one' },
      warn,
    );
    expect(out).toEqual({ a: 'one', b: ['x-fallback'], c: 3, d: '' });
    expect(warn).toHaveBeenCalledWith('MISSING');
  });

  it('resolves denied names to an empty string in the same single pass, with a distinct callback', () => {
    const warn = vi.fn();
    const denied = vi.fn();
    const env = { SECRET: 's3cr3t-value', A: 'one', INDIRECT: '${SECRET}' };
    const out = interpolateEnv(
      {
        bypass: '$${SECRET}{SECRET}',
        nested: '${A:-${SECRET}}',
        adjacent: '${SECRET}${SECRET}${A}',
        fallback: '${SECRET:-x}',
        indirect: '${INDIRECT}',
        unset: '${NOPE}',
      },
      env,
      warn,
      { deny: (name) => name === 'SECRET', onDenied: denied },
    );
    expect(out).toEqual({
      bypass: '${SECRET}',
      nested: 'one}',
      adjacent: 'one',
      fallback: '',
      indirect: '${SECRET}',
      unset: '',
    });
    expect(JSON.stringify(out)).not.toContain('s3cr3t-value');
    expect(denied).toHaveBeenCalledWith('SECRET');
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn).toHaveBeenCalledWith('NOPE');
  });

  it('never re-scans a substituted value', () => {
    const out = interpolateEnv('${A}', { A: '${B}', B: 'b' }, vi.fn());
    expect(out).toBe('${B}');
  });
});

describe('BUILTIN_EXCLUDES', () => {
  it('contains the documented excludes', () => {
    expect(BUILTIN_EXCLUDES).toEqual(
      expect.arrayContaining(['**/node_modules/**', '**/.git/**', '**/*.min.js']),
    );
  });

  it('does not exclude coverage directories, which may hold source (ruling Q3)', () => {
    expect(BUILTIN_EXCLUDES.some((glob) => glob.includes('coverage'))).toBe(false);
  });

  it('has analyzers.detekt with its defaults and accepts kotlin as a language (phase 8E)', () => {
    const c = parseConfig({ version: 1 });
    expect(c.analyzers.detekt).toEqual({ enabled: 'auto', configFile: null, timeoutSeconds: 900 });
    expect(parseConfig({ version: 1, languages: ['kotlin'] }).languages).toEqual(['kotlin']);
    expect(errorPaths({ version: 1, analyzers: { detekt: { rules: {} } } })).not.toEqual([]);
    expect(errorPaths({ version: 1, analyzers: { detekt: { configFile: '' } } })).not.toEqual([]);
    // A built-in engine id is reserved for external SARIF (report-format.md 7.2).
    expect(errorPaths({ version: 1, sarif: [{ path: 'r.sarif', engine: 'detekt' }] })).not.toEqual(
      [],
    );
    // Android and Kotlin Multiplatform test source sets (ruling E17).
    expect(c.tests.include).toContain('**/src/androidTest/**');
    expect(c.tests.include).toContain('**/src/*Test/**');
  });

  it('has analyzers.swiftlint with its defaults, knows Swift and excludes Swift dependencies (config.md §3, §3.1, §6)', () => {
    const c = parseConfig({ version: 1 });
    expect(c.analyzers.swiftlint).toEqual({
      enabled: 'auto',
      configFile: null,
      timeoutSeconds: 600,
    });
    expect(parseConfig({ version: 1, languages: ['swift'] }).languages).toEqual(['swift']);
    for (const glob of ['**/Pods/**', '**/Carthage/**', '**/.build/**']) {
      expect(BUILTIN_EXCLUDES).toContain(glob);
    }
    expect(
      parseConfig({ version: 1, analyzers: { swiftlint: { configFile: 'qualor-default' } } })
        .analyzers.swiftlint.configFile,
    ).toBe('qualor-default');
    expect(() =>
      parseConfig({ version: 1, analyzers: { swiftlint: { configFile: '' } } }),
    ).toThrow();
    expect(() => parseConfig({ version: 1, analyzers: { swiftlint: { args: [] } } })).toThrow();
    expect(() =>
      parseConfig({ version: 1, sarif: [{ path: 'r.sarif', engine: 'swiftlint' }] }),
    ).toThrow(/reserved/);
  });

  it('has analyzers.rubocop with its defaults, knows Ruby, its test files and its excludes (plan 9B)', () => {
    const c = parseConfig({ version: 1 });
    expect(c.analyzers.rubocop).toEqual({
      enabled: 'auto',
      select: ['qualor-default'],
      ignore: [],
      targetRubyVersion: RUBOCOP_DEFAULT_TARGET_RUBY,
      timeoutSeconds: 600,
    });
    expect(parseConfig({ version: 1, languages: ['ruby'] }).languages).toEqual(['ruby']);
    for (const glob of ['**/*_spec.rb', '**/*_test.rb', '**/spec/**/*.rb', '**/test/**/*.rb'])
      expect(c.tests.include).toContain(glob);
    for (const glob of ['**/.bundle/**', '**/db/schema.rb'])
      expect(BUILTIN_EXCLUDES).toContain(glob);
  });

  it('validates RuboCop selectors and target Rubies, and reserves the rubocop engine id', () => {
    const rubocop = (r: object) =>
      parseConfig({ version: 1, analyzers: { rubocop: r } }).analyzers.rubocop;
    expect(
      rubocop({ select: ['qualor-default', 'Style', 'Style/StringLiterals'], ignore: ['Security'] })
        .select,
    ).toEqual(['qualor-default', 'Style', 'Style/StringLiterals']);
    expect(rubocop({ targetRubyVersion: 3.3 }).targetRubyVersion).toBe(3.3);
    expect(rubocop({ targetRubyVersion: '2.7' }).targetRubyVersion).toBe('2.7');
    expect(() => rubocop({ select: [] })).toThrow(/at least one/);
    expect(() => rubocop({ select: ['Lint/NotACop'] })).toThrow(
      /unknown RuboCop department or cop "Lint\/NotACop"/,
    );
    expect(() => rubocop({ select: ['rails'] })).toThrow(/RuboCop department/);
    expect(() => rubocop({ ignore: ['qualor-default'] })).toThrow(/RuboCop department/);
    expect(() => rubocop({ targetRubyVersion: '9.9' })).toThrow(/Ruby version RuboCop/);
    expect(() => rubocop({ configFile: '.rubocop.yml' })).toThrow();
    expect(() =>
      parseConfig({ version: 1, sarif: [{ path: 'r.sarif', engine: 'rubocop' }] }),
    ).toThrow(/reserved/);
  });
});
