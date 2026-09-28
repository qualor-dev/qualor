import { describe, expect, it } from 'vitest';
import { parseCommandLine } from './args';
import { CliError, EXIT } from './errors';

function usageError(argv: string[]): CliError {
  try {
    parseCommandLine(argv);
  } catch (err) {
    if (err instanceof CliError) return err;
    throw err;
  }
  throw new Error(`expected a usage error for ${argv.join(' ')}`);
}

describe('parseCommandLine', () => {
  it('shows help for no arguments, help, --help and -h', () => {
    for (const argv of [[], ['help'], ['--help'], ['-h']]) {
      expect(parseCommandLine(argv)).toEqual({ name: 'help' });
    }
  });

  it('parses version and validate', () => {
    expect(parseCommandLine(['version'])).toEqual({ name: 'version' });
    expect(parseCommandLine(['--version'])).toEqual({ name: 'version' });
    expect(parseCommandLine(['validate'])).toEqual({ name: 'validate' });
    expect(parseCommandLine(['validate', '--config', 'ci/qualor.yml'])).toEqual({
      name: 'validate',
      config: 'ci/qualor.yml',
    });
  });

  it('parses every scan flag, with repeatable --sarif and --coverage', () => {
    expect(
      parseCommandLine([
        'scan',
        '--config',
        'q.yml',
        '--project-key',
        'acme/app',
        '--sarif',
        'a.sarif',
        '--sarif=b.sarif',
        '--coverage',
        'coverage/lcov.info',
        '--branch',
        'feature/x',
        '--mr',
        '42',
        '--mr-target',
        'main',
        '--no-wait',
        '--token-file',
        '/run/secrets/qualor',
        '--server-url',
        'https://qualor.acme.test',
        '--ca-file',
        '/etc/ssl/acme-ca.pem',
        '--dry-run',
        '--output',
        'out/report.json.gz',
        '--gitlab-code-quality',
        'gl-code-quality-report.json',
        '--gitlab-sast',
        'gl-sast-report.json',
        '--gitlab-dependency-scanning',
        'gl-dependency-scanning-report.json',
      ]),
    ).toEqual({
      name: 'scan',
      flags: {
        config: 'q.yml',
        projectKey: 'acme/app',
        sarif: ['a.sarif', 'b.sarif'],
        coverage: ['coverage/lcov.info'],
        branch: 'feature/x',
        mr: '42',
        mrTarget: 'main',
        wait: false,
        dryRun: true,
        output: 'out/report.json.gz',
        tokenFile: '/run/secrets/qualor',
        serverUrl: 'https://qualor.acme.test',
        caFile: '/etc/ssl/acme-ca.pem',
        gitlabCodeQuality: 'gl-code-quality-report.json',
        gitlabSast: 'gl-sast-report.json',
        gitlabDependencyScanning: 'gl-dependency-scanning-report.json',
      },
    });
  });

  it('defaults a bare scan', () => {
    expect(parseCommandLine(['scan'])).toEqual({
      name: 'scan',
      flags: { sarif: [], coverage: [], wait: true, dryRun: false },
    });
  });

  it('rejects unknown commands and flags with exit code 2 and the usage text', () => {
    const unknown = usageError(['scna']);
    expect(unknown.exitCode).toBe(2);
    expect(unknown.message).toContain('unknown command "scna"');
    expect(unknown.message).toContain('Usage:');
    expect(usageError(['scan', '--sarf', 'x']).exitCode).toBe(2);
    expect(usageError(['scan', 'extra']).exitCode).toBe(2);
    expect(usageError(['version', '--config', 'x']).exitCode).toBe(2);
  });

  it('enforces flag combinations', () => {
    expect(usageError(['scan', '--mr', '1']).message).toContain('--mr and --mr-target');
    expect(usageError(['scan', '--mr-target', 'main']).message).toContain('--mr and --mr-target');
    expect(usageError(['scan', '--dry-run']).message).toContain('--dry-run needs --output');
    expect(usageError(['scan', '--output', 'x.gz']).message).toContain('only valid with --dry-run');
    expect(usageError(['scan', '--branch', ' ']).message).toContain(
      '--branch needs a non-empty value',
    );
    expect(usageError(['scan', '--sarif', '']).message).toContain(
      '--sarif needs a non-empty value',
    );
  });

  it('validates --branch, --mr and --mr-target early (length and git ref format)', () => {
    const bad: [string, string][] = [
      ['--branch', 'x'.repeat(256)],
      ['--branch', '-upload-pack=evil'],
      ['--branch', 'a..b'],
      ['--branch', 'a b'],
      ['--branch', 'a~1'],
      ['--branch', 'feat/'],
      ['--branch', 'x.lock'],
      ['--branch', 'a@{1}'],
      ['--branch', 'a\u0007b'],
    ];
    for (const [flag, v] of bad) {
      const err = usageError(['scan', flag, v]);
      expect(err.exitCode, v).toBe(2);
      expect(err.message, v).toContain(`${flag} `);
    }
    for (const [mr, target] of [
      ['1'.repeat(65), 'main'],
      ['12; rm', 'main'],
      ['42', '--upload-pack=x'],
      ['42', 'm'.repeat(256)],
    ] as const) {
      expect(usageError(['scan', '--mr', mr, '--mr-target', target]).exitCode).toBe(2);
    }
    const ok = parseCommandLine([
      'scan',
      '--branch',
      'feature/JIRA-1_x.y',
      '--mr',
      '42',
      '--mr-target',
      'release/2.0',
    ]);
    expect(ok).toMatchObject({
      flags: { branch: 'feature/JIRA-1_x.y', mr: '42', mrTarget: 'release/2.0' },
    });
  });

  it('parses qualor dotnet begin and end (config.md §5)', () => {
    expect(parseCommandLine(['dotnet', 'begin'])).toEqual({ name: 'dotnet-begin' });
    expect(parseCommandLine(['dotnet', 'begin', '--config', 'q.yml'])).toEqual({
      name: 'dotnet-begin',
      config: 'q.yml',
    });
    const end = parseCommandLine(['dotnet', 'end', '--dry-run', '--output', 'r.json.gz']);
    expect(end).toMatchObject({ name: 'dotnet-end', flags: { dryRun: true, output: 'r.json.gz' } });
    expect(() => parseCommandLine(['dotnet'])).toThrow(/begin, end or abort/);
    expect(() => parseCommandLine(['dotnet', 'build'])).toThrow(/begin, end or abort/);
    expect(() => parseCommandLine(['dotnet', 'begin', '--dry-run'])).toThrow();
  });

  it('parses qualor dotnet abort, whose --config is accepted and ignored (config.md §5, §6.1)', () => {
    expect(parseCommandLine(['dotnet', 'abort'])).toEqual({ name: 'dotnet-abort' });
    expect(parseCommandLine(['dotnet', 'abort', '--config', 'q.yml'])).toEqual({
      name: 'dotnet-abort',
    });
    expect(() => parseCommandLine(['dotnet', 'abort', '--config', ' '])).toThrow(/non-empty/);
    expect(() => parseCommandLine(['dotnet', 'abort', '--dry-run'])).toThrow();
    expect(() => parseCommandLine(['dotnet', 'abort', 'now'])).toThrow();
    expect(() => parseCommandLine(['dotnet'])).toThrow(/begin, end or abort/);
  });
});

describe('qualor import sonarqube (import-sonarqube.md §3)', () => {
  const parse = (...a: string[]) => parseCommandLine(['import', 'sonarqube', ...a]);

  it('parses the brief form with defaults', () => {
    expect(parse('--url', 'https://sonar.test', '--token', 'squ_x')).toEqual({
      name: 'import-sonarqube',
      flags: {
        url: 'https://sonar.test',
        token: 'squ_x',
        sonarKind: 'auto',
        projects: [],
        only: ['profiles', 'gates', 'projects', 'issues'],
        createProjects: false,
        setDefaults: false,
        overwrite: false,
        dryRun: false,
        sonarAuth: 'auto',
        timeoutSeconds: 30,
        maxIssues: 100_000,
        allowInsecureHttp: false,
      },
    });
  });

  it('parses every option', () => {
    const c = parse(
      '--url',
      'https://sonarcloud.io',
      '--token-file',
      't',
      '--organization',
      'acme',
      '--sonar-kind',
      'cloud',
      '--qualor-organization',
      'default',
      '--project',
      'a',
      '--project',
      'b',
      '--only',
      'issues,gates',
      '--path-prefix',
      'services/api',
      '--create-projects',
      '--set-defaults',
      '--overwrite',
      '--dry-run',
      '--output',
      'r.json',
      '--server-url',
      'https://q.test',
      '--qualor-token-file',
      'q',
      '--ca-file',
      'ca.pem',
      '--sonar-ca-file',
      's.pem',
      '--sonar-auth',
      'basic',
      '--timeout',
      '60',
      '--max-issues',
      '5',
      '--allow-insecure-http',
    );
    expect(c).toMatchObject({
      name: 'import-sonarqube',
      flags: {
        organization: 'acme',
        sonarKind: 'cloud',
        projects: ['a', 'b'],
        only: ['gates', 'issues'],
        pathPrefix: 'services/api',
        qualorOrganization: 'default',
        timeoutSeconds: 60,
        maxIssues: 5,
        allowInsecureHttp: true,
      },
    });
  });

  it('drops a trailing slash of --path-prefix', () => {
    expect(parse('--url', 'https://s', '--path-prefix', 'services/api/')).toMatchObject({
      flags: { pathPrefix: 'services/api' },
    });
  });

  it.each([
    [[]],
    [['--url', 'https://s', '--token', 'a', '--token-file', 'b']],
    [['--url', 'https://s', '--only', 'profiles,nope']],
    [['--url', 'https://s', '--only', '']],
    [['--url', 'https://s', '--timeout', '0']],
    [['--url', 'https://s', '--timeout', '601']],
    [['--url', 'https://s', '--max-issues', '1.5']],
    [['--url', 'https://s', '--sonar-kind', 'moon']],
    [['--url', 'https://s', '--sonar-auth', 'digest']],
    [['--url', 'https://s', '--path-prefix', '../x']],
    [['--url', 'https://s', '--path-prefix', '/abs']],
    [['--url', 'https://s', '--path-prefix', 'a\\b']],
    [['--url', 'https://s', '--path-prefix', 'C:/x']],
    [['--url', 'https://s', '--organization', 'bad org']],
    [['--url', 'https://s', '--project', 'a\u0007b']],
    [['--url', 'https://s', '--token', '']],
    [['--url', 'https://s', 'positional']],
    [['--url', 'https://s', '--qualor-organization', 'Default']],
    [['--url', 'https://s', '--qualor-organization', 'a/b']],
    [['--url', 'https://s', '--qualor-organization', 'a%2e']],
    [['--url', 'https://s', '--qualor-organization', 'ab\u0000']],
    [['--url', 'https://s', '--path-prefix', 'a\u0007b']],
    [['--url', 'https://s', '--path-prefix', 'a\nb']],
    [['--url', 'https://s', '--path-prefix', 'a\u009bb']],
  ])('refuses %j with exit 2', (a) => {
    expect(() => parse(...a)).toThrow(expect.objectContaining({ exitCode: EXIT.USAGE }));
  });

  it('never echoes a stray argument, which may be a token', () => {
    for (const a of [
      ['--url', 'https://s', 'squ_stray0123456789'],
      ['--url', 'https://s', '--dry-run', 'squ_stray0123456789'],
    ]) {
      const err = usageError(['import', 'sonarqube', ...a]);
      expect(err.exitCode).toBe(EXIT.USAGE);
      expect(err.message).not.toContain('squ_stray0123456789');
    }
  });

  it('refuses an unknown import source', () => {
    expect(() => parseCommandLine(['import', 'jenkins'])).toThrow(/sonarqube/);
  });
});
