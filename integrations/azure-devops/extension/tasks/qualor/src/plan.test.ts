import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { AZURE_PIPELINES_ENV } from '../../../../../../cli/src/config/ci';
import { planRun, TASK_FORWARDED_ENV, type TaskContext, type TaskInputs } from './plan';

// Assembled at run time: gitleaks scans the repository for Qualor tokens.
const TOKEN = ['qlr', 'prj', randomBytes(16).toString('hex')].join('_');
const URL = 'https://qualor.example.test';
const MERGE = 'a'.repeat(40);
const HEAD = 'b'.repeat(40);

const SCAN: TaskInputs = {
  dotnet: false,
  dotnetBuild: 'dotnet build --no-incremental',
  imageTag: '0.16.0',
  extraArgs: ['--no-wait'],
};
const DOTNET: TaskInputs = { ...SCAN, dotnet: true };

function context(overrides: Partial<TaskContext> = {}): TaskContext {
  return {
    platform: 'linux',
    uid: 1234,
    gid: 1235,
    sourcesDir: '/home/agent/_work/1/s',
    tempDir: '/home/agent/_work/_temp',
    env: {
      PATH: '/usr/bin',
      TF_BUILD: 'True',
      BUILD_REASON: 'PullRequest',
      BUILD_SOURCEVERSION: MERGE,
      SYSTEM_PULLREQUEST_SOURCECOMMITID: HEAD,
    },
    qualorUrl: URL,
    qualorToken: TOKEN,
    ...overrides,
  };
}

const COMMON = [
  'run',
  '--rm',
  '--user',
  '1234:1235',
  '-v',
  '/home/agent/_work/1/s:/src',
  '-w',
  '/src',
  '-v',
  '/home/agent/_work/_temp/qualor-home:/qualor-home',
  '-e',
  'HOME=/qualor-home',
];
const CACHE = ['-e', 'QUALOR_TRIVY_CACHE_DIR=/src/.qualor/trivy'];
const FORWARDED = [
  '-e',
  'TF_BUILD',
  '-e',
  'BUILD_REASON',
  '-e',
  'BUILD_SOURCEVERSION',
  '-e',
  'SYSTEM_PULLREQUEST_SOURCECOMMITID',
];
const FORWARDED_ENV = {
  TF_BUILD: 'True',
  BUILD_REASON: 'PullRequest',
  BUILD_SOURCEVERSION: MERGE,
  SYSTEM_PULLREQUEST_SOURCECOMMITID: HEAD,
};
const SERVER = ['-e', 'QUALOR_URL', '-e', 'QUALOR_TOKEN'];

function stepsOf(result: ReturnType<typeof planRun>) {
  if ('problem' in result) throw new Error(`unexpected problem: ${result.problem}`);
  return result.steps;
}

describe('planRun: qualor scan', () => {
  it('runs the scanner image as the agent user with the sources, HOME and the cache', () => {
    expect(stepsOf(planRun(SCAN, context()))).toEqual([
      {
        name: 'scan',
        args: [
          ...COMMON,
          ...CACHE,
          ...FORWARDED,
          ...SERVER,
          'qualor/scanner:0.16.0',
          'scan',
          '--no-wait',
        ],
        env: { ...FORWARDED_ENV, QUALOR_URL: URL, QUALOR_TOKEN: TOKEN },
      },
    ]);
  });

  it('forwards only the Azure Pipelines variables that are set, in the CLI order', () => {
    const env = {
      BUILD_BUILDID: '42',
      SYSTEM_TEAMPROJECTID: 'p',
      HOME: '/home/agent',
      PATH: '/bin',
    };
    const [scan] = stepsOf(planRun({ ...SCAN, extraArgs: [] }, context({ env })));
    expect(scan!.args).toEqual([
      ...COMMON,
      ...CACHE,
      '-e',
      'BUILD_BUILDID',
      '-e',
      'SYSTEM_TEAMPROJECTID',
      ...SERVER,
      'qualor/scanner:0.16.0',
      'scan',
    ]);
    expect(scan!.env).toEqual({
      BUILD_BUILDID: '42',
      SYSTEM_TEAMPROJECTID: 'p',
      QUALOR_URL: URL,
      QUALOR_TOKEN: TOKEN,
    });
  });

  it('passes QUALOR_PROJECT_KEY by name when the pipeline sets it', () => {
    const env = { ...context().env, QUALOR_PROJECT_KEY: 'acme/app' };
    const [scan] = stepsOf(planRun(SCAN, context({ env })));
    expect(scan!.args).toEqual([
      ...COMMON,
      ...CACHE,
      ...FORWARDED,
      ...SERVER,
      '-e',
      'QUALOR_PROJECT_KEY',
      'qualor/scanner:0.16.0',
      'scan',
      '--no-wait',
    ]);
    expect(scan!.env['QUALOR_PROJECT_KEY']).toBe('acme/app');
  });

  it('takes the uid and gid from the context (an agent that is not 1000 or 1001)', () => {
    const [scan] = stepsOf(planRun(SCAN, context({ uid: 4242, gid: 77 })));
    expect(scan!.args.slice(0, 4)).toEqual(['run', '--rm', '--user', '4242:77']);
  });

  it('keeps the token out of the arguments: it reaches docker only through the environment', () => {
    const [scan] = stepsOf(planRun(SCAN, context()));
    expect(scan!.args.some((a) => a.includes(TOKEN))).toBe(false);
    expect(scan!.args.some((a) => a.includes(URL))).toBe(false);
    expect(scan!.env['QUALOR_TOKEN']).toBe(TOKEN);
  });
});

describe('planRun: problems', () => {
  it('refuses any platform but Linux', () => {
    for (const platform of ['win32', 'darwin'] as const) {
      expect(planRun(SCAN, context({ platform }))).toEqual({
        problem: 'Qualor@0 runs on Linux agents with Docker.',
      });
    }
  });

  it('checks the platform before the variables', () => {
    expect(planRun(SCAN, context({ platform: 'win32', qualorUrl: undefined }))).toEqual({
      problem: 'Qualor@0 runs on Linux agents with Docker.',
    });
  });

  it('asks for QUALOR_URL and QUALOR_TOKEN when either is missing or blank', () => {
    const problem = 'Set the pipeline variables QUALOR_URL and QUALOR_TOKEN (a secret).';
    for (const overrides of [
      { qualorUrl: undefined },
      { qualorUrl: ' ' },
      { qualorToken: undefined },
      { qualorToken: '' },
    ]) {
      expect(planRun(SCAN, context(overrides))).toEqual({ problem });
      expect(planRun(DOTNET, context(overrides))).toEqual({ problem });
    }
  });

  it('asks for the build command when .NET is on and dotnetBuild is empty', () => {
    for (const dotnetBuild of ['', '   ']) {
      expect(planRun({ ...DOTNET, dotnetBuild }, context())).toEqual({
        problem: 'Set dotnetBuild, the command that builds the solution.',
      });
    }
    // Without .NET the build command is not used.
    expect('steps' in planRun({ ...SCAN, dotnetBuild: '' }, context())).toBe(true);
  });
});

describe('planRun: .NET', () => {
  const image = 'qualor/scanner-dotnet:0.16.0';

  it('runs begin, the build and end in three containers, and abort only after a failure', () => {
    expect(stepsOf(planRun(DOTNET, context()))).toEqual([
      {
        name: 'begin',
        args: [...COMMON, ...CACHE, ...FORWARDED, image, 'dotnet', 'begin'],
        env: FORWARDED_ENV,
      },
      {
        name: 'build',
        args: [
          ...COMMON,
          ...FORWARDED,
          '--entrypoint',
          'sh',
          image,
          '-c',
          'dotnet build --no-incremental',
        ],
        env: FORWARDED_ENV,
      },
      {
        name: 'end',
        args: [...COMMON, ...CACHE, ...FORWARDED, ...SERVER, image, 'dotnet', 'end', '--no-wait'],
        env: { ...FORWARDED_ENV, QUALOR_URL: URL, QUALOR_TOKEN: TOKEN },
      },
      {
        name: 'abort',
        args: [...COMMON, ...CACHE, ...FORWARDED, image, 'dotnet', 'abort'],
        env: FORWARDED_ENV,
        onFailureOnly: true,
      },
    ]);
  });

  it('gives the build neither QUALOR_URL nor QUALOR_TOKEN nor any other QUALOR_ variable', () => {
    const env = { ...context().env, QUALOR_PROJECT_KEY: 'acme/app', QUALOR_TOKEN: TOKEN };
    const build = stepsOf(planRun(DOTNET, context({ env }))).find((s) => s.name === 'build')!;
    expect(Object.keys(build.env).filter((k) => k.startsWith('QUALOR_'))).toEqual([]);
    expect(build.args.filter((a) => a.startsWith('QUALOR_'))).toEqual([]);
    expect(build.args.join(' ')).not.toContain('-e QUALOR_URL');
    expect(build.args.join(' ')).not.toContain('-e QUALOR_TOKEN');
  });

  it('passes the server variables to end only, and the token never as an argument', () => {
    const env = { ...context().env, QUALOR_PROJECT_KEY: 'acme/app' };
    const steps = stepsOf(planRun(DOTNET, context({ env })));
    const withServer = steps.filter((s) => s.args.includes('QUALOR_TOKEN')).map((s) => s.name);
    expect(withServer).toEqual(['end']);
    expect(steps.find((s) => s.name === 'end')!.env['QUALOR_PROJECT_KEY']).toBe('acme/app');
    expect(steps.flatMap((s) => s.args).some((a) => a.includes(TOKEN))).toBe(false);
  });
});

describe('TASK_FORWARDED_ENV', () => {
  it('is the list of CI variables the CLI reads (AZURE_PIPELINES_ENV)', () => {
    expect(TASK_FORWARDED_ENV).toEqual(AZURE_PIPELINES_ENV);
  });
});
