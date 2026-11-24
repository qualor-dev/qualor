import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { AZURE_PIPELINES_ENV } from '../../../../../../cli/src/config/ci';
import { EXIT } from '../../../../../../cli/src/errors';
import {
  parseCommand,
  planRun,
  PROBLEM_COMMAND,
  PROBLEM_PLATFORM,
  PROBLEM_SERVER,
  STEP_LABEL,
  stepFailure,
  stepProcessEnv,
  TASK_FORWARDED_ENV,
  withoutQualor,
  type TaskContext,
  type TaskInputs,
} from './plan';

// Assembled at run time: gitleaks scans the repository for Qualor tokens.
const TOKEN = ['qlr', 'prj', randomBytes(16).toString('hex')].join('_');
const URL = 'https://qualor.example.test';
const MERGE = 'a'.repeat(40);
const HEAD = 'b'.repeat(40);

const SCAN: TaskInputs = {
  command: 'scan',
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
    taskVersion: '0.16.0',
    ...overrides,
  };
}

const USER_SOURCES = ['run', '--rm', '--user', '1234:1235', '-v', '/home/agent/_work/1/s:/src'];
const REST = [
  '-w',
  '/src',
  '-v',
  '/home/agent/_work/_temp/qualor-home:/qualor-home',
  '-e',
  'HOME=/qualor-home',
];
const COMMON = [...USER_SOURCES, ...REST];
/** The build's read-only view of the repository's git directory (fails when it is missing). */
const GIT_MOUNT = 'type=bind,source=/home/agent/_work/1/s/.git,target=/src/.git,readonly';
const GIT_READ_ONLY = ['--mount', GIT_MOUNT];
/**
 * scan, end and abort ignore what the build could have written into the shared HOME: a global
 * git config and python's user site-packages.
 */
const HOME_ISOLATION = ['-e', 'GIT_CONFIG_GLOBAL=/dev/null', '-e', 'PYTHONNOUSERSITE=1'];
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
          ...HOME_ISOLATION,
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
      ...HOME_ISOLATION,
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
      ...HOME_ISOLATION,
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

  it('falls back to the task version when imageTag is empty, so the image always has a tag', () => {
    for (const imageTag of ['', '  ']) {
      const ctx = context({ taskVersion: '0.17.2' });
      const [scan] = stepsOf(planRun({ ...SCAN, imageTag }, ctx));
      expect(scan!.args).toContain('qualor/scanner:0.17.2');
      const images = stepsOf(planRun({ ...DOTNET, imageTag }, ctx)).map((s) =>
        s.args.find((a) => a.startsWith('qualor/')),
      );
      expect(images).toEqual(Array(4).fill('qualor/scanner-dotnet:0.17.2'));
    }
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
          ...USER_SOURCES,
          ...GIT_READ_ONLY,
          ...REST,
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
        args: [
          ...COMMON,
          ...CACHE,
          ...HOME_ISOLATION,
          ...FORWARDED,
          ...SERVER,
          image,
          'dotnet',
          'end',
          '--no-wait',
        ],
        env: { ...FORWARDED_ENV, QUALOR_URL: URL, QUALOR_TOKEN: TOKEN },
      },
      {
        name: 'abort',
        args: [...COMMON, ...CACHE, ...HOME_ISOLATION, ...FORWARDED, image, 'dotnet', 'abort'],
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

  it('mounts .git read-only for the build, after the /src mount, and only for the build', () => {
    const steps = stepsOf(planRun(DOTNET, context()));
    const build = steps.find((s) => s.name === 'build')!;
    const sources = build.args.indexOf('/home/agent/_work/1/s:/src');
    const git = build.args.indexOf(GIT_MOUNT);
    expect(sources).toBeGreaterThan(0);
    expect(build.args[sources - 1]).toBe('-v');
    // --mount, not -v: a missing .git fails the step instead of becoming an empty root-owned dir.
    expect(build.args[git - 1]).toBe('--mount');
    expect(git).toBeGreaterThan(sources);
    const others = steps.filter((s) => s.name !== 'build').flatMap((s) => s.args);
    expect(others.some((a) => a.includes('/.git'))).toBe(false);
  });

  it('runs scan, end and abort without the global git config or python user site-packages', () => {
    const steps = [...stepsOf(planRun(SCAN, context())), ...stepsOf(planRun(DOTNET, context()))];
    const withVariable = (value: string): string[] =>
      steps
        .filter((s) => s.args.some((a, i) => a === '-e' && s.args[i + 1] === value))
        .map((s) => s.name);
    expect(withVariable('GIT_CONFIG_GLOBAL=/dev/null')).toEqual(['scan', 'end', 'abort']);
    expect(withVariable('PYTHONNOUSERSITE=1')).toEqual(['scan', 'end', 'abort']);
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

describe('the environment of the docker client and of git on the agent', () => {
  // The agent's own environment: an `env:` mapping may put QUALOR_ values there.
  const host = {
    PATH: '/usr/bin',
    QUALOR_TOKEN: `${TOKEN}-mapped`,
    QUALOR_URL: 'https://other.example.test',
    QUALOR_CA_FILE: '/etc/ca.pem',
    qualor_lower: 'x',
    UNSET: undefined,
  };

  it('drops every QUALOR_ variable and unset values from the host environment', () => {
    expect(withoutQualor(host)).toEqual({ PATH: '/usr/bin' });
  });

  it('gives begin, build and abort no QUALOR_ variable, and end only the planned ones', () => {
    const steps = [...stepsOf(planRun(SCAN, context())), ...stepsOf(planRun(DOTNET, context()))];
    const qualorKeys = Object.fromEntries(
      steps.map((s) => [
        s.name,
        Object.keys(stepProcessEnv(host, s)).filter((k) => /^qualor_/i.test(k)),
      ]),
    );
    expect(qualorKeys).toEqual({
      scan: ['QUALOR_URL', 'QUALOR_TOKEN'],
      begin: [],
      build: [],
      end: ['QUALOR_URL', 'QUALOR_TOKEN'],
      abort: [],
    });
    const end = steps.find((s) => s.name === 'end')!;
    expect(stepProcessEnv(host, end)).toEqual({
      PATH: '/usr/bin',
      ...FORWARDED_ENV,
      QUALOR_URL: URL,
      QUALOR_TOKEN: TOKEN,
    });
  });
});

describe('TASK_FORWARDED_ENV', () => {
  it('is the list of CI variables the CLI reads (AZURE_PIPELINES_ENV)', () => {
    expect(TASK_FORWARDED_ENV).toEqual(AZURE_PIPELINES_ENV);
  });
});

describe('stepFailure', () => {
  const runner = (code: number): string =>
    `The process '/usr/bin/docker' failed with exit code ${code}`;

  it("says a failed quality gate for the scanner's exit code 1 of scan and end", () => {
    expect(EXIT.GATE_FAILED).toBe(1);
    for (const name of ['scan', 'end'] as const) {
      const text = stepFailure(name, runner(EXIT.GATE_FAILED));
      expect(text).toMatch(/^qualor (scan|dotnet end) failed: the quality gate did not pass[.]/);
      expect(text).not.toContain('docker');
    }
  });

  it('says a usage or configuration error for exit code 2 of any qualor step', () => {
    expect(EXIT.USAGE).toBe(2);
    for (const name of ['scan', 'begin', 'end', 'abort'] as const) {
      expect(stepFailure(name, runner(EXIT.USAGE))).toMatch(
        /^qualor .* failed: the scanner rejected its arguments or its configuration [(]exit code 2[)][.]/,
      );
    }
  });

  it('names any other code, and the build command is never read as the gate', () => {
    expect(stepFailure('scan', runner(EXIT.SERVER))).toBe('qualor scan failed with exit code 4.');
    expect(stepFailure('begin', runner(1))).toBe('qualor dotnet begin failed with exit code 1.');
    expect(stepFailure('build', runner(1))).toBe('The build command failed with exit code 1.');
    expect(stepFailure('build', runner(2))).toBe('The build command failed with exit code 2.');
  });

  it('keeps a message without an exit code', () => {
    expect(stepFailure('scan', 'spawn docker ENOENT')).toBe(
      'qualor scan failed: spawn docker ENOENT',
    );
  });
});

describe('planRun: qualor fix', () => {
  const FIX: TaskInputs = { ...SCAN, command: 'fix', extraArgs: ['--max', '3'] };

  it('command fix plans one fix step, without the head checkout or the Trivy cache', () => {
    expect(stepsOf(planRun(FIX, context()))).toEqual([
      {
        name: 'fix',
        args: [
          ...COMMON,
          ...HOME_ISOLATION,
          ...FORWARDED,
          ...SERVER,
          'qualor/scanner:0.16.0',
          'fix',
          '--max',
          '3',
        ],
        env: { ...FORWARDED_ENV, QUALOR_URL: URL, QUALOR_TOKEN: TOKEN },
      },
    ]);
  });

  it('keeps the token out of the arguments', () => {
    const [step] = stepsOf(planRun(FIX, context()));
    expect(step!.args.join(' ')).not.toContain(TOKEN);
    expect(step!.args).not.toContain('QUALOR_TRIVY_CACHE_DIR=/src/.qualor/trivy');
  });

  it('fix with dotnet is refused', () => {
    expect(planRun({ ...FIX, dotnet: true }, context())).toEqual({
      problem: 'The fix command does not use the .NET scanner: switch dotnet off.',
    });
  });

  it('fix still needs the server and a Linux agent', () => {
    expect(planRun(FIX, context({ platform: 'win32' }))).toEqual({ problem: PROBLEM_PLATFORM });
    expect(planRun(FIX, context({ qualorToken: '' }))).toEqual({ problem: PROBLEM_SERVER });
  });

  it('names the fix step and its exit codes as the CLI reference does', () => {
    const runner = (code: number): string =>
      `The process '/usr/bin/docker' failed with exit code ${code}`;
    expect(STEP_LABEL.fix).toBe('Qualor fix');
    expect(stepFailure('fix', runner(2))).toBe(
      'Qualor fix failed (exit code 2): a flag is wrong, there is no server, token or project key, HEAD is not the main branch (a detached HEAD, a tag pipeline, a commit other than the pipeline run), or the system is musl.',
    );
    expect(stepFailure('fix', runner(4))).toBe(
      'Qualor fix failed (exit code 4): the Qualor server is unreachable or answered an error.',
    );
    expect(stepFailure('fix', runner(5))).toBe(
      'Qualor fix failed (exit code 5): the token is wrong, revoked, of another project, or not a project analysis token.',
    );
    expect(stepFailure('fix', runner(1))).toBe('Qualor fix failed with exit code 1.');
    expect(stepFailure('fix', 'spawn docker ENOENT')).toBe(
      'Qualor fix failed: spawn docker ENOENT',
    );
  });
});

describe('parseCommand', () => {
  it('reads scan and fix, and scan when the input is unset or empty', () => {
    expect(parseCommand('scan')).toBe('scan');
    expect(parseCommand('fix')).toBe('fix');
    expect(parseCommand(' fix ')).toBe('fix');
    expect(parseCommand(undefined)).toBe('scan');
    expect(parseCommand('')).toBe('scan');
  });

  it('refuses any other value with a fixed text, and never scans', () => {
    for (const value of ['Fix', 'SCAN', 'fixes', 'scan fix', '${{ parameters.cmd }}']) {
      expect(parseCommand(value), value).toEqual({
        problem: 'The command input must be scan or fix.',
      });
    }
    expect(PROBLEM_COMMAND).toBe('The command input must be scan or fix.');
  });
});
