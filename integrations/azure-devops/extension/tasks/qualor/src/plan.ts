import path from 'node:path';

/**
 * The CI variables the scanner reads on Azure Pipelines, forwarded into the container by name
 * (`docker run` passes no host environment). A copy of the CLI's `AZURE_PIPELINES_ENV`
 * (cli/src/config/ci.ts): the task bundle must not carry CLI code, and plan.test.ts keeps the
 * two lists equal.
 */
export const TASK_FORWARDED_ENV: readonly string[] = [
  'TF_BUILD',
  'BUILD_REPOSITORY_PROVIDER',
  'BUILD_REASON',
  'BUILD_SOURCEBRANCH',
  'BUILD_SOURCEVERSION',
  'BUILD_BUILDID',
  'BUILD_REPOSITORY_ID',
  'BUILD_REPOSITORY_NAME',
  'SYSTEM_TEAMPROJECT',
  'SYSTEM_TEAMPROJECTID',
  'SYSTEM_COLLECTIONURI',
  'SYSTEM_PULLREQUEST_PULLREQUESTID',
  'SYSTEM_PULLREQUEST_SOURCEBRANCH',
  'SYSTEM_PULLREQUEST_TARGETBRANCH',
  'SYSTEM_PULLREQUEST_SOURCECOMMITID',
];

/** The task's inputs (task.json), `arguments` already split into `extraArgs`. */
export interface TaskInputs {
  /** `scan` (the default) or `fix`: `qualor fix` prepares the dependency fix pull requests. */
  command: 'scan' | 'fix';
  dotnet: boolean;
  dotnetBuild: string;
  imageTag: string;
  extraArgs: string[];
}

/** What the task reads from the agent: its process, its directories and the pipeline variables. */
export interface TaskContext {
  platform: NodeJS.Platform;
  uid: number;
  gid: number;
  sourcesDir: string;
  tempDir: string;
  env: Record<string, string | undefined>;
  qualorUrl: string | undefined;
  qualorToken: string | undefined;
  /** The task's own version (task.json): the image tag when the `imageTag` input is empty. */
  taskVersion: string;
}

/**
 * One `docker run`: `args` follow `docker`, `env` is added to the docker client's environment.
 * Every value that comes from the pipeline travels in `env` and reaches the container through
 * `-e NAME`, so it never appears in `args` (the task log prints the command line).
 */
export interface DockerStep {
  name: 'scan' | 'fix' | 'begin' | 'build' | 'end' | 'abort';
  args: string[];
  env: Record<string, string>;
  /** Runs only after an earlier step failed (`qualor dotnet abort`). */
  onFailureOnly?: true;
}

export const PROBLEM_PLATFORM = 'Qualor@0 runs on Linux agents with Docker.';
export const PROBLEM_SERVER = 'Set the pipeline variables QUALOR_URL and QUALOR_TOKEN (a secret).';
export const PROBLEM_FIX_DOTNET =
  'The fix command does not use the .NET scanner: switch dotnet off.';
export const PROBLEM_BUILD = 'Set dotnetBuild, the command that builds the solution.';

/** In the container: the sources, the scanner's HOME and the vulnerability database cache. */
const SOURCES = '/src';
const HOME = '/qualor-home';
const TRIVY_CACHE = '/src/.qualor/trivy';

/**
 * The `docker run` steps of one task run, or the problem that stops it before anything runs.
 *
 * Every step starts `run --rm --user <uid>:<gid> -v <sourcesDir>:/src -w /src
 * -v <tempDir>/qualor-home:/qualor-home -e HOME=/qualor-home`. Then, by step:
 *
 * | Step | Then | Image and command |
 * | --- | --- | --- |
 * | scan | `C H F S` | `qualor/scanner:<tag> scan <arguments>` |
 * | fix | `H F S` | `qualor/scanner:<tag> fix <arguments>` (`command: fix`: no head checkout, no cache) |
 * | begin | `C F` | `qualor/scanner-dotnet:<tag> dotnet begin` |
 * | build | `F` | `--entrypoint sh qualor/scanner-dotnet:<tag> -c <dotnetBuild>` |
 * | end | `C H F S` | `qualor/scanner-dotnet:<tag> dotnet end <arguments>` |
 * | abort | `C H F` | `qualor/scanner-dotnet:<tag> dotnet abort` (after a failure only) |
 *
 * `C` = `-e QUALOR_TRIVY_CACHE_DIR=/src/.qualor/trivy`; `H` = `-e GIT_CONFIG_GLOBAL=/dev/null
 * -e PYTHONNOUSERSITE=1`; `F` = `-e NAME` for each `TASK_FORWARDED_ENV` variable that is set;
 * `S` = `-e QUALOR_URL -e QUALOR_TOKEN` (and `-e QUALOR_PROJECT_KEY` when set). `<tag>` is
 * `imageTag`, or the task's version when that input is empty.
 *
 * The build runs the project's code (NuGet props and targets, analyzers, source generators), so
 * it gets no `QUALOR_` variable and sees the repository's git directory read-only: its args add
 * `--mount type=bind,source=<sourcesDir>/.git,target=/src/.git,readonly` right after the `/src`
 * mount. It still shares HOME with begin and end (the MSBuild hook lives there), so scan, end
 * and abort ignore what it could write there: the global git config (a `core.fsmonitor` or
 * filter command would run next to the token) and python's user site-packages (the scanner runs
 * python3 for the cppcheck addons).
 *
 * The container runs as the agent user, so what the scanner writes into the sources belongs to
 * that user, and HOME is a directory of the agent's temp directory that the task creates first.
 */
export function planRun(
  inputs: TaskInputs,
  ctx: TaskContext,
): { problem: string } | { steps: DockerStep[] } {
  const url = ctx.qualorUrl ?? '';
  const token = ctx.qualorToken ?? '';
  if (ctx.platform !== 'linux') return { problem: PROBLEM_PLATFORM };
  if (url.trim() === '' || token.trim() === '') return { problem: PROBLEM_SERVER };
  if (inputs.command === 'fix' && inputs.dotnet) return { problem: PROBLEM_FIX_DOTNET };
  if (inputs.dotnet && inputs.dotnetBuild.trim() === '') return { problem: PROBLEM_BUILD };

  const forwardedEnv: Record<string, string> = {};
  for (const name of TASK_FORWARDED_ENV) {
    const value = ctx.env[name];
    if (value !== undefined) forwardedEnv[name] = value;
  }
  const projectKey = ctx.env['QUALOR_PROJECT_KEY'] ?? '';
  const server: Record<string, string> = {
    QUALOR_URL: url,
    QUALOR_TOKEN: token,
    ...(projectKey.trim() === '' ? {} : { QUALOR_PROJECT_KEY: projectKey }),
  };
  const tag = inputs.imageTag.trim() === '' ? ctx.taskVersion : inputs.imageTag.trim();

  /**
   * The common start; `readOnlyGit` adds the build's read-only `.git` after the `/src` mount.
   * `--mount`, not `-v`: when `.git` is missing the step fails, where `-v` would make Docker
   * create it as an empty directory owned by root.
   */
  const gitMount = `type=bind,source=${path.posix.join(ctx.sourcesDir, '.git')},target=${SOURCES}/.git,readonly`;
  const base = (readOnlyGit: boolean): string[] => [
    'run',
    '--rm',
    '--user',
    `${ctx.uid}:${ctx.gid}`,
    '-v',
    `${ctx.sourcesDir}:${SOURCES}`,
    ...(readOnlyGit ? ['--mount', gitMount] : []),
    '-w',
    SOURCES,
    '-v',
    `${path.posix.join(ctx.tempDir, 'qualor-home')}:${HOME}`,
    '-e',
    `HOME=${HOME}`,
  ];
  const names = (env: Record<string, string>): string[] =>
    Object.keys(env).flatMap((name) => ['-e', name]);
  /**
   * A step that runs `qualor`. `distrustHome`: it ignores what the build could write into the
   * HOME they share (`H`); `upload`: it also gets the server variables.
   */
  const qualor = (
    name: DockerStep['name'],
    image: string,
    command: string[],
    {
      distrustHome,
      upload,
      cache = true,
    }: { distrustHome: boolean; upload: boolean; cache?: boolean },
  ): DockerStep => {
    const env = upload ? { ...forwardedEnv, ...server } : forwardedEnv;
    return {
      name,
      args: [
        ...base(false),
        ...(cache ? ['-e', `QUALOR_TRIVY_CACHE_DIR=${TRIVY_CACHE}`] : []),
        ...(distrustHome ? ['-e', 'GIT_CONFIG_GLOBAL=/dev/null', '-e', 'PYTHONNOUSERSITE=1'] : []),
        ...names(env),
        image,
        ...command,
      ],
      env,
    };
  };

  if (inputs.command === 'fix') {
    const fix = ['fix', ...inputs.extraArgs];
    return {
      steps: [
        qualor('fix', `qualor/scanner:${tag}`, fix, {
          distrustHome: true,
          upload: true,
          cache: false,
        }),
      ],
    };
  }
  if (!inputs.dotnet) {
    const scan = ['scan', ...inputs.extraArgs];
    return {
      steps: [qualor('scan', `qualor/scanner:${tag}`, scan, { distrustHome: true, upload: true })],
    };
  }
  const image = `qualor/scanner-dotnet:${tag}`;
  return {
    steps: [
      qualor('begin', image, ['dotnet', 'begin'], { distrustHome: false, upload: false }),
      {
        name: 'build',
        args: [
          ...base(true),
          ...names(forwardedEnv),
          '--entrypoint',
          'sh',
          image,
          '-c',
          inputs.dotnetBuild,
        ],
        env: forwardedEnv,
      },
      qualor('end', image, ['dotnet', 'end', ...inputs.extraArgs], {
        distrustHome: true,
        upload: true,
      }),
      {
        ...qualor('abort', image, ['dotnet', 'abort'], { distrustHome: true, upload: false }),
        onFailureOnly: true,
      },
    ],
  };
}

/**
 * The agent's environment without unset values and without any `QUALOR_` variable (in any
 * case): the base of every child process the task starts, so a value mapped with `env:` on the
 * task reaches only the steps that plan it.
 */
export function withoutQualor(
  env: Readonly<Record<string, string | undefined>>,
): Record<string, string> {
  const kept: Record<string, string> = {};
  for (const [name, value] of Object.entries(env)) {
    if (value !== undefined && !/^QUALOR_/i.test(name)) kept[name] = value;
  }
  return kept;
}

/** A step's docker client environment: the agent's without `QUALOR_` variables, plus `step.env`. */
export function stepProcessEnv(
  hostEnv: Readonly<Record<string, string | undefined>>,
  step: DockerStep,
): Record<string, string> {
  return { ...withoutQualor(hostEnv), ...step.env };
}

/** What the task says for a step that failed; `LABEL` names the step. */
export const STEP_LABEL: Record<DockerStep['name'], string> = {
  scan: 'qualor scan',
  fix: 'Qualor fix',
  begin: 'qualor dotnet begin',
  build: 'The build command',
  end: 'qualor dotnet end',
  abort: 'qualor dotnet abort',
};

/** The `qualor fix` exit codes that docs/guide/cli.md names (0 is a pass; 1 is not used). */
const FIX_EXIT: Record<string, string> = {
  '2': 'a flag is wrong, there is no server, token or project key, HEAD is not the main branch (a detached HEAD, a tag pipeline, a commit other than the pipeline run), or the system is musl.',
  '4': 'the Qualor server is unreachable or answered an error.',
  '5': 'the token is wrong, revoked, of another project, or not a project analysis token.',
};

/**
 * The failure of a step in plain words. The tool runner's message is "The process '/usr/bin/docker'
 * failed with exit code N": the scanner's own exit codes (cli/src/errors.ts `EXIT`) say more. 1 is
 * a failed quality gate (only `scan` and `dotnet end` evaluate it), 2 is a usage or configuration
 * error; any other code, and the build command's code, is named as it is. A message without an
 * exit code stays as it is.
 */
export function stepFailure(name: DockerStep['name'], message: string): string {
  const label = STEP_LABEL[name];
  const code = /exit code (\d+)/.exec(message)?.[1];
  if (code === undefined) return `${label} failed: ${message}`;
  if (name === 'fix' && FIX_EXIT[code] !== undefined)
    return `${label} failed (exit code ${code}): ${FIX_EXIT[code]}`;
  if (name !== 'build') {
    if (code === '1' && (name === 'scan' || name === 'end'))
      return `${label} failed: the quality gate did not pass. The scan report lists the conditions that failed.`;
    if (code === '2')
      return `${label} failed: the scanner rejected its arguments or its configuration (exit code 2). Check the task's inputs and qualor.yml.`;
  }
  return `${label} failed with exit code ${code}.`;
}
