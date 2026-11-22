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
}

/**
 * One `docker run`: `args` follow `docker`, `env` is added to the docker client's environment.
 * Every value that comes from the pipeline travels in `env` and reaches the container through
 * `-e NAME`, so it never appears in `args` (the task log prints the command line).
 */
export interface DockerStep {
  name: 'scan' | 'begin' | 'build' | 'end' | 'abort';
  args: string[];
  env: Record<string, string>;
  /** Runs only after an earlier step failed (`qualor dotnet abort`). */
  onFailureOnly?: true;
}

export const PROBLEM_PLATFORM = 'Qualor@0 runs on Linux agents with Docker.';
export const PROBLEM_SERVER = 'Set the pipeline variables QUALOR_URL and QUALOR_TOKEN (a secret).';
export const PROBLEM_BUILD = 'Set dotnetBuild, the command that builds the solution.';

/** In the container: the sources, the scanner's HOME and the vulnerability database cache. */
const SOURCES = '/src';
const HOME = '/qualor-home';
const TRIVY_CACHE = '/src/.qualor/trivy';

/**
 * The `docker run` steps of one task run, or the problem that stops it before anything runs.
 *
 * Every step: `run --rm --user <uid>:<gid> -v <sourcesDir>:/src -w /src
 * -v <tempDir>/qualor-home:/qualor-home -e HOME=/qualor-home`, then
 * `-e QUALOR_TRIVY_CACHE_DIR=/src/.qualor/trivy` (not for the build, which gets no `QUALOR_`
 * variable), `-e NAME` for each `TASK_FORWARDED_ENV` variable that is set, `-e QUALOR_URL
 * -e QUALOR_TOKEN` (and `-e QUALOR_PROJECT_KEY` when set) for the steps that upload, the image
 * and the command:
 *
 * | Step | Image | Command |
 * | --- | --- | --- |
 * | scan | `qualor/scanner:<imageTag>` | `scan <arguments>` (uploads) |
 * | begin | `qualor/scanner-dotnet:<imageTag>` | `dotnet begin` |
 * | build | `--entrypoint sh qualor/scanner-dotnet:<imageTag>` | `-c <dotnetBuild>` |
 * | end | `qualor/scanner-dotnet:<imageTag>` | `dotnet end <arguments>` (uploads) |
 * | abort | `qualor/scanner-dotnet:<imageTag>` | `dotnet abort` (after a failure only) |
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

  const base = [
    'run',
    '--rm',
    '--user',
    `${ctx.uid}:${ctx.gid}`,
    '-v',
    `${ctx.sourcesDir}:${SOURCES}`,
    '-w',
    SOURCES,
    '-v',
    `${path.posix.join(ctx.tempDir, 'qualor-home')}:${HOME}`,
    '-e',
    `HOME=${HOME}`,
  ];
  const names = (env: Record<string, string>): string[] =>
    Object.keys(env).flatMap((name) => ['-e', name]);
  /** A step that runs `qualor`; with `upload`, it also gets the server variables. */
  const qualor = (
    name: DockerStep['name'],
    image: string,
    command: string[],
    upload: boolean,
  ): DockerStep => {
    const env = upload ? { ...forwardedEnv, ...server } : forwardedEnv;
    return {
      name,
      args: [
        ...base,
        '-e',
        `QUALOR_TRIVY_CACHE_DIR=${TRIVY_CACHE}`,
        ...names(env),
        image,
        ...command,
      ],
      env,
    };
  };

  if (!inputs.dotnet) {
    return {
      steps: [
        qualor('scan', `qualor/scanner:${inputs.imageTag}`, ['scan', ...inputs.extraArgs], true),
      ],
    };
  }
  const image = `qualor/scanner-dotnet:${inputs.imageTag}`;
  return {
    steps: [
      qualor('begin', image, ['dotnet', 'begin'], false),
      {
        name: 'build',
        args: [
          ...base,
          ...names(forwardedEnv),
          '--entrypoint',
          'sh',
          image,
          '-c',
          inputs.dotnetBuild,
        ],
        env: forwardedEnv,
      },
      qualor('end', image, ['dotnet', 'end', ...inputs.extraArgs], true),
      { ...qualor('abort', image, ['dotnet', 'abort'], false), onFailureOnly: true },
    ],
  };
}
