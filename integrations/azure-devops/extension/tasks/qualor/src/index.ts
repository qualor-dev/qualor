import { execFile } from 'node:child_process';
import { mkdirSync, readFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Writable } from 'node:stream';
import { promisify } from 'node:util';
import * as tl from 'azure-pipelines-task-lib/task';
import { splitArguments } from './args';
import { headCheckout } from './head';
import {
  planRun,
  STEP_LABEL,
  stepFailure,
  stepProcessEnv,
  withoutQualor,
  type DockerStep,
} from './plan';

/**
 * The Qualor@0 task: task-lib wiring only. plan.ts decides what runs, head.ts checks out the pull
 * request head, args.ts splits `arguments`; this file reads the inputs and variables and runs
 * docker.
 */

const execFileAsync = promisify(execFile);

const DOCKER_MISSING = 'Docker is not installed on this agent.';

function messageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * A secret variable, read without a log line: task-lib's getVariable writes
 * `##vso[task.debug]<name>=<value>`, which the agent masks for a secret variable only, not for a
 * token in a plain variable or an `env:` mapping. The value is registered with setSecret at once.
 */
function secretVariable(name: string): string | undefined {
  tl.setStdStream(new Writable({ write: (_chunk, _encoding, done) => done() }));
  let value: string | undefined;
  try {
    value = tl.getVariable(name);
  } finally {
    tl.setStdStream(process.stdout);
  }
  tl.setSecret(value);
  return value;
}

/** The task's version from the task.json beside the bundle (the extension's version). */
function taskVersion(): string {
  const task = JSON.parse(readFileSync(path.join(__dirname, 'task.json'), 'utf8')) as {
    version?: { Major?: unknown; Minor?: unknown; Patch?: unknown };
  };
  const parts = [task.version?.Major, task.version?.Minor, task.version?.Patch];
  if (!parts.every((p) => Number.isInteger(p))) throw new Error('task.json has no version');
  return parts.join('.');
}

/** git in the sources directory, without the agent's QUALOR_ variables (head.ts adds its -c options). */
function git(cwd: string): (args: string[]) => Promise<string> {
  const env = withoutQualor(process.env);
  return async (args) => (await execFileAsync('git', args, { cwd, env, encoding: 'utf8' })).stdout;
}

async function runStep(docker: string, step: DockerStep): Promise<void> {
  // The tool runner logs the command line: step.args hold no pipeline value (plan.ts).
  await tl
    .tool(docker)
    .arg(step.args)
    .execAsync({ env: stepProcessEnv(process.env, step) });
}

/** Runs the steps in order; after a failed step, the `onFailureOnly` ones (`dotnet abort`). */
async function runSteps(docker: string, steps: readonly DockerStep[]): Promise<string | null> {
  for (const step of steps.filter((s) => s.onFailureOnly !== true)) {
    try {
      await runStep(docker, step);
    } catch (err) {
      for (const cleanup of steps.filter((s) => s.onFailureOnly === true)) {
        try {
          await runStep(docker, cleanup);
        } catch (cleanupErr) {
          tl.warning(`${STEP_LABEL[cleanup.name]} failed: ${messageOf(cleanupErr)}`);
        }
      }
      return stepFailure(step.name, messageOf(err));
    }
  }
  return null;
}

/** The task; resolves with the problem that failed it, or null. */
async function run(): Promise<string | null> {
  const qualorToken = secretVariable('QUALOR_TOKEN');
  const sourcesDir = tl.getVariable('Build.SourcesDirectory') || process.cwd();
  const tempDir = tl.getVariable('Agent.TempDirectory') || os.tmpdir();
  const plan = planRun(
    {
      command: tl.getInput('command', false) === 'fix' ? 'fix' : 'scan',
      dotnet: tl.getBoolInput('dotnet', false),
      dotnetBuild: tl.getInput('dotnetBuild', false) ?? '',
      imageTag: tl.getInput('imageTag', false) ?? '',
      extraArgs: splitArguments(tl.getInput('arguments', false) ?? ''),
    },
    {
      platform: process.platform,
      uid: process.getuid?.() ?? -1,
      gid: process.getgid?.() ?? -1,
      sourcesDir,
      tempDir,
      env: process.env,
      qualorUrl: tl.getVariable('QUALOR_URL'),
      qualorToken,
      taskVersion: taskVersion(),
    },
  );
  if ('problem' in plan) return plan.problem;

  const docker = tl.which('docker', false);
  if (docker === '') return DOCKER_MISSING;
  // Created here, as the agent user: docker would create a missing bind-mount source as root.
  mkdirSync(path.join(tempDir, 'qualor-home'), { recursive: true });

  // A fix run is on the main branch: there is no pull request head to check out.
  if (plan.steps[0]?.name !== 'fix') {
    const head = await headCheckout(git(sourcesDir), process.env);
    if ('problem' in head) return head.problem;
    if (head.checkedOut !== null)
      console.log(`Checked out the pull request head ${head.checkedOut}.`);
  }

  return runSteps(docker, plan.steps);
}

run().then(
  (problem) => {
    if (problem !== null) tl.setResult(tl.TaskResult.Failed, problem);
  },
  (err: unknown) => tl.setResult(tl.TaskResult.Failed, messageOf(err)),
);
