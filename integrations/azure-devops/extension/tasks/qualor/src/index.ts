import { execFile } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Writable } from 'node:stream';
import { promisify } from 'node:util';
import * as tl from 'azure-pipelines-task-lib/task';
import { ToolRunner } from 'azure-pipelines-task-lib/toolrunner';
import { headCheckout } from './head';
import { planRun, type DockerStep } from './plan';

/**
 * The Qualor@0 task: task-lib wiring only. plan.ts decides what runs, head.ts checks out the pull
 * request head; this file reads the inputs and variables and runs docker.
 */

const execFileAsync = promisify(execFile);

const DOCKER_MISSING = 'Docker is not installed on this agent.';

const LABEL: Record<DockerStep['name'], string> = {
  scan: 'qualor scan',
  begin: 'qualor dotnet begin',
  build: 'The build command',
  end: 'qualor dotnet end',
  abort: 'qualor dotnet abort',
};

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

/**
 * `arguments` split as task-lib splits a command line (`ToolRunner.line`). Its parser is private
 * and uses no instance state; a ToolRunner instance would need the tool to exist on the agent.
 */
function splitArguments(line: string): string[] {
  const parse = (ToolRunner.prototype as unknown as { _argStringToArray?: unknown })
    ._argStringToArray;
  const args: unknown =
    typeof parse === 'function' ? parse.call(ToolRunner.prototype, line) : undefined;
  if (!Array.isArray(args) || !args.every((a) => typeof a === 'string')) {
    throw new Error(
      'azure-pipelines-task-lib no longer has the argument parser of ToolRunner.line',
    );
  }
  return args;
}

function git(cwd: string): (args: string[]) => Promise<string> {
  return async (args) => (await execFileAsync('git', args, { cwd, encoding: 'utf8' })).stdout;
}

function definedEnv(extra: Record<string, string>): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [name, value] of Object.entries(process.env)) {
    if (value !== undefined) env[name] = value;
  }
  return { ...env, ...extra };
}

async function runStep(docker: string, step: DockerStep): Promise<void> {
  // The tool runner logs the command line: step.args hold no pipeline value (plan.ts).
  await tl
    .tool(docker)
    .arg(step.args)
    .exec({ env: definedEnv(step.env) });
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
          tl.warning(`${LABEL[cleanup.name]} failed: ${messageOf(cleanupErr)}`);
        }
      }
      return `${LABEL[step.name]} failed: ${messageOf(err)}`;
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
    },
  );
  if ('problem' in plan) return plan.problem;

  const docker = tl.which('docker', false);
  if (docker === '') return DOCKER_MISSING;
  // Created here, as the agent user: docker would create a missing bind-mount source as root.
  mkdirSync(path.join(tempDir, 'qualor-home'), { recursive: true });

  const head = await headCheckout(git(sourcesDir), process.env);
  if ('problem' in head) return head.problem;
  if (head.checkedOut !== null)
    console.log(`Checked out the pull request head ${head.checkedOut}.`);

  return runSteps(docker, plan.steps);
}

run().then(
  (problem) => {
    if (problem !== null) tl.setResult(tl.TaskResult.Failed, problem);
  },
  (err: unknown) => tl.setResult(tl.TaskResult.Failed, messageOf(err)),
);
