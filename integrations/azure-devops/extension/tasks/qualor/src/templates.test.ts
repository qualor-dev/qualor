import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { AZURE_PIPELINES_ENV } from '../../../../../../cli/src/config/ci';
import { planRun, type TaskContext } from './plan';

/**
 * The docker examples (integrations/azure-devops/qualor-*docker.yml) run what the task runs: the
 * `docker run` commands in their scripts equal `planRun`'s arguments, with the host values as the
 * examples spell them. (cli/test/azure-templates.test.ts checks the rest of the examples.)
 */
const EXAMPLES = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../..');

/** Splits a shell line into words, honouring double quotes (the examples use no escapes). */
const words = (line: string): string[] =>
  [...line.matchAll(/"([^"]*)"|(\S+)/g)].map((m) => m[1] ?? m[2]!);

/** The `docker run` commands of a file, backslash continuations joined, as word lists. */
function dockerRuns(file: string): string[][] {
  const text = readFileSync(path.join(EXAMPLES, file), 'utf8').replace(/\\\r?\n\s*/g, ' ');
  return text
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.startsWith('docker run '))
    .map((l) => words(l).slice(1));
}

/** A planned argument as the example writes it. */
const asExample = (arg: string): string =>
  arg === '1234:5678'
    ? '$(id -u):$(id -g)'
    : arg.replace(/^qualor\/scanner(-dotnet)?:TAG$/, '$(QUALOR_SCANNER_IMAGE)');

function planned(dotnet: boolean): string[][] {
  const ctx: TaskContext = {
    platform: 'linux',
    uid: 1234,
    gid: 5678,
    sourcesDir: '$(Build.SourcesDirectory)',
    tempDir: '$(Agent.TempDirectory)',
    env: Object.fromEntries(AZURE_PIPELINES_ENV.map((n) => [n, 'x'])),
    qualorUrl: 'https://qualor.example.test',
    qualorToken: 'token',
    taskVersion: 'TAG',
  };
  const plan = planRun(
    { dotnet, dotnetBuild: 'dotnet build --no-incremental', imageTag: 'TAG', extraArgs: [] },
    ctx,
  );
  if ('problem' in plan) throw new Error(plan.problem);
  return plan.steps.map((step) => step.args.map(asExample));
}

describe('the docker examples', () => {
  it.each([
    ['qualor-docker.yml', false],
    ['qualor-dotnet-docker.yml', true],
  ] as const)('%s runs the docker commands the task plans', (file, dotnet) => {
    expect(dockerRuns(file)).toEqual(planned(dotnet));
  });
});
