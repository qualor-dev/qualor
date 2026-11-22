import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { VERSION } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { parseCommandLine } from '../src/args';
import { AZURE_PIPELINES_ENV } from '../src/config/ci';

/** The Azure Pipelines examples in `integrations/azure-devops/`. Azure itself is not run here. */
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const read = (name: string) =>
  readFileSync(path.join(ROOT, 'integrations', 'azure-devops', name), 'utf8');

interface Step {
  checkout?: string;
  fetchDepth?: number;
  persistCredentials?: boolean;
  task?: string;
  script?: string;
  displayName?: string;
  condition?: string;
  inputs?: Record<string, unknown>;
  env?: Record<string, string>;
}
interface Pipeline {
  trigger: unknown;
  pool: unknown;
  variables?: Record<string, string>;
  steps: Step[];
}

const TAG = VERSION.split('.').slice(0, 2).join('.');
const FILES = [
  { name: 'qualor.yml', docker: false, dotnet: false },
  { name: 'qualor-docker.yml', docker: true, dotnet: false },
  { name: 'qualor-dotnet.yml', docker: false, dotnet: true },
  { name: 'qualor-dotnet-docker.yml', docker: true, dotnet: true },
] as const;

/** Splits a shell line into words, honouring double quotes (no escapes are used in the examples). */
function words(line: string): string[] {
  return [...line.matchAll(/"([^"]*)"|(\S+)/g)].map((m) => m[1] ?? m[2]!);
}

/** The `docker run` commands of a script, backslash continuations joined, as word lists. */
function dockerRuns(script: string): string[][] {
  const joined = script.replace(/\\\n\s*/g, ' ');
  return joined
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.startsWith('docker run '))
    .map((l) => words(l).slice(1));
}

describe.each(FILES)('integrations/azure-devops/$name', ({ name, docker, dotnet }) => {
  const text = read(name);
  const pipeline = parse(text) as Pipeline;
  const scripts = pipeline.steps.filter((s) => s.script !== undefined);
  const code = text
    .split('\n')
    .filter((l) => !l.trimStart().startsWith('#'))
    .join('\n');

  it('triggers on every branch and tag, on an Ubuntu agent', () => {
    expect(pipeline.trigger).toEqual({ branches: { include: ['*'] }, tags: { include: ['*'] } });
    expect(pipeline.pool).toEqual({ vmImage: 'ubuntu-latest' });
  });

  it('says where it is configured, that Azure Repos ignores pr:, and what a tag does', () => {
    expect(text).toMatch(/QUALOR_URL/);
    expect(text).toMatch(/QUALOR_TOKEN[^\n]*secret/);
    expect(text).toMatch(/Azure Repos ignores `pr:`/);
    expect(text).toMatch(/Build validation/);
    expect(text).toMatch(/Linux agent with Docker/);
    expect(text).toMatch(/tags\.[\s#]+There[\s#]+the[\s#]+scan[\s#]+records[\s#]+a[\s#]+version/);
    expect(code).not.toMatch(/^pr:/m);
  });

  it('checks out the full history and keeps no credentials', () => {
    const checkouts = pipeline.steps.filter((s) => s.checkout !== undefined);
    expect(checkouts).toEqual([{ checkout: 'self', fetchDepth: 0, persistCredentials: false }]);
    expect(pipeline.steps[0]).toBe(checkouts[0]);
  });

  it('has no Cache@2 step (Azure DevOps Server has no pipeline caching)', () => {
    expect(pipeline.steps.filter((s) => s.task === 'Cache@2')).toEqual([]);
    expect(code).not.toContain('Cache@2');
  });

  it('maps the token only as an env: entry, never into a script or onto a command line', () => {
    expect(text.match(/\$\(QUALOR_TOKEN\)/g)).toHaveLength(1);
    for (const s of scripts) {
      // `-e QUALOR_TOKEN` by name is the only mention.
      expect((s.script ?? '').replace(/-e QUALOR_TOKEN\b/g, '')).not.toMatch(/QUALOR_TOKEN/);
    }
    const mapped = pipeline.steps.filter((s) => s.env !== undefined);
    expect(mapped).toHaveLength(1);
    expect(mapped[0]!.env).toEqual({ QUALOR_TOKEN: '$(QUALOR_TOKEN)' });
    expect(text).not.toMatch(/persistCredentials:\s*true/);
    expect(pipeline).not.toHaveProperty('env');
  });

  if (!docker) {
    it('uses the Qualor@0 task, with the .NET build only in the .NET form', () => {
      const tasks = pipeline.steps.filter((s) => s.task === 'Qualor@0');
      expect(tasks).toHaveLength(1);
      expect(tasks[0]!.inputs).toEqual(
        dotnet ? { dotnet: true, dotnetBuild: 'dotnet build --no-incremental' } : undefined,
      );
      expect(tasks[0]!.env).toEqual({ QUALOR_TOKEN: '$(QUALOR_TOKEN)' });
      expect(scripts).toEqual([]);
      expect(pipeline.variables).toBeUndefined();
    });
    return;
  }

  it('names the scanner image by its minor tag, a fixed one', () => {
    const image = `qualor/scanner${dotnet ? '-dotnet' : ''}:${TAG}`;
    expect(pipeline.variables).toEqual({ QUALOR_SCANNER_IMAGE: image });
    expect(text).not.toMatch(/qualor\/scanner[\w-]*:(0|latest|\d+\.\d+\.\d+)(?![.\d])/);
  });

  it('forwards exactly the CI variables the CLI reads, by name', () => {
    for (const run of scripts.flatMap((s) => dockerRuns(s.script!))) {
      const names = run.flatMap((w, i) =>
        w === '-e' && /^[A-Z_]+$/.test(run[i + 1]!) ? [run[i + 1]!] : [],
      );
      const forwarded = names.filter((n) => AZURE_PIPELINES_ENV.includes(n));
      expect(forwarded).toEqual([...AZURE_PIPELINES_ENV]);
      for (const n of names) {
        if (!AZURE_PIPELINES_ENV.includes(n)) {
          expect(['QUALOR_URL', 'QUALOR_TOKEN', 'PYTHONNOUSERSITE']).toContain(n);
        }
      }
    }
  });

  it('prepares the clone and the home directory in a first step of its own, without the token', () => {
    const first = scripts[0]!.script!;
    expect(scripts[0]!.env).toBeUndefined();
    expect(first).not.toContain('docker run');
    const head = first.indexOf('SYSTEM_PULLREQUEST_SOURCECOMMITID');
    const home = first.indexOf('mkdir -p "$(Agent.TempDirectory)/qualor-home"');
    expect(head).toBeGreaterThan(-1);
    expect(head).toBeLessThan(home);
    for (const part of [
      'tr A-F a-f',
      '${BUILD_REASON:-}" = PullRequest',
      '"${merge:-HEAD}^2^{commit}"',
      'git() { command git -c core.hooksPath=/dev/null -c core.fsmonitor=false "$@"; }',
      'git checkout --detach "$head"',
      'Set fetchDepth: 0 on the checkout step.',
      'Could not read the pull request head from the clone:',
      '"$status" -eq 1',
    ]) {
      expect(first).toContain(part);
    }
    // Only the first script prepares the clone.
    for (const s of scripts.slice(1)) expect(s.script).not.toContain('rev-parse');
  });

  it('stops a script at its first failing command', () => {
    for (const s of scripts) expect(s.script).toMatch(/^set -euo pipefail\n/);
  });

  it('runs begin, the build, end and abort as four docker runs (the task test compares their flags)', () => {
    const found = scripts.flatMap((s) => dockerRuns(s.script!));
    expect(found).toHaveLength(dotnet ? 4 : 1);
    expect(found.every((run) => run.slice(0, 3).join(' ') === 'run --rm --user')).toBe(true);
    // `abort` is the last step of the .NET form, after a failure only.
    const abort = scripts.find((s) => /dotnet abort/.test(s.script ?? ''));
    if (dotnet) expect(abort?.condition).toBe('failure()');
    else expect(abort).toBeUndefined();
    for (const s of scripts) if (s !== abort) expect(s.condition).toBeUndefined();
  });

  it('gives the server variables to the scan or end step only, and nothing of QUALOR_ to the build', () => {
    const steps = scripts.map((s) => s.script!);
    const withServer = steps.filter((s) => /-e QUALOR_URL -e QUALOR_TOKEN/.test(s));
    expect(withServer).toHaveLength(1);
    expect(withServer[0]).toMatch(dotnet ? /dotnet end$/m : /scan$/m);
    expect(pipeline.steps.find((s) => s.env)?.script).toBe(withServer[0]);
    if (!dotnet) return;
    const build = steps.find((s) => s.includes('--entrypoint sh'))!;
    expect(build.replaceAll('$(QUALOR_SCANNER_IMAGE)', '')).not.toMatch(/QUALOR_/);
    expect(build).not.toMatch(/GIT_CONFIG_GLOBAL|PYTHONNOUSERSITE/);
    expect(build).toContain(
      '--mount type=bind,source=$(Build.SourcesDirectory)/.git,target=/src/.git,readonly',
    );
    expect(build).toContain('-c "dotnet build --no-incremental"');
    const begin = steps.find((s) => /dotnet begin$/m.test(s))!;
    expect(begin).not.toMatch(/QUALOR_URL|QUALOR_TOKEN/);
    // begin, build, end, abort in that order; a comment says to replace the build.
    const at = ['dotnet begin', '--entrypoint sh', 'dotnet end', 'dotnet abort'].map((p) =>
      steps.findIndex((s) => s.includes(p)),
    );
    expect(at).toEqual([1, 2, 3, 4]);
    expect(text).toMatch(/# .*[Rr]eplace.*build/);
  });

  it('writes qualor command lines the CLI accepts', () => {
    const commands = scripts
      .flatMap((s) => s.script!.split('\n'))
      .map((l) => l.trim())
      .filter((l) => /^\$\(QUALOR_SCANNER_IMAGE\) (scan|dotnet)/.test(l))
      .map((l) => words(l).slice(1));
    expect(commands.length).toBe(dotnet ? 3 : 1);
    for (const c of commands) expect(() => parseCommandLine(c)).not.toThrow();
  });
});
