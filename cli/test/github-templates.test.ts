import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { parseCommandLine } from '../src/args';

/**
 * github.md §11: the workflow to copy and the App manifest, in `integrations/github/` (not under
 * `templates/`, the GitLab CI/CD catalog's component directory). GitHub itself is not run here.
 */
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const read = (name: string) =>
  readFileSync(path.join(ROOT, 'integrations', 'github', name), 'utf8');

describe('integrations/github/qualor.yml', () => {
  const text = read('qualor.yml');
  const workflow = parse(text) as {
    on: Record<string, unknown>;
    permissions: Record<string, string>;
    jobs: Record<
      string,
      {
        if?: string;
        permissions?: unknown;
        container: { image: string; options: string };
        steps: {
          uses?: string;
          with?: Record<string, unknown>;
          run?: string;
          env?: Record<string, string>;
        }[];
      }
    >;
  };
  const job = workflow.jobs.qualor!;

  it('runs on pull requests and on pushes, never on pull_request_target', () => {
    expect(Object.keys(workflow.on).sort()).toEqual(['pull_request', 'push']);
    // The header comment warns against it by name; no line of the workflow itself uses it.
    const code = text.split('\n').filter((line) => !line.trimStart().startsWith('#'));
    expect(code.join('\n')).not.toContain('pull_request_target');
  });

  it('has one job, which skips pull requests from forks (GitHub gives them no secrets)', () => {
    expect(Object.keys(workflow.jobs)).toEqual(['qualor']);
    expect(job.if).toBe(
      "github.event_name == 'push' || github.event.pull_request.head.repo.full_name == github.repository",
    );
  });

  it('asks GitHub for nothing but reading the repository (the App posts)', () => {
    expect(workflow.permissions).toEqual({ contents: 'read' });
    // No job widens them.
    for (const j of Object.values(workflow.jobs)) expect(j.permissions).toBeUndefined();
  });

  it('checks out the pull request head with full history and no stored credentials, with checkout pinned to a commit', () => {
    const checkout = job.steps.find((s) => s.uses?.startsWith('actions/checkout@'));
    expect(checkout?.uses).toMatch(/^actions\/checkout@[0-9a-f]{40}$/);
    expect(checkout?.with).toEqual({
      'fetch-depth': 0,
      'persist-credentials': false,
      ref: '${{ github.event.pull_request.head.sha || github.sha }}',
    });
    for (const step of job.steps) if (step.uses) expect(step.uses).toMatch(/@[0-9a-f]{40}$/);
  });

  it('runs the scanner image named by a variable, as the runner user, with the token from a secret', () => {
    expect(job.container).toEqual({
      image: '${{ vars.QUALOR_SCANNER_IMAGE }}',
      options: '--user 1001',
    });
    const scan = job.steps.find((s) => s.run?.startsWith('qualor scan'));
    expect(scan?.env).toEqual({
      QUALOR_URL: '${{ vars.QUALOR_URL }}',
      QUALOR_TOKEN: '${{ secrets.QUALOR_TOKEN }}',
    });
    expect(() => parseCommandLine(scan!.run!.split(/\s+/).slice(1))).not.toThrow();
  });

  it('never prints the token, and puts no expression into a command', () => {
    // The token reaches the scan only through its environment: no step's command names it.
    for (const step of job.steps) expect(step.run ?? '').not.toMatch(/QUALOR_TOKEN|secrets\./);
    // An expression in `run:` is pasted into the shell script before it runs (script injection).
    for (const step of job.steps) expect(step.run ?? '').not.toContain('${{');
    expect(text.match(/secrets\.QUALOR_TOKEN/g)).toHaveLength(1);
    expect(text).not.toMatch(/persist-credentials:\s*true/);
  });

  it('says where a dependency install step goes', () => {
    expect(text).toMatch(/# .*install.*dependencies|# .*dependencies.*install/i);
  });
});

interface Step {
  name?: string;
  if?: string;
  uses?: string;
  with?: Record<string, unknown>;
  run?: string;
  env?: Record<string, string>;
}

describe('integrations/github/qualor-dotnet.yml (github.md §11, config.md §6.1)', () => {
  const text = read('qualor-dotnet.yml');
  const workflow = parse(text) as {
    on: Record<string, unknown>;
    permissions: Record<string, string>;
    jobs: Record<
      string,
      {
        if?: string;
        permissions?: unknown;
        container: { image: string; options: string };
        steps: Step[];
      }
    >;
  };
  const plain = parse(read('qualor.yml')) as typeof workflow;
  const job = workflow.jobs.qualor!;
  const run = (prefix: string) => {
    const found = job.steps.filter((s) => s.run?.trim().startsWith(prefix));
    expect(found).toHaveLength(1);
    return found[0]!;
  };

  it("has the plain template's triggers, fork guard, permissions and pinned checkout", () => {
    expect(workflow.on).toEqual(plain.on);
    expect(workflow.permissions).toEqual({ contents: 'read' });
    expect(Object.keys(workflow.jobs)).toEqual(['qualor']);
    expect(job.if).toBe(plain.jobs.qualor!.if);
    expect(job.permissions).toBeUndefined();
    const checkout = job.steps.find((s) => s.uses?.startsWith('actions/checkout@'));
    expect(checkout).toEqual(plain.jobs.qualor!.steps.find((s) => s.uses === checkout?.uses));
    for (const step of job.steps) if (step.uses) expect(step.uses).toMatch(/@[0-9a-f]{40}$/);
    const code = text.split('\n').filter((line) => !line.trimStart().startsWith('#'));
    expect(code.join('\n')).not.toContain('pull_request_target');
  });

  it('runs qualor/scanner-dotnet, named by its own variable, as the runner user', () => {
    expect(job.container).toEqual({
      image: '${{ vars.QUALOR_SCANNER_DOTNET_IMAGE }}',
      options: '--user 1001',
    });
    expect(text).toMatch(/QUALOR_SCANNER_DOTNET_IMAGE: qualor\/scanner-dotnet:<tag>/);
  });

  it('runs begin, the build, end, and abort on failure or cancellation, in that order, with commands the CLI accepts', () => {
    const begin = run('qualor dotnet begin');
    const build = run('dotnet build');
    const end = run('qualor dotnet end');
    const abort = run('qualor dotnet abort');
    const order = [begin, build, end, abort].map((s) => job.steps.indexOf(s));
    expect(order).toEqual([...order].sort((a, b) => a - b));
    expect(build.run!.trim()).toBe('dotnet build --no-incremental');
    // A cancelled run on a persistent self-hosted runner must clean up too (abort is idempotent).
    expect(abort.if).toBe('failure() || cancelled()');
    for (const s of [begin, build, end]) expect(s.if).toBeUndefined();
    expect(parseCommandLine(begin.run!.trim().split(/\s+/).slice(1))).toEqual({
      name: 'dotnet-begin',
    });
    expect(parseCommandLine(end.run!.trim().split(/\s+/).slice(1))).toMatchObject({
      name: 'dotnet-end',
    });
    expect(parseCommandLine(abort.run!.trim().split(/\s+/).slice(1))).toEqual({
      name: 'dotnet-abort',
    });
    // A comment says to replace the build with the project's own.
    expect(text).toMatch(/# .*[Rr]eplace.*build/);
  });

  it("gives the URL and the token to the end step only: the build runs the repository's code", () => {
    const end = run('qualor dotnet end');
    expect(end.env).toEqual({
      QUALOR_URL: '${{ vars.QUALOR_URL }}',
      QUALOR_TOKEN: '${{ secrets.QUALOR_TOKEN }}',
    });
    for (const step of job.steps) {
      if (step !== end) expect(step.env ?? {}).not.toHaveProperty('QUALOR_TOKEN');
    }
    expect(text.match(/secrets\.QUALOR_TOKEN/g)).toHaveLength(1);
    // No workflow- or job-level env, which every step (the build included) would inherit.
    expect(workflow).not.toHaveProperty('env');
    expect(job).not.toHaveProperty('env');
    expect(text).toMatch(/# .*token/i);
  });

  it('never prints the token, and puts no expression into a command', () => {
    for (const step of job.steps) expect(step.run ?? '').not.toMatch(/QUALOR_TOKEN|secrets\./);
    for (const step of job.steps) expect(step.run ?? '').not.toContain('${{');
    expect(text).not.toMatch(/persist-credentials:\s*true/);
  });

  it('says that HOME must stay writable (the hook and NuGet live there)', () => {
    expect(text).toMatch(/HOME/);
    expect(text).toMatch(/writable/);
  });
});

describe('integrations/github/app-manifest.json', () => {
  const manifest = JSON.parse(read('app-manifest.json')) as Record<string, unknown>;
  it('asks for the permissions and the event of github.md §2.1, nothing more', () => {
    expect(manifest.default_permissions).toEqual({
      checks: 'write',
      pull_requests: 'write',
      metadata: 'read',
    });
    expect(manifest.default_events).toEqual(['check_run']);
    expect(manifest.public).toBe(false);
    const hook = manifest.hook_attributes as { url: string; active: boolean };
    expect(hook.url).toMatch(/\/api\/v0\/github\/webhooks\/<connection id>$/);
    // Inactive until the administrator has a connection id and a secret (github.md §2.1).
    expect(hook.active).toBe(false);
  });
});
