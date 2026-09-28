import { must, REPO_ROOT, run, type Api, type RunResult, type Stack } from './stack';
import { scanWorkspace, workspaceGit, workspaceWrite, type Workspace } from './workspace';

/**
 * Scans with the `qualor/scanner` image against a throwaway stack (plan 1G), shared by
 * `pnpm dogfood`, `pnpm deploy:exit-test` and `pnpm deploy:screenshots`.
 */
export const QUALOR_PROJECT = { key: 'qualor/qualor', name: 'Qualor' };

/** The exit test's merge request: one `==` on a new line of a new TypeScript file. */
export const EXIT_TEST_FILE = 'packages/shared/src/dogfood-exit-test.ts';
export const LOOSE_EQUALITY_SOURCE =
  '/** Added by the dogfood exit test (plan 1G): `==` must fail the gate. */\n' +
  'export const looselyEqual = (a: unknown, b: unknown): boolean => a == b;\n';
export const STRICT_EQUALITY_SOURCE =
  '/** Added by the dogfood exit test (plan 1G): nothing here to report. */\n' +
  'export const strictlyEqual = (a: unknown, b: unknown): boolean => a === b;\n';

export function log(line: string): void {
  process.stdout.write(`${line}\n`);
}

/**
 * The workflow command that hides `value` in the rest of a GitHub Actions log (the command line
 * itself is not shown), or nothing elsewhere: GitLab CI can only mask variables defined in its
 * settings, so there the scripts rely on never printing the value.
 */
export function ciMask(value: string, env: NodeJS.ProcessEnv = process.env): string {
  return env['GITHUB_ACTIONS'] === 'true' ? `::add-mask::${value}\n` : '';
}

/** The lines of the CLI's stderr worth showing: skipped analyzers and the gate verdict. */
export function gateLines(stderr: string): string[] {
  return stderr
    .split('\n')
    .filter((l) => /quality gate|\((passed|failed|error|no_value)\)$|: skipped \(|failed/.test(l))
    .map((l) => `    ${l.trim()}`);
}

/** LCOV `SF:` paths with forward slashes (a report written on Windows has backslashes). */
export function portableLcov(text: string): string {
  return text.replace(/^SF:(.*)$/gm, (_, p: string) => `SF:${p.replaceAll('\\', '/')}`);
}

export interface ScanTarget {
  ws: Workspace;
  stack: Stack;
  token: string;
  projectKey: string;
  /** The repository inside the workspace volume (default `/src`). */
  workdir?: string;
}

/** One `qualor scan`; logs its exit code, duration and gate lines. */
export function scanAs(t: ScanTarget, label: string, args: string[]): RunResult {
  const started = Date.now();
  const r = scanWorkspace(t.ws, {
    network: t.stack.network,
    token: t.token,
    workdir: t.workdir,
    args: ['--project-key', t.projectKey, ...args],
  });
  log(`${label}: exit ${r.code} in ${((Date.now() - started) / 1000).toFixed(0)} s`);
  for (const line of gateLines(r.stderr)) log(line);
  return r;
}

/** Commits `text` as `file` on a new `branch` from `main` in the workspace. */
export function commitOnBranch(ws: Workspace, branch: string, file: string, text: string): void {
  workspaceGit(ws, ['checkout', '--quiet', '-B', branch, 'main']);
  workspaceWrite(ws, file, text);
  workspaceGit(ws, ['add', file]);
  workspaceGit(ws, ['commit', '--quiet', '-m', `dogfood: ${file} on ${branch}`]);
}

/**
 * Runs a dogfood flow and returns its exit code; a thrown error (compose, the checkout copy, the
 * install, the API) is an infrastructure failure: logged, and exit 4 like the CLI's "server
 * unreachable" (config.md §7), never 1, which means "the gate failed".
 */
export async function exitFourOnFailure(flow: () => Promise<number>): Promise<number> {
  try {
    return await flow();
  } catch (err) {
    log(`infrastructure failure: ${err instanceof Error ? err.message : String(err)}`);
    return 4;
  }
}

export function resolveRevision(rev: string): string {
  return must(
    run('git', ['rev-parse', '--verify', '--quiet', `${rev}^{commit}`], { cwd: REPO_ROOT }),
    `git rev-parse ${rev}`,
  ).stdout.trim();
}

export interface BranchSummary {
  id: string;
  name: string;
  kind: 'branch' | 'merge_request';
  gateStatus: string | null;
  measures: Record<string, number | null>;
}

/** A branch's open issues by rule, as `<rule> <count>` (for example `eslint:eqeqeq 1`). */
export async function openIssuesByRule(api: Api, branchId: string): Promise<string[]> {
  const page = await api.json<{ facets?: { rule?: { value: string; count: number }[] } }>(
    'GET',
    `/api/v0/issues?branchId=${branchId}&status=open&limit=1&facets=rule`,
  );
  return (page.facets?.rule ?? []).map((f) => `${f.value} ${f.count}`);
}

/** Logs every branch's gate and headline measures, and its open issues by rule. */
export async function logBranches(api: Api, projectId: string): Promise<BranchSummary[]> {
  const { items } = await api.json<{ items: BranchSummary[] }>(
    'GET',
    `/api/v0/projects/${projectId}/branches`,
  );
  for (const b of items) {
    const m = b.measures;
    log(
      `${b.kind} ${b.name}: gate ${b.gateStatus}, ncloc ${m['ncloc']}, issues ${m['issues']}, ` +
        `new_issues ${m['new_issues']}, coverage ${m['coverage']}, new_coverage ${m['new_coverage']}, ` +
        `duplicated_lines_density ${m['duplicated_lines_density']}`,
    );
    const rules = await openIssuesByRule(api, b.id);
    if (rules.length > 0) log(`    open issues by rule: ${rules.join(', ')}`);
  }
  return items;
}
