import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import {
  ciMask,
  commitOnBranch,
  EXIT_TEST_FILE,
  exitFourOnFailure,
  log,
  logBranches,
  openIssuesByRule,
  LOOSE_EQUALITY_SOURCE,
  portableLcov,
  QUALOR_PROJECT,
  resolveRevision,
  scanAs,
  STRICT_EQUALITY_SOURCE,
  type BranchSummary,
  type ScanTarget,
} from './scans';
import { Api, startStack, stopStack, stopStacksOnSignal, type RunResult } from './stack';
import {
  createWorkspace,
  removeWorkspace,
  workspaceGit,
  workspaceWrite,
  type Workspace,
} from './workspace';

/**
 * Qualor scans itself (brief rule 4, plan 1G) with the `qualor/scanner` image against a throwaway
 * `qualor/server` stack and the default "Qualor way" gate.
 *
 *   pnpm dogfood --base <rev> [--head <rev>] [--mr <id> --mr-target <branch>] [--coverage <lcov>]
 *     scans `base` as the main branch, then `head` (default HEAD) as merge request `id`, or as the
 *     next main-branch analysis without `--mr`, and exits with the head scan's exit code
 *     (config.md §7). `--mr-target` (default main) is the project's main branch, as which `base`
 *     is scanned. The `dogfood` CI jobs run this.
 *   pnpm deploy:exit-test
 *     the Phase 1 exit test: HEAD as main (the gate passes), a merge request that adds a
 *     fixture-known issue on new code (ESLint `eqeqeq`, as in fixtures/ts-basic: the gate fails on
 *     new_issues, exit 1), and a clean merge request (the gate passes).
 * A failure of the stack, the checkout copy or the install exits 4, never 1 (the gate's code).
 */

/** What a dogfood flow gets: the scan target, and the API and project to check results with. */
interface QualorRun extends ScanTarget {
  api: Api;
  projectId: string;
}
async function withQualorProject(
  label: string,
  revision: string,
  body: (t: QualorRun) => Promise<number>,
  mainBranch = 'main',
): Promise<number> {
  // A cancelled run (Ctrl+C, a CI timeout) tears the stack down too; the CI jobs' last step
  // removes the workspace volume, which carries DEPLOY_LABEL.
  const undoSignals = stopStacksOnSignal();
  const stack = await startStack(`qualor-${label}-${process.pid}`);
  process.stdout.write(ciMask(stack.admin.password));
  log(`stack up in ${(stack.upMs / 1000).toFixed(1)} s at ${stack.url}`);
  // Removed in `finally` even when copying the checkout into it fails halfway.
  const ws: Workspace = { volume: `qualor-${label}-${process.pid}` };
  try {
    createWorkspace(ws.volume, revision, mainBranch);
    const api = new Api(stack.url);
    await api.login(stack.admin.username, stack.admin.password);
    const project = await api.createProject(QUALOR_PROJECT.key, QUALOR_PROJECT.name, mainBranch);
    // Created through the API for this run only and handed to the scanner through its environment.
    process.stdout.write(ciMask(project.token));
    try {
      const target = { ws, stack, token: project.token, projectKey: QUALOR_PROJECT.key };
      return await body({ ...target, api, projectId: project.id });
    } finally {
      await logBranches(api, project.id);
    }
  } finally {
    removeWorkspace(ws);
    stopStack(stack);
    undoSignals();
  }
}

async function exitTest(): Promise<number> {
  const head = resolveRevision('HEAD');
  return withQualorProject('exit-test', head, async (t) => {
    const failures: string[] = [];
    const main = scanAs(t, `main at ${head.slice(0, 12)}`, ['--branch', 'main']);
    if (main.code !== 0) failures.push(`the main-branch scan exited ${main.code}, expected 0`);
    if (!semgrepSkippedForQB3(main)) {
      failures.push('Semgrep was not skipped because the image ships no rules');
    }

    commitOnBranch(t.ws, 'dogfood/eqeqeq', EXIT_TEST_FILE, LOOSE_EQUALITY_SOURCE);
    const mr = ['--mr-target', 'main', '--mr'];
    const bad = scanAs(t, 'MR !1 adds `a == b`', ['--branch', 'dogfood/eqeqeq', ...mr, '1']);
    if (bad.code !== 1) failures.push(`the MR with a new issue exited ${bad.code}, expected 1`);
    if (!/new_issues > 0: 1 \(failed\)/.test(bad.stderr)) {
      failures.push('the MR gate did not fail on exactly one new issue');
    }
    // Not logBranches: the summary is logged once, at the end of withQualorProject.
    const { items: branches } = await t.api.json<{ items: BranchSummary[] }>(
      'GET',
      `/api/v0/projects/${t.projectId}/branches`,
    );
    const mr1 = branches.find((b) => b.kind === 'merge_request' && b.name === '1');
    const rules = mr1 === undefined ? [] : await openIssuesByRule(t.api, mr1.id);
    if (rules.join(', ') !== 'eslint:eqeqeq 1') {
      failures.push(`MR !1's open issues are [${rules.join(', ')}], expected [eslint:eqeqeq 1]`);
    }

    commitOnBranch(t.ws, 'dogfood/clean', EXIT_TEST_FILE, STRICT_EQUALITY_SOURCE);
    const clean = scanAs(t, 'MR !2 adds `a === b`', ['--branch', 'dogfood/clean', ...mr, '2']);
    if (clean.code !== 0) failures.push(`the clean MR exited ${clean.code}, expected 0`);

    for (const f of failures) log(`FAIL ${f}`);
    log(
      failures.length === 0
        ? 'exit test passed: the gate blocks an MR that adds a fixture-known issue'
        : 'exit test FAILED',
    );
    return failures.length === 0 ? 0 : 1;
  });
}

/** The scan logged `semgrep: skipped (…)`: the image's empty qualor-default rules. */
function semgrepSkippedForQB3(r: RunResult): boolean {
  return /semgrep: skipped \(the qualor\/scanner image ships no Semgrep rules yet;/.test(r.stderr);
}

interface DogfoodOptions {
  base: string;
  head: string;
  mr?: string;
  mrTarget: string;
  coverage?: string;
}

async function dogfood(o: DogfoodOptions): Promise<number> {
  const base = resolveRevision(o.base);
  const head = resolveRevision(o.head);
  const mainBranch = o.mrTarget;
  return withQualorProject(
    'dogfood',
    base,
    async (t) => {
      const first = scanAs(t, `baseline: ${mainBranch} at ${base.slice(0, 12)}`, [
        '--branch',
        mainBranch,
      ]);
      if (first.code !== 0) {
        process.stderr.write(first.stderr);
        log(`the baseline scan exited ${first.code}, so ${head.slice(0, 12)} cannot be judged`);
        // A failed baseline gate is not the head's verdict: report it as a scan problem (4).
        return first.code === 1 ? 4 : first.code;
      }
      const branch = o.mr === undefined ? mainBranch : `mr-${o.mr}`;
      workspaceGit(t.ws, ['checkout', '--quiet', '-B', branch, head]);
      if (o.coverage !== undefined) {
        workspaceWrite(t.ws, 'coverage/lcov.info', portableLcov(readFileSync(o.coverage, 'utf8')));
      }
      const mrArgs = o.mr === undefined ? [] : ['--mr', o.mr, '--mr-target', mainBranch];
      const label = `${o.mr === undefined ? mainBranch : `MR !${o.mr}`} at ${head.slice(0, 12)}`;
      const r = scanAs(t, label, ['--branch', branch, ...mrArgs]);
      if (r.code !== 0) process.stderr.write(r.stderr);
      return r.code;
    },
    mainBranch,
  );
}

const { values } = parseArgs({
  options: {
    'exit-test': { type: 'boolean' },
    base: { type: 'string' },
    head: { type: 'string', default: 'HEAD' },
    mr: { type: 'string' },
    'mr-target': { type: 'string', default: 'main' },
    coverage: { type: 'string' },
  },
});
if (values['exit-test']) {
  process.exitCode = await exitFourOnFailure(exitTest);
} else if (values.base === undefined) {
  process.stderr.write('usage: pnpm dogfood --base <rev> [--head <rev>] [--mr <id>] ...\n');
  process.exitCode = 2;
} else {
  const { base } = values;
  process.exitCode = await exitFourOnFailure(() =>
    dogfood({
      base,
      head: values.head,
      mr: values.mr,
      mrTarget: values['mr-target'],
      coverage: values.coverage,
    }),
  );
}
