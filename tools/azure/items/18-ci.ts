import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import {
  BUILD_POLICY,
  answerOf,
  BuildSchema,
  buildLogs,
  createBranchAt,
  createDefinition,
  createPolicy,
  createPr,
  defaultQueueId,
  evaluations,
  keptLogLines,
  logText,
  ok,
  permissionsKey,
  printedValues,
  prWithMerge,
  probeSource,
  pushFiles,
  queuePermissions,
  refHead,
  repoInfo,
  result,
  shape,
  waitBuild,
  waitFor,
  type Pr,
  type ProbeContext,
  type ProbeItem,
  type Repo,
} from './common.js';

/** The images the bench builds from the branch (`ship-images.ps1`); they exist on the bench host only. */
export const BENCH_IMAGE_TAG = 'azure-dev';
/** Nothing is uploaded: the report goes into the checkout, where the next step reads it. */
export const DRY_RUN = '--dry-run --output /src/.qualor/report.json';
/** The private dev variant of the extension (`dev-overrides.json`). */
const EXTENSION = { publisher: 'qualor', id: 'qualor-dev' } as const;
/** The Qualor@0 task's id (task.json), the same in the dev variant. */
const QUALOR_TASK_ID = '86f47d06-36e4-4f79-9432-3ae5770d5288';
export const EXAMPLES = new URL('../../../integrations/azure-devops/', import.meta.url);

export type Form = 'docker' | 'task';
const PATHS: Record<Form, string> = {
  docker: '.azure-pipelines/qualor-docker.yml',
  task: '.azure-pipelines/qualor-task.yml',
};

/**
 * The step both forms end with: the report's `scm` block on one line. The report is gzipped
 * whatever its name says. Backticks, not `$(...)`: Azure DevOps would read that as a macro.
 */
export const PRINT_SCM = [
  '  - script: |',
  '      set -euo pipefail',
  '      report="$(Build.SourcesDirectory)/.qualor/report.json"',
  '      echo "QUALOR_SCM=`gzip -dc "$report" | jq -c .scm`"',
  '    displayName: Print the report scm block',
  '    condition: succeededOrFailed()',
].join('\n');

export type Swap = [RegExp, (match: string, ...groups: string[]) => string];

/** `text` with every swap applied once; throws when the example no longer has what a swap expects. */
export function swapped(
  name: string,
  text: string,
  swaps: Swap[],
  tail: string | null = PRINT_SCM,
): string {
  let out = text.replace(/\r\n/g, '\n');
  for (const [re, to] of swaps) {
    if (!re.test(out)) throw new Error(`${name} no longer matches ${String(re)}`);
    out = out.replace(re, to);
  }
  return tail === null ? `${out.trimEnd()}\n` : `${out.trimEnd()}\n\n${tail}\n`;
}

/** The bench's own pool and no CI trigger (only the Build validation policy queues builds). */
export const BENCH_SWAPS: Swap[] = [
  [/^trigger:\n(?: {2}.*\n)+/m, () => 'trigger: none\n'],
  [/^pool:\n {2}vmImage: ubuntu-latest\n/m, () => 'pool:\n  name: Default\n'],
];

/**
 * integrations/azure-devops/qualor-docker.yml as the bench runs it (ruling 3): the bench image,
 * `--dry-run --output` after `scan`, and the step that prints the report's `scm`.
 */
export function benchDockerYaml(example: string): string {
  return swapped('qualor-docker.yml', example, [
    ...BENCH_SWAPS,
    [
      /^( {2}QUALOR_SCANNER_IMAGE: )qualor\/scanner:\S+$/m,
      (_m, key) => `${key}qualor/scanner:${BENCH_IMAGE_TAG}`,
    ],
    [/\$\(QUALOR_SCANNER_IMAGE\) scan$/m, (m) => `${m} ${DRY_RUN}`],
  ]);
}

/**
 * integrations/azure-devops/qualor.yml as the bench runs it: the bench image tag in place of the
 * example's pin, and the arguments (a second `inputs:` block would not compile).
 */
export function benchTaskYaml(example: string): string {
  return swapped('qualor.yml', example, [
    ...BENCH_SWAPS,
    [
      /^( {2}- task: Qualor@0\n {4}displayName: Qualor scan\n {4}inputs:\n) {6}imageTag: .+\n/m,
      (_m, head) => `${head}      imageTag: ${BENCH_IMAGE_TAG}\n      arguments: ${DRY_RUN}\n`,
    ],
  ]);
}

export const example = (file: string): string =>
  readFileSync(fileURLToPath(new URL(file, EXAMPLES)), 'utf8');

/** The report's `scm` block, as far as item 18 reads it. */
const ScmSchema = z.object({
  provider: z.string(),
  revision: z.string(),
  branch: z.string().nullable(),
  mergeRequest: z
    .object({ id: z.string(), targetBranch: z.string(), sourceBranch: z.string() })
    .nullable(),
  azure: z
    .object({
      projectId: z.string().optional(),
      repositoryId: z.string().optional(),
      buildId: z.string().optional(),
      checkout: z.string().optional(),
    })
    .optional(),
});
type Scm = z.infer<typeof ScmSchema>;

export const branchName = (ref: string): string => ref.replace(/^refs\/heads\//, '');

/** Each assertion of the brief as `[what, expected, got]`. */
export function scmChecks(
  scm: Scm,
  want: { prId: number; target: string; source: string; repo: Repo; buildId: number; head: string },
): [string, string, string | undefined][] {
  return [
    ['provider', 'azure', scm.provider],
    ['mergeRequest.id', String(want.prId), scm.mergeRequest?.id],
    ['mergeRequest.targetBranch', branchName(want.target), scm.mergeRequest?.targetBranch],
    ['mergeRequest.sourceBranch', branchName(want.source), scm.mergeRequest?.sourceBranch],
    ['azure.projectId', want.repo.project.id.toLowerCase(), scm.azure?.projectId],
    ['azure.repositoryId', want.repo.id.toLowerCase(), scm.azure?.repositoryId],
    ['azure.buildId', String(want.buildId), scm.azure?.buildId],
    ['azure.checkout', 'head', scm.azure?.checkout],
    ['revision', want.head, scm.revision],
  ];
}

/** Whether the target's collection or organisation has the dev extension installed. */
export async function extensionInstalled(
  ctx: ProbeContext,
): Promise<{ installed: boolean; why: string }> {
  const client = ctx.admin ?? ctx.bot;
  const res = await client.request(
    'GET',
    '/_apis/extensionmanagement/installedextensions',
    undefined,
    { apiVersion: '7.0-preview.1' },
  );
  if (res.status !== 200) {
    // Services serves extension management on extmgmt.dev.azure.com, out of the client's reach:
    // ask whether the organisation's pipelines can use the task instead.
    const task = await client.request(
      'GET',
      `/_apis/distributedtask/tasks/${QUALOR_TASK_ID}`,
      undefined,
      { apiVersion: '7.0' },
    );
    const count = z.object({ count: z.number() }).safeParse(task.json);
    const available = task.status === 200 && count.success && count.data.count > 0;
    const versions = count.success ? `, ${count.data.count} versions` : '';
    const availability = available ? 'available' : `not available (HTTP ${task.status}${versions})`;
    return {
      installed: available,
      why: `installed extensions not readable here (HTTP ${res.status}); task ${QUALOR_TASK_ID} ${availability}`,
    };
  }
  const list = shape(
    z.object({
      value: z.array(
        z
          .object({
            publisherId: z.string(),
            extensionId: z.string(),
            version: z.string().optional(),
          })
          .loose(),
      ),
    }),
    res.json,
    'installed extensions',
  );
  const found = list.value.find(
    (e) => e.publisherId === EXTENSION.publisher && e.extensionId === EXTENSION.id,
  );
  return found
    ? {
        installed: true,
        why: `${EXTENSION.publisher}.${EXTENSION.id} ${found.version ?? '?'} installed`,
      }
    : { installed: false, why: `${EXTENSION.publisher}.${EXTENSION.id} not installed` };
}

/**
 * Authorizes the probe's definitions on the shared queue in one PATCH (item 8's authorizeQueue
 * handles one definition, and its after-clean-up check would see the other probe definition). The
 * clean-up takes the authorizations back; a check after clean-up compares the queue's permissions
 * with the first reading, the probe's definitions left out.
 */
export async function authorizeDefinitions(
  ctx: ProbeContext,
  queueId: number,
  ids: number[],
): Promise<string> {
  const before = await queuePermissions(ctx, queueId);
  const need = ids.filter((id) => !before.open && !before.authorized(id));
  if (need.length === 0) return 'queue open or pipelines already authorized';
  const ignore = new Set(ids);
  const without = (perms: typeof before.perms) =>
    permissionsKey({
      ...perms,
      pipelines: (perms.pipelines ?? []).filter((p) => !ignore.has(p.id)),
    });
  const p = `/${ctx.project}/_apis/pipelines/pipelinePermissions/queue/${queueId}`;
  const opts = { apiVersion: '7.0-preview.1' };
  ctx.cleanup.add(`restore the pipeline permissions of queue ${queueId}`, async () => {
    const now = await queuePermissions(ctx, queueId);
    const back = need.filter((id) => now.authorized(id));
    if (back.length === 0) return;
    ok(
      await ctx.bot.request(
        'PATCH',
        p,
        { pipelines: back.map((id) => ({ id, authorized: false })) },
        opts,
      ),
      'take back the authorization',
    );
  });
  ctx.verifications.push({
    label: `queue ${queueId} permissions`,
    check: async () => {
      const was = without(before.perms);
      const now = without((await queuePermissions(ctx, queueId)).perms);
      return now === was
        ? {
            ok: true,
            text: `queue ${queueId} pipeline permissions equal the original (${was}; the probe's definitions left out)`,
          }
        : {
            ok: false,
            text: `queue ${queueId} pipeline permissions differ: before ${was}, after ${now}`,
          };
    },
  });
  const res = ok(
    await ctx.bot.request(
      'PATCH',
      p,
      { pipelines: need.map((id) => ({ id, authorized: true })) },
      opts,
    ),
    'authorize the pipelines',
  );
  return `${need.length} pipeline(s) authorized on queue ${queueId} first (HTTP ${res.status})`;
}

/** The build the policy queued for definition `definitionId` (item 17's wait). */
export async function policyBuild(ctx: ProbeContext, definitionId: number) {
  return waitFor(
    async () => {
      const res = ok(
        await ctx.bot.request(
          'GET',
          `/${ctx.project}/_apis/build/builds?definitions=${definitionId}`,
        ),
        'builds',
      );
      return shape(z.object({ value: z.array(BuildSchema) }), res.json, 'builds').value[0];
    },
    { timeoutMs: 120_000, intervalMs: 5000 },
  );
}

/** One pipeline of the item; `label` names it in texts and recordings (default: its form), `scanStep` is the step whose result counts. */
export type Run = {
  form: Form;
  label?: string;
  scanStep?: string;
  definitionId: number;
  policyId: number;
};

const TimelineSchema = z.object({
  records: z.array(
    z
      .object({
        type: z.string().nullish(),
        name: z.string().nullish(),
        result: z.string().nullish(),
        issues: z
          .array(z.object({ type: z.string().nullish(), message: z.string().nullish() }))
          .nullish(),
        log: z.object({ id: z.number() }).nullish(),
      })
      .loose(),
  ),
});
export type TimelineRecord = z.infer<typeof TimelineSchema>['records'][number];

/** The records of a build's timeline; none when it cannot be read. */
export async function timeline(ctx: ProbeContext, buildId: number): Promise<TimelineRecord[]> {
  const res = await ctx.bot.request(
    'GET',
    `/${ctx.project}/_apis/build/builds/${buildId}/timeline`,
  );
  const parsed = TimelineSchema.safeParse(res.json);
  return res.status === 200 && parsed.success ? parsed.data.records : [];
}

/** The display name of the scan step in both examples. */
const SCAN_STEP = 'Qualor scan';

/**
 * The steps of a build that did not succeed, each with its first issue and the last lines of its
 * log: the detail only (redacted with the rest), never a recording.
 */
export function failedSteps(records: TimelineRecord[], logs: Map<number, string[]>): string {
  const bad = records.filter(
    (r) =>
      (r.type === 'Task' &&
        r.result !== 'succeeded' &&
        r.result !== 'skipped' &&
        typeof r.result === 'string') ||
      (r.type !== 'Task' && (r.issues ?? []).some((i) => i.type === 'error')),
  );
  if (bad.length === 0) {
    // A plan that failed before any job (an invalid YAML, a missing task) names why in its logs.
    const first = [...logs.values()]
      .flat()
      .map((l) => logText(l).trim())
      .filter((l) => l.length > 0)
      .slice(0, 6)
      .map((l) => l.slice(0, 300));
    const logsText = first.length ? `; logs: ${first.join(' / ')}` : '; no logs';
    return `no failed step in the timeline (${records.length} records)${logsText}`;
  }
  return bad
    .map((r) => {
      const issue = (r.issues ?? []).find((i) => i.message)?.message ?? 'no issue';
      const tail = (r.log ? (logs.get(r.log.id) ?? []) : [])
        .map((l) => logText(l).trim())
        .filter((l) => l.length > 0 && !l.startsWith('##[section]'))
        .slice(-6)
        .map((l) => l.slice(0, 220));
      const tailText = tail.length ? ` | log tail: ${tail.join(' / ')}` : '';
      return `step "${r.name ?? '?'}" ${r.result ?? '?'}: ${issue.slice(0, 300)}${tailText}`;
    })
    .join('; ');
}

/**
 * The errors Azure DevOps found in a build's YAML. Such a build fails before any job: it has no
 * timeline and no logs (both calls answer with an empty body).
 */
function validationErrors(json: unknown): string[] {
  const parsed = z
    .object({
      validationResults: z
        .array(z.object({ result: z.string().nullish(), message: z.string().nullish() }))
        .nullish(),
    })
    .safeParse(json);
  if (!parsed.success) return [];
  return (parsed.data.validationResults ?? [])
    .filter((v) => v.result === 'error')
    .map((v) => (v.message ?? 'no message').slice(0, 300));
}

/** One form's build: waits for it, records it, and checks the printed `scm` block. */
export async function checkForm(
  ctx: ProbeContext,
  run: Run,
  want: { pr: Pr; target: string; source: string; repo: Repo },
): Promise<{ pass: boolean; text: string }> {
  const tag = run.label ?? run.form;
  const stepName = run.scanStep ?? SCAN_STEP;
  let queued = await policyBuild(ctx, run.definitionId);
  let how = 'queued by the Build validation policy';
  if (!queued) {
    const { list } = await evaluations(ctx, want.pr);
    const ev = list.value.find((e) => e.configuration.id === run.policyId);
    if (ev) {
      await ctx.bot.request(
        'PATCH',
        `/${ctx.project}/_apis/policy/evaluations/${ev.evaluationId}`,
        undefined,
        {
          apiVersion: '7.0-preview.1',
        },
      );
      queued = await policyBuild(ctx, run.definitionId);
      how = 'queued by a requeue of the policy evaluation';
    }
  }
  if (!queued)
    return { pass: false, text: `${tag} form: no build was queued for the pull request` };
  // Both forms share the target's one agent: the second waits for the first.
  const done = await waitBuild(ctx, queued.id, { timeoutMs: 30 * 60_000 });
  if (done.build.status !== 'completed') {
    return {
      pass: false,
      text: `${tag} form: build ${queued.id} did not complete within 30 minutes (${how})`,
    };
  }
  const invalid = validationErrors(done.res.json);
  if (invalid.length > 0) {
    return {
      pass: false,
      text: `${tag} form: build ${queued.id} has no logs: its YAML did not compile (${invalid.join('; ')})`,
    };
  }
  // The logs first: reading them adds the agent's name to the redaction table.
  const logs = await buildLogs(ctx, queued.id);
  await ctx.record(`build-${tag}`, answerOf(done.res));
  let line: string | undefined;
  for (const [logId, lines] of logs) {
    const found = printedValues(lines, ['QUALOR_SCM'])['QUALOR_SCM'];
    if (found !== undefined) {
      line = found;
      await ctx.record(`build-log-${tag}`, {
        logId,
        lines: keptLogLines(lines, ['QUALOR_SCM']),
      });
      break;
    }
  }
  const records = await timeline(ctx, queued.id);
  const scanStep =
    records.find((r) => r.type === 'Task' && r.name === stepName)?.result ?? 'not run';
  const why = done.build.result === 'succeeded' ? '' : ` (${failedSteps(records, logs)})`;
  const status = `build ${queued.id} (${how}): result ${done.build.result ?? 'none'}${why}, step "${stepName}" ${scanStep}, reason ${done.build.reason ?? '?'}, sourceBranch ${done.build.sourceBranch ?? '?'}`;
  if (line === undefined)
    return { pass: false, text: `${tag} form: ${status}; no QUALOR_SCM line printed` };
  let scm: Scm;
  try {
    scm = shape(ScmSchema, JSON.parse(line), 'report scm');
  } catch (err) {
    return {
      pass: false,
      text: `${tag} form: ${status}; the scm line is not the expected JSON (${(err as Error).message})`,
    };
  }
  await ctx.record(`scm-${tag}`, scm);
  const head = want.pr.lastMergeSourceCommit?.commitId ?? '?';
  const checks = scmChecks(scm, {
    prId: want.pr.pullRequestId,
    target: want.target,
    source: want.source,
    repo: want.repo,
    buildId: queued.id,
    head,
  });
  const failed = checks.filter(([, expected, got]) => got !== expected);
  const lines = checks.map(([what, expected, got]) =>
    got === expected ? `${what} = ${got}` : `${what}: expected ${expected}, got ${got ?? 'absent'}`,
  );
  // The item asks about the scan and its report: another failed step is named in the text only.
  const fieldsText =
    failed.length === 0 ? 'every scm field as expected' : `${failed.length} scm field(s) differ`;
  return {
    pass: failed.length === 0 && scanStep === 'succeeded',
    text: `${tag} form: ${status}; ${fieldsText}: ${lines.join('; ')}`,
  };
}

export const item: ProbeItem = {
  id: 18,
  title:
    'a pull request build scans the pull request head, and the report names the PR and the repository',
  async run(ctx) {
    const repo = await repoInfo(ctx);
    const base = await refHead(ctx, repo.defaultBranch);
    if (!base) throw new Error('no head on the default branch');
    const ext = await extensionInstalled(ctx);
    const forms: Form[] = ext.installed ? ['docker', 'task'] : ['docker'];
    const yaml: Record<Form, () => string> = {
      docker: () => benchDockerYaml(example('qualor-docker.yml')),
      task: () => benchTaskYaml(example('qualor.yml')),
    };

    const target = await createBranchAt(ctx, `probe/18-${ctx.stamp}-target`, base);
    const { refName } = await pushFiles(
      ctx,
      `probe/18-${ctx.stamp}`,
      [...forms.map((f) => ({ path: `/${PATHS[f]}`, content: yaml[f]() })), probeSource(ctx)],
      { base },
    );
    const queueId = await defaultQueueId(ctx);
    // A dummy analysis token: --dry-run sends nothing, and qualor.invalid never resolves.
    const token = ['qlr', 'bench', randomBytes(12).toString('hex')].join('_');
    const runs: Run[] = [];
    for (const form of forms) {
      const def = await createDefinition(ctx, {
        name: `Qualor probe item 18 ${form} ${ctx.stamp}`,
        path: '\\',
        type: 'build',
        queue: { id: queueId },
        process: { type: 2, yamlFilename: PATHS[form] },
        repository: { id: repo.id, name: repo.name, type: 'TfsGit', defaultBranch: refName },
        variables: {
          QUALOR_URL: { value: 'https://qualor.invalid', allowOverride: false },
          QUALOR_TOKEN: { value: token, isSecret: true, allowOverride: false },
        },
      });
      runs.push({ form, definitionId: def.id, policyId: 0 });
    }
    const authorized = await authorizeDefinitions(
      ctx,
      queueId,
      runs.map((r) => r.definitionId),
    );
    for (const run of runs) {
      const policy = await createPolicy(ctx, {
        isEnabled: true,
        isBlocking: true,
        type: { id: BUILD_POLICY },
        settings: {
          buildDefinitionId: run.definitionId,
          queueOnSourceUpdateOnly: false,
          manualQueueOnly: false,
          displayName: `Qualor probe item 18 ${run.form}`,
          validDuration: 0,
          scope: [{ repositoryId: repo.id, refName: target, matchKind: 'exact' }],
        },
      });
      run.policyId = policy.id;
    }

    const created = await createPr(ctx, refName, { targetRefName: target });
    const { pr } = await prWithMerge(ctx, created.pr.pullRequestId);
    const outcomes: { pass: boolean; text: string }[] = [];
    for (const run of runs) {
      outcomes.push(await checkForm(ctx, run, { pr, target, source: refName, repo }));
    }
    const skipped = ext.installed ? [] : [`task form skipped: ${ext.why}`];
    const detail = [
      `pull request ${pr.pullRequestId} into ${branchName(target)}; image qualor/scanner:${BENCH_IMAGE_TAG}; ${DRY_RUN}; ${authorized}; extension: ${ext.why}`,
      ...outcomes.map((o) => o.text),
      ...skipped,
    ].join('\n\n');
    return result(ctx, outcomes.every((o) => o.pass) ? 'yes' : 'no', detail);
  },
};
