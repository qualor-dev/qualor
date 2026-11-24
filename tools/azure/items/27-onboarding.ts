import { z } from 'zod';
import type { AzureResponse } from '../client.js';
import { BENCH_IMAGE_TAG } from './18-ci.js';
import { check, needEnv, rec, servicePrincipalId, type Check } from './19-decoration.js';
import { QualorApi } from './21-review.js';
import { pushedCommit } from './22-fix-writes.js';
import {
  buildProblem,
  codeOf,
  ensureRepository,
  fileText,
  headOf,
  qualorMain,
} from './24-fix-pr.js';
import { describeAnswer } from './26-ci-setup.js';
import {
  abandonPr,
  addHosts,
  answerOf,
  BUILD_POLICY,
  BuildSchema,
  cancelBuilds,
  createPr,
  defaultQueueId,
  deleteBranch,
  evaluations,
  getBuild,
  getPr,
  gitPath,
  hostsOf,
  ok,
  prWithMerge,
  pushFiles,
  queuePermissions,
  refHead,
  remove,
  repoInfo,
  result,
  shape,
  waitBuild,
  waitFor,
  type ProbeContext,
  type ProbeItem,
  type Repo,
} from './common.js';

/**
 * Ruling: the third repository of the bench project, made by the item when missing and kept
 * between runs (it goes with the organisation at the end of 0.17).
 */
export const SETUP_REPOSITORY = 'qualor-probe-setup';
/** The one file main holds at the start of each run. */
export const HELLO_PATH = '/src/hello.js';
/** The setup's pipeline file (server/src/onboarding/ci-setup.ts AZURE_FILE), as Azure DevOps paths read. */
export const PIPELINE_PATH = '/.azure-pipelines/qualor.yml';
/** server/src/onboarding/setup-run.ts SETUP_BRANCH and SETUP_TITLE. */
export const SETUP_BRANCH = 'qualor/setup';
export const SETUP_TITLE = 'Add Qualor code analysis';
/** The names the setup gives its pipeline: `Qualor`, or `Qualor (<repository>)` when that is taken. */
export const PIPELINE_NAMES: readonly string[] = ['Qualor', `Qualor (${SETUP_REPOSITORY})`];
/** The Build validation policy's display name (server/src/scm/azure/client.ts createBuildPolicy). */
export const POLICY_NAME = 'Qualor';
/** The bench's self-hosted pool on the Linux instance, where the :azure-dev images exist. */
export const POOL = 'Default';
/** The item's own branches (the probe pull request's), which an earlier run may have left. */
const PROBE_PREFIX = 'refs/heads/probe/27-';
const MAIN = 'refs/heads/main';
const SETUP_REF = `refs/heads/${SETUP_BRANCH}`;
const ZEROS = '0'.repeat(40);
const RESET_COMMENT = 'Qualor probe item 27: main as each run starts it';
/** The setup run itself: a few Azure DevOps calls. */
const SETUP_WAIT_MS = 5 * 60_000;
/** Azure DevOps takes the image commit into the pull request, then completes it. */
const SOURCE_WAIT_MS = 2 * 60_000;
const MERGE_WAIT_MS = 3 * 60_000;
/** Ruling: the main build and the main analysis together; the build must be queued within 5. */
const MAIN_WAIT_MS = 15 * 60_000;
const MAIN_QUEUED_MS = 5 * 60_000;
/** The last poll of the main analysis gets this long even when the build used the 15 minutes. */
const ANALYSIS_GRACE_MS = 2 * 60_000;
/** Ruling: the policy job after the main analysis. */
const POLICY_WAIT_MS = 5 * 60_000;
/** The policy queues the pull request's build at once. */
const PR_BUILD_WAIT_MS = 3 * 60_000;
/** Ruling: Qualor's status on the probe pull request, from its creation. */
const STATUS_WAIT_MS = 15 * 60_000;

const enc = encodeURIComponent;
const lf = (text: string): string => text.replace(/\r\n/g, '\n');
const sameId = (a: string | null | undefined, b: string): boolean =>
  (a ?? '').toLowerCase() === b.toLowerCase();

// ---------------------------------------------------------------------------------------------
// Pure helpers (unit-tested)

/**
 * The one file of main at the start of each run: the empty function of items 19 and 21 on line 2
 * (sonarjs S1186, one analyzer finding), without their run stamp, so main reads the same each run.
 */
export function helloSource(): string {
  return [
    '// Qualor probe item 27: the one file of the setup repository.',
    'export function emptyHandler() {',
    '}',
    '',
  ].join('\n');
}

/** The probe pull request's change: one small new file. */
export function probeSource(stamp: string): string {
  return [
    `// Qualor probe item 27 (${stamp}): a change for the Build validation policy to build.`,
    'export const probeValue = 27;',
    '',
  ].join('\n');
}

const TreeSchema = z.object({
  value: z.array(
    z
      .object({
        path: z.string(),
        isFolder: z.boolean().optional(),
        gitObjectType: z.string().optional(),
      })
      .loose(),
  ),
});

/** The files of a recursive items listing (the root and folders left out), sorted. */
export function treeFiles(json: unknown): string[] {
  return shape(TreeSchema, json, 'tree listing')
    .value.filter((e) => e.isFolder !== true && e.gitObjectType !== 'tree')
    .map((e) => e.path)
    .toSorted();
}

/** Whether main is as each run starts it: the hello file alone, with its text. */
export function isKnownMain(files: readonly string[], hello: string | null): boolean {
  return (
    files.length === 1 && files[0] === HELLO_PATH && hello !== null && lf(hello) === helloSource()
  );
}

export type ResetChange = { changeType: 'add' | 'edit' | 'delete'; path: string };

/**
 * The changes of the fast-forward reset (used when the force-move is refused): every other file
 * deleted, the hello file added or written back; none when main is already as wanted.
 */
export function resetChanges(files: readonly string[], hello: string | null): ResetChange[] {
  const out: ResetChange[] = files
    .filter((f) => f !== HELLO_PATH)
    .map((path) => ({ changeType: 'delete', path }));
  if (!files.includes(HELLO_PATH)) out.push({ changeType: 'add', path: HELLO_PATH });
  else if (hello === null || lf(hello) !== helloSource()) {
    out.push({ changeType: 'edit', path: HELLO_PATH });
  }
  return out;
}

/** A push's `changes` for {@link resetChanges}: a delete carries no content, the hello file its text. */
export function pushChanges(changes: readonly ResetChange[]): Record<string, unknown>[] {
  return changes.map((c) =>
    c.changeType === 'delete'
      ? { changeType: 'delete', item: { path: c.path } }
      : {
          changeType: c.changeType,
          item: { path: c.path },
          newContent: { content: helloSource(), contentType: 'rawtext' },
        },
  );
}

const RefUpdatesSchema = z.object({
  value: z.array(z.object({ success: z.boolean(), updateStatus: z.string().optional() }).loose()),
});

/** Whether a `POST refs` answer says every update succeeded. */
export function refUpdatesSucceeded(json: unknown): boolean {
  const parsed = RefUpdatesSchema.safeParse(json);
  return (
    parsed.success && parsed.data.value.length > 0 && parsed.data.value.every((u) => u.success)
  );
}

type Ref = { name: string; objectId: string };

/** The branches an earlier run may have left: the setup's branch and the item's probe branches. */
export function staleBranches(refs: readonly Ref[]): Ref[] {
  return refs.filter((r) => r.name === SETUP_REF || r.name.startsWith(PROBE_PREFIX));
}

const DefinitionListSchema = z.object({
  value: z.array(
    z
      .object({
        id: z.number(),
        name: z.string(),
        repository: z.object({ id: z.string() }).loose().nullish(),
        process: z.object({ yamlFilename: z.string().optional() }).loose().nullish(),
      })
      .loose(),
  ),
});

type Listed = { id: number; name: string };

/**
 * The repository's pipelines in a definitions listing: the setup's (by the names it gives them),
 * and any other on the setup's file (a setup would call those foreign: `foreign_pipeline`).
 */
export function setupDefinitions(
  json: unknown,
  repositoryId: string,
): { own: Listed[]; others: Listed[] } {
  const mine = shape(DefinitionListSchema, json, 'definitions').value.filter((d) =>
    sameId(d.repository?.id, repositoryId),
  );
  const onFile = (d: (typeof mine)[number]) =>
    `/${(d.process?.yamlFilename ?? '').replace(/^\/+/, '')}` === PIPELINE_PATH;
  return {
    own: mine.filter((d) => PIPELINE_NAMES.includes(d.name)).map(({ id, name }) => ({ id, name })),
    others: mine
      .filter((d) => !PIPELINE_NAMES.includes(d.name) && onFile(d))
      .map(({ id, name }) => ({ id, name })),
  };
}

const PolicyListSchema = z.object({
  value: z.array(
    z
      .object({
        id: z.number(),
        isEnabled: z.boolean().optional(),
        isBlocking: z.boolean().optional(),
        type: z.object({ id: z.string() }).loose().optional(),
        settings: z
          .object({
            buildDefinitionId: z.number().optional(),
            displayName: z.string().nullish(),
            scope: z
              .array(
                z
                  .object({
                    repositoryId: z.string().nullish(),
                    refName: z.string().nullish(),
                    matchKind: z.string().nullish(),
                  })
                  .loose(),
              )
              .optional(),
          })
          .loose(),
      })
      .loose(),
  ),
});
type Policy = z.infer<typeof PolicyListSchema>['value'][number];

const isBuildPolicy = (p: Policy): boolean => p.type === undefined || p.type.id === BUILD_POLICY;

/** The Build validation policies an earlier run left on main: those of the setup's pipelines, or named `Qualor`. */
export function policiesToRemove(json: unknown, definitionIds: readonly number[]): number[] {
  return shape(PolicyListSchema, json, 'policies')
    .value.filter(
      (p) =>
        isBuildPolicy(p) &&
        ((p.settings.buildDefinitionId !== undefined &&
          definitionIds.includes(p.settings.buildDefinitionId)) ||
          p.settings.displayName === POLICY_NAME),
    )
    .map((p) => p.id);
}

/** Whether a policy applies to main of the repository exactly (Azure DevOps answers `Exact`). */
const onMain = (p: Policy, repositoryId: string): boolean =>
  (p.settings.scope ?? []).some(
    (s) =>
      sameId(s.repositoryId, repositoryId) &&
      s.refName === MAIN &&
      (s.matchKind ?? '').toLowerCase() === 'exact',
  );

/** The policy the setup's job adds: one non-blocking, enabled `Qualor` policy for the pipeline on main. */
export function judgeMainPolicy(
  json: unknown,
  want: { definitionId: number; repositoryId: string },
): { check: Check; policyId: number | null } {
  const mine = shape(PolicyListSchema, json, 'policies').value.filter(
    (p) => isBuildPolicy(p) && p.settings.buildDefinitionId === want.definitionId,
  );
  const good = mine.find(
    (p) =>
      p.isEnabled === true &&
      p.isBlocking === false &&
      p.settings.displayName === POLICY_NAME &&
      onMain(p, want.repositoryId),
  );
  const got =
    mine.length === 0
      ? 'no Build validation policy for the pipeline on main'
      : mine
          .map(
            (p) =>
              `policy ${p.id}: enabled ${String(p.isEnabled)}, blocking ${String(p.isBlocking)}, "${p.settings.displayName ?? ''}", ${onMain(p, want.repositoryId) ? 'main of the repository exactly' : 'another scope'}`,
          )
          .join('; ');
  return {
    check: check(
      `one non-blocking, enabled Build validation policy "${POLICY_NAME}" for the pipeline on main`,
      mine.length === 1 && good !== undefined,
      got,
    ),
    policyId: good?.id ?? mine[0]?.id ?? null,
  };
}

const SetupItemSchema = z
  .object({
    ref: z.string(),
    name: z.string(),
    project: z.object({ id: z.string(), key: z.string() }).nullable(),
    projectOutcome: z.string(),
    ciOutcome: z.string(),
    ciUrl: z.string().nullable(),
    ciReason: z.string().nullable(),
    token: z.string().nullable().optional(),
    error: z.object({ code: z.string(), message: z.string() }).loose().nullable(),
    azure: z
      .object({
        pipelineUrl: z.string().nullable(),
        queue: z.string().nullable(),
        policy: z.string().nullable(),
        policyError: z.string().nullable(),
      })
      .nullable(),
  })
  .loose();
export const SetupRunSchema = z
  .object({ id: z.string(), status: z.string(), items: z.array(SetupItemSchema) })
  .loose();
export type SetupRun = z.infer<typeof SetupRunSchema>;
export type SetupItem = z.infer<typeof SetupItemSchema>;

/** The tokens a run's answer shows (a snippet's, once, to its creator): never printed or recorded. */
export function tokensIn(json: unknown): string[] {
  const items = (json as { items?: unknown } | null)?.items;
  if (!Array.isArray(items)) return [];
  return items.flatMap((i) => {
    const token = (i as { token?: unknown } | null)?.token;
    return typeof token === 'string' && token.length > 0 ? [token] : [];
  });
}

/** The pipeline's id in the run's `azure.pipelineUrl` (`…/_build?definitionId=<id>`). */
export function definitionIdOf(pipelineUrl: string | null | undefined): number | null {
  const m = /[?&]definitionId=(\d+)(?:&|#|$)/.exec(pipelineUrl ?? '');
  return m ? Number(m[1]) : null;
}

/** The run is done and its one repository got the pull request. */
export function judgeSetupItem(run: SetupRun): Check {
  const item = run.items[0];
  const pass =
    run.status === 'done' &&
    run.items.length === 1 &&
    item?.ciOutcome === 'merge_request' &&
    item.ciUrl !== null &&
    item.error === null &&
    (item.projectOutcome === 'created' || item.projectOutcome === 'adopted');
  const got = item
    ? `run ${run.status}; ciOutcome ${item.ciOutcome}${item.ciReason ? ` (${item.ciReason})` : ''}; project ${item.projectOutcome}${item.error ? `; error ${item.error.code}: ${item.error.message}` : ''}`
    : `run ${run.status}; no item`;
  return check(
    'the setup run is done and its repository is `merge_request` (a pull request, no error)',
    pass,
    got,
  );
}

/** The setup recorded the Build validation policy as pending: none until the first main analysis. */
export function judgePending(item: SetupItem): Check {
  return check(
    "the run's item has azure.policy `pending` before the merge",
    item.azure?.policy === 'pending',
    `azure.policy ${item.azure?.policy ?? 'absent'}`,
  );
}

/** After the main analysis the job turned the policy on. */
export function judgePolicyOn(item: SetupItem | undefined): Check {
  const policy = item?.azure?.policy ?? 'absent';
  return check(
    "the run's item has azure.policy `on` after the main analysis",
    policy === 'on',
    `${policy}${item?.azure?.policyError ? `: ${item.azure.policyError}` : ''}`,
  );
}

const ChangesSchema = z.object({
  changeEntries: z.array(
    z
      .object({
        changeType: z.string(),
        item: z
          .object({
            path: z.string(),
            isFolder: z.boolean().optional(),
            gitObjectType: z.string().optional(),
          })
          .loose(),
      })
      .loose(),
  ),
});

/** The files an iteration changes (folders left out), with their change types. */
export function changedFiles(json: unknown): { path: string; changeType: string }[] {
  return shape(ChangesSchema, json, 'iteration changes')
    .changeEntries.filter((e) => e.item.isFolder !== true && e.item.gitObjectType !== 'tree')
    .map((e) => ({ path: e.item.path, changeType: e.changeType }));
}

const unquote = (value: string): string => {
  if (/^'.*'$/.test(value)) return value.slice(1, -1).replaceAll("''", "'");
  if (/^".*"$/.test(value)) return value.slice(1, -1);
  return value;
};

/** The pool of a pipeline file as `name: Default` or `vmImage: ubuntu-latest`; null without a pool block. */
export function poolOf(yaml: string | null): string | null {
  const m = /^pool:\n {2}(name|vmImage): (.+)$/m.exec(lf(yaml ?? ''));
  if (!m?.[1] || m[2] === undefined) return null;
  return `${m[1]}: ${unquote(m[2].trim())}`;
}

const IMAGE_LINE = /^( {2}QUALOR_SCANNER_IMAGE: )(qualor\/scanner(?:-dotnet)?):(\S+)$/m;

/** The scanner image a pipeline file names (`qualor/scanner:0.17.0`); null without the line. */
export function imageOf(yaml: string | null): string | null {
  const m = IMAGE_LINE.exec(lf(yaml ?? ''));
  return m ? `${m[2]}:${m[3]}` : null;
}

/**
 * The pipeline file as a person on the bench edits it in the pull request: the scanner image on
 * the bench's own tag (the setup pins the server's version, which the bench has no image of).
 * Null without the image line.
 */
export function pinBenchImage(yaml: string): string | null {
  const text = lf(yaml);
  if (!IMAGE_LINE.test(text)) return null;
  return text.replace(
    IMAGE_LINE,
    (_m, key: string, image: string) => `${key}${image}:${BENCH_IMAGE_TAG}`,
  );
}

/** The setup's pull request as it opened it, before the item's image commit. */
export function judgeSetupPr(
  pr: { status: string; title: string; sourceRefName: string; targetRefName: string },
  files: readonly { path: string; changeType: string }[],
  yaml: string | null,
): Check[] {
  const types = (t: string) => t.split(',').map((s) => s.trim().toLowerCase());
  const only = files[0];
  return [
    check(
      `the pull request "${SETUP_TITLE}" is active, from ${SETUP_BRANCH} into main`,
      pr.status === 'active' &&
        pr.title === SETUP_TITLE &&
        pr.sourceRefName === SETUP_REF &&
        pr.targetRefName === MAIN,
      `${pr.status}, "${pr.title}", ${pr.sourceRefName} into ${pr.targetRefName}`,
    ),
    check(
      `it adds exactly ${PIPELINE_PATH.slice(1)}`,
      files.length === 1 && only?.path === PIPELINE_PATH && types(only.changeType).includes('add'),
      files.map((f) => `${f.changeType} ${f.path}`).join(', ') || 'no file',
    ),
    check(
      `the file runs on the agent pool ${POOL} (\`pool: name: ${POOL}\`)`,
      poolOf(yaml) === `name: ${POOL}`,
      yaml === null ? 'the file was not read' : `pool ${poolOf(yaml) ?? 'none'}`,
    ),
  ];
}

const VariableSchema = z
  .object({ value: z.string().nullish(), isSecret: z.boolean().optional() })
  .loose();
export const DefinitionSchema = z
  .object({
    id: z.number(),
    name: z.string(),
    process: z.object({ yamlFilename: z.string().optional() }).loose().optional(),
    repository: z.object({ id: z.string() }).loose().optional(),
    queue: z.object({ id: z.number(), name: z.string().optional() }).loose().optional(),
    variables: z.record(z.string(), VariableSchema).nullish(),
  })
  .loose();
export type Definition = z.infer<typeof DefinitionSchema>;

const sameUrl = (a: string, b: string): boolean =>
  a.replace(/\/+$/, '').toLowerCase() === b.replace(/\/+$/, '').toLowerCase();

/** The setup's pipeline: on the file of the repository, the pool's queue, the address and the secret. */
export function judgeDefinition(
  def: Definition,
  want: { repositoryId: string; queueId: number; qualorUrl: string },
): Check[] {
  const yaml = (def.process?.yamlFilename ?? '').replace(/^\/+/, '');
  const runs =
    PIPELINE_NAMES.includes(def.name) &&
    `/${yaml}` === PIPELINE_PATH &&
    sameId(def.repository?.id, want.repositoryId) &&
    def.queue?.id === want.queueId;
  const url = def.variables?.['QUALOR_URL'];
  const token = def.variables?.['QUALOR_TOKEN'];
  const urlValue = url?.value;
  const urlSet = typeof urlValue === 'string' && urlValue.length > 0 && url?.isSecret !== true;
  const secret = token?.isSecret === true && (token.value === null || token.value === undefined);
  const urlText = !url
    ? 'absent'
    : urlSet
      ? `set (${sameUrl(urlValue, want.qualorUrl) ? "the probe's Qualor address" : 'another address than the probe uses'})`
      : 'without a value';
  const tokenText = !token
    ? 'absent'
    : `isSecret ${String(token.isSecret === true)}, ${token.value === null || token.value === undefined ? 'no value read back' : 'a value read back'}`;
  return [
    check(
      `the pipeline "${PIPELINE_NAMES.join('" or "')}" runs ${PIPELINE_PATH.slice(1)} of the repository on the ${POOL} queue`,
      runs,
      `"${def.name}", ${yaml || 'no file'}, ${sameId(def.repository?.id, want.repositoryId) ? 'the repository' : 'another repository'}, queue ${def.queue?.name ?? String(def.queue?.id ?? 'none')}`,
    ),
    check(
      'the pipeline holds QUALOR_URL and QUALOR_TOKEN as a secret (isSecret, no value read back)',
      urlSet && secret,
      `QUALOR_URL ${urlText}; QUALOR_TOKEN ${tokenText}`,
    ),
  ];
}

/** The definition as recorded: a secret variable's value is never kept, whatever Azure DevOps answered. */
export function definitionRecording(json: unknown): unknown {
  if (!json || typeof json !== 'object') return json;
  const def = json as Record<string, unknown>;
  const vars = def['variables'];
  if (!vars || typeof vars !== 'object') return def;
  return {
    ...def,
    variables: Object.fromEntries(
      Object.entries(vars as Record<string, unknown>).map(([key, v]) => [
        key,
        v && typeof v === 'object' && (v as { isSecret?: unknown }).isSecret === true
          ? { ...(v as Record<string, unknown>), value: null }
          : v,
      ]),
    ),
  };
}

/** The queue as the setup recorded it and as Azure DevOps reads it: authorised for the pipeline, or open. */
export function judgeQueue(
  itemQueue: string | null | undefined,
  azure: { open: boolean; authorized: boolean },
): Check {
  return check(
    `the ${POOL} queue is authorised for the pipeline (or open to every pipeline)`,
    (itemQueue === 'authorized' || itemQueue === 'open') && (azure.open || azure.authorized),
    `the run says ${itemQueue ?? 'nothing'}; Azure DevOps: the queue ${azure.open ? 'is open to every pipeline' : 'is not open to every pipeline'}, the pipeline ${azure.authorized ? 'is' : 'is not'} listed as authorised`,
  );
}

export type Build = z.infer<typeof BuildSchema>;

/** The build of main after the merge: of the merge commit, else the newest of main (the pipeline is this run's). */
export function mainBuildOf(
  builds: readonly Build[],
  mergeCommit: string | undefined,
): Build | undefined {
  const ofMain = builds.filter((b) => b.sourceBranch === MAIN);
  return (
    ofMain.find((b) => mergeCommit !== undefined && sameId(b.sourceVersion, mergeCommit)) ??
    ofMain[0]
  );
}

/** A branch's unfinished builds: CI builds the item does not need, cancelled to free the one agent. */
export function toCancel(builds: readonly Build[], sourceBranch: string): Build[] {
  return builds.filter(
    (b) => b.sourceBranch === sourceBranch && b.status !== 'completed' && b.status !== 'cancelling',
  );
}

export type Evaluation = { status: string; configuration: { id: number }; context?: unknown };

/** The build the policy queued for the probe pull request: a pullRequest build, or the evaluation's. */
export function judgePrBuild(
  builds: readonly Build[],
  evals: readonly Evaluation[],
  want: { prId: number; policyId: number | null },
): Check {
  const prBuild = builds.find(
    (b) => b.reason === 'pullRequest' && b.sourceBranch === `refs/pull/${want.prId}/merge`,
  );
  const ev =
    want.policyId === null ? undefined : evals.find((e) => e.configuration.id === want.policyId);
  const evBuild = (ev?.context as { buildId?: unknown } | null | undefined)?.buildId;
  return check(
    'the policy queued a build of the pipeline for the probe pull request',
    prBuild !== undefined || typeof evBuild === 'number',
    `${prBuild ? `build ${prBuild.id} (reason pullRequest, ${prBuild.status}${prBuild.result ? ` ${prBuild.result}` : ''})` : 'no pullRequest build of the pipeline'}; ${ev ? `evaluation ${ev.status}${typeof evBuild === 'number' ? ` with build ${evBuild}` : ' without a build'}` : 'no evaluation of the policy'}`,
  );
}

export const StatusSchema = z
  .object({
    id: z.number(),
    state: z.string().nullish(),
    description: z.string().nullish(),
    context: z.object({ name: z.string(), genre: z.string().nullish() }).loose(),
    createdBy: z.object({ id: z.string() }).loose().nullish(),
  })
  .loose();
export type Status = z.infer<typeof StatusSchema>;

/**
 * Qualor's newest status: genre `qualor` and the project key as the name (server/src/scm/render.ts
 * `azureStatusName`). Azure Pipelines posts its own `codecoverage` status under the pipeline's name,
 * here `qualor` too, so the genre alone is not Qualor's.
 */
export function qualorStatus(statuses: readonly Status[], projectKey: string): Status | undefined {
  return statuses
    .filter(
      (s) =>
        s.context.genre === 'qualor' &&
        s.context.name === projectKey &&
        typeof s.state === 'string' &&
        s.state !== 'notSet',
    )
    .toSorted((a, b) => b.id - a.id)[0];
}

/** What a Qualor answer that is not 2xx says: its code and its first message (no secret is in either). */
export function problemText(json: unknown): string {
  const p = (json ?? {}) as {
    title?: unknown;
    detail?: unknown;
    errors?: { path?: unknown; message?: unknown }[];
  };
  const first = Array.isArray(p.errors) ? p.errors[0] : undefined;
  const message =
    first && typeof first.message === 'string'
      ? `${typeof first.path === 'string' ? `${first.path}: ` : ''}${first.message}`
      : typeof p.detail === 'string'
        ? p.detail
        : typeof p.title === 'string'
          ? p.title
          : '';
  return `${codeOf(json)}${message ? ` (${message.slice(0, 200)})` : ''}`;
}

// ---------------------------------------------------------------------------------------------
// Azure DevOps calls

const RefListSchema = z.object({
  value: z.array(z.object({ name: z.string(), objectId: z.string() })),
});
const PrListSchema = z.object({
  value: z.array(
    z
      .object({
        pullRequestId: z.number(),
        status: z.string(),
        title: z.string(),
        sourceRefName: z.string(),
        targetRefName: z.string(),
        createdBy: z.object({ id: z.string() }).loose().optional(),
      })
      .loose(),
  ),
});

const gitById = (ctx: ProbeContext, repoId: string, rest: string): string =>
  `/${ctx.project}/_apis/git/repositories/${repoId}${rest}`;

/** Deletes `name` (a full ref name) of a repository read by id, when it is there. */
async function deleteRef(ctx: ProbeContext, repoId: string, name: string): Promise<void> {
  const head = await headOf(ctx, repoId, name);
  if (!head) return;
  const res = ok(
    await ctx.bot.request('POST', gitById(ctx, repoId, '/refs'), [
      { name, oldObjectId: head, newObjectId: ZEROS },
    ]),
    `delete ${name}`,
  );
  if (!refUpdatesSucceeded(res.json)) throw new Error(`delete ${name}: the ref update failed`);
}

/**
 * What an earlier run left, before the setup: every active pull request of the repository (the
 * item's alone) abandoned, the setup's pipelines and their Build validation policies on main
 * removed, the setup branch and the item's probe branches deleted.
 */
async function clearEarlierRun(ctx: ProbeContext, repoId: string, notes: string[]) {
  const root = `/${ctx.project}/_apis`;
  const prs = shape(
    PrListSchema,
    ok(
      await ctx.bot.request(
        'GET',
        gitById(ctx, repoId, '/pullrequests?searchCriteria.status=active'),
      ),
      'active pull requests',
    ).json,
    'pull requests',
  ).value;
  for (const pr of prs) {
    ok(
      await ctx.bot.request('PATCH', gitById(ctx, repoId, `/pullrequests/${pr.pullRequestId}`), {
        status: 'abandoned',
      }),
      `abandon pull request ${pr.pullRequestId}`,
    );
  }
  const defs = setupDefinitions(
    ok(
      await ctx.bot.request(
        'GET',
        `${root}/build/definitions?repositoryId=${repoId}&repositoryType=TfsGit&includeAllProperties=true`,
      ),
      'definitions of the repository',
    ).json,
    repoId,
  );
  const policies = policiesToRemove(
    ok(
      await ctx.bot.request(
        'GET',
        `${root}/policy/configurations?repositoryId=${repoId}&refName=${enc(MAIN)}&policyType=${BUILD_POLICY}`,
      ),
      'policies on main',
    ).json,
    defs.own.map((d) => d.id),
  );
  for (const id of policies) await remove(ctx.bot, `${root}/policy/configurations/${id}`, 'policy');
  for (const d of defs.own) {
    await cancelBuilds(ctx, d.id);
    await remove(ctx.bot, `${root}/build/definitions/${d.id}`, `definition ${d.id}`);
  }
  const refs = shape(
    RefListSchema,
    ok(await ctx.bot.request('GET', gitById(ctx, repoId, '/refs?filter=heads/')), 'branches').json,
    'branches',
  ).value;
  const stale = staleBranches(refs);
  for (const r of stale) await deleteRef(ctx, repoId, r.name);
  notes.push(
    `before the setup: ${prs.length} active pull request(s) abandoned, ${policies.length} Build validation policy(ies) and ${defs.own.length} pipeline(s) of an earlier run removed${defs.own.length ? ` (${defs.own.map((d) => `"${d.name}" ${d.id}`).join(', ')})` : ''}, ${stale.length} branch(es) deleted`,
  );
  if (defs.others.length > 0) {
    notes.push(
      `other pipelines on ${PIPELINE_PATH.slice(1)} stay (the setup will call them foreign): ${defs.others.map((d) => `"${d.name}" ${d.id}`).join(', ')}`,
    );
  }
}

/**
 * Main as each run starts it: the hello file alone. A parentless commit holding it goes to a
 * temporary ref, then main is moved there (Azure DevOps refuses a non-fast-forward push, item
 * 22d); when either is refused, one fast-forward commit deletes the rest and writes the file back.
 */
async function resetMain(ctx: ProbeContext, repoId: string, notes: string[]): Promise<void> {
  const pushes = gitById(ctx, repoId, '/pushes');
  const hello = pushChanges([{ changeType: 'add', path: HELLO_PATH }]);
  const head = await headOf(ctx, repoId, MAIN);
  if (!head) {
    const res = ok(
      await ctx.bot.request('POST', pushes, {
        refUpdates: [{ name: MAIN, oldObjectId: ZEROS }],
        // The first commit of an empty repository has no parents.
        commits: [{ comment: RESET_COMMENT, changes: hello }],
      }),
      'seed main',
    );
    await rec(ctx, 'push-seed', answerOf(res));
    notes.push(`main of ${SETUP_REPOSITORY} seeded with ${HELLO_PATH}`);
    return;
  }
  const files = treeFiles(
    ok(
      await ctx.bot.request(
        'GET',
        gitById(
          ctx,
          repoId,
          `/items?scopePath=/&recursionLevel=Full&versionDescriptor.version=${head}&versionDescriptor.versionType=commit`,
        ),
      ),
      'files of main',
    ).json,
  );
  const text = files.includes(HELLO_PATH) ? await fileText(ctx, repoId, HELLO_PATH, head) : null;
  if (isKnownMain(files, text)) {
    notes.push(`main of ${SETUP_REPOSITORY} already holds ${HELLO_PATH} alone`);
    return;
  }
  const tmp = `refs/qualor/probe-tmp/27-${ctx.stamp}`;
  ctx.cleanup.add(`delete ref ${tmp}`, () => deleteRef(ctx, repoId, tmp));
  const pushed = await ctx.bot.request('POST', pushes, {
    refUpdates: [{ name: tmp, oldObjectId: ZEROS }],
    commits: [{ comment: RESET_COMMENT, changes: hello }],
  });
  await rec(ctx, 'push-reset', answerOf(pushed));
  let refused: string;
  if (pushed.status < 300) {
    const commit = pushedCommit(pushed, 'push the reset commit');
    const moved = await ctx.bot.request('POST', gitById(ctx, repoId, '/refs'), [
      { name: MAIN, oldObjectId: head, newObjectId: commit },
    ]);
    await rec(ctx, 'ref-move', answerOf(moved));
    await deleteRef(ctx, repoId, tmp);
    if (
      moved.status < 300 &&
      refUpdatesSucceeded(moved.json) &&
      (await headOf(ctx, repoId, MAIN)) === commit
    ) {
      notes.push(
        `main of ${SETUP_REPOSITORY} force-moved to a parentless commit with ${HELLO_PATH} alone (it held ${files.length} file(s))`,
      );
      return;
    }
    refused = `the move of main: ${describeAnswer(moved.status, moved.json)}`;
  } else {
    refused = `the parentless commit: ${describeAnswer(pushed.status, pushed.json)}`;
  }
  const changes = resetChanges(files, text);
  const ff = ok(
    await ctx.bot.request('POST', pushes, {
      refUpdates: [{ name: MAIN, oldObjectId: head }],
      commits: [{ comment: RESET_COMMENT, parents: [head], changes: pushChanges(changes) }],
    }),
    'reset main (fast-forward)',
  );
  await rec(ctx, 'push-reset-ff', answerOf(ff));
  notes.push(
    `refused: ${refused}; main of ${SETUP_REPOSITORY} reset by a fast-forward commit instead (${changes.map((c) => `${c.changeType} ${c.path}`).join(', ')})`,
  );
}

async function activePrsFrom(ctx: ProbeContext, repo: Repo, sourceRef: string) {
  const res = ok(
    await ctx.bot.request(
      'GET',
      gitPath(
        ctx,
        repo,
        `/pullrequests?searchCriteria.sourceRefName=${enc(sourceRef)}&searchCriteria.targetRefName=${enc(MAIN)}&searchCriteria.status=active`,
      ),
    ),
    `pull requests from ${sourceRef}`,
  );
  return shape(PrListSchema, res.json, 'pull requests').value;
}

/** The changes of a pull request's newest iteration. */
async function iterationChanges(ctx: ProbeContext, repo: Repo, prId: number) {
  const iterations = shape(
    z.object({ value: z.array(z.object({ id: z.number() }).loose()).min(1) }),
    ok(
      await ctx.bot.request('GET', gitPath(ctx, repo, `/pullRequests/${prId}/iterations`)),
      'iterations',
    ).json,
    'iterations',
  );
  const newest = Math.max(...iterations.value.map((i) => i.id));
  return ok(
    await ctx.bot.request(
      'GET',
      gitPath(ctx, repo, `/pullRequests/${prId}/iterations/${newest}/changes`),
    ),
    'iteration changes',
  );
}

/** Qualor's status on the pull request, newest iteration first; undefined while there is none. */
async function prStatus(ctx: ProbeContext, repo: Repo, prId: number, projectKey: string) {
  const iterations = shape(
    z.object({ value: z.array(z.object({ id: z.number() }).loose()) }),
    ok(
      await ctx.bot.request('GET', gitPath(ctx, repo, `/pullRequests/${prId}/iterations`)),
      'iterations',
    ).json,
    'iterations',
  ).value.toSorted((a, b) => b.id - a.id);
  for (const it of iterations) {
    const res = ok(
      await ctx.bot.request(
        'GET',
        gitPath(ctx, repo, `/pullRequests/${prId}/iterations/${it.id}/statuses`),
      ),
      'iteration statuses',
    );
    const list = shape(z.object({ value: z.array(StatusSchema) }), res.json, 'statuses').value;
    const status = qualorStatus(list, projectKey);
    if (status) return { res, status, iterationId: it.id };
  }
  return undefined;
}

async function definitionBuilds(ctx: ProbeContext, definitionId: number) {
  const res = ok(
    await ctx.bot.request('GET', `/${ctx.project}/_apis/build/builds?definitions=${definitionId}`),
    'builds',
  );
  return { res, list: shape(z.object({ value: z.array(BuildSchema) }), res.json, 'builds').value };
}

/** Cancels the pipeline's unfinished builds of `sourceBranch`; how many it asked to cancel. */
async function cancelBranchBuilds(
  ctx: ProbeContext,
  definitionId: number,
  sourceBranch: string,
): Promise<number> {
  let n = 0;
  for (const b of toCancel((await definitionBuilds(ctx, definitionId)).list, sourceBranch)) {
    const res = await ctx.bot.request('PATCH', `/${ctx.project}/_apis/build/builds/${b.id}`, {
      status: 'cancelling',
    });
    if (res.status < 300) n++;
  }
  return n;
}

/** Pushes one commit that edits the pipeline file on the setup branch; the answer. */
async function pushPipelineEdit(
  ctx: ProbeContext,
  repo: Repo,
  head: string,
  content: string,
): Promise<AzureResponse> {
  return ok(
    await ctx.bot.request('POST', gitPath(ctx, repo, '/pushes'), {
      refUpdates: [{ name: SETUP_REF, oldObjectId: head }],
      commits: [
        {
          comment: `Qualor probe item 27: the bench's scanner image (qualor/scanner:${BENCH_IMAGE_TAG})`,
          parents: [head],
          changes: [
            {
              changeType: 'edit',
              item: { path: PIPELINE_PATH },
              newContent: { content, contentType: 'rawtext' },
            },
          ],
        },
      ],
    }),
    'push the image commit',
  );
}

/** Where the probe pull request's build is, for a status that did not come: its state, and a failure's steps. */
async function prBuildState(ctx: ProbeContext, builds: readonly Build[], prId: number) {
  const listed = builds.find(
    (b) => b.reason === 'pullRequest' && b.sourceBranch === `refs/pull/${prId}/merge`,
  );
  if (!listed) return 'no pullRequest build listed';
  const { build } = await getBuild(ctx, listed.id);
  const state = `build ${build.id} ${build.status}${build.result ? ` ${build.result}` : ''}`;
  return build.status === 'completed' && build.result !== 'succeeded'
    ? `${state}: ${await buildProblem(ctx, build.id)}`
    : state;
}

const mergeStatusOf = (json: unknown): string => {
  const s = (json as { mergeStatus?: unknown } | null)?.mergeStatus;
  return typeof s === 'string' ? s : 'none';
};

// ---------------------------------------------------------------------------------------------
// The bench Qualor

const ConnectionItem = z
  .object({
    id: z.string(),
    provider: z.string(),
    baseUrl: z.string(),
    ciSetup: z.object({ available: z.boolean(), reason: z.string().nullable() }).loose(),
  })
  .loose();

async function readRun(api: QualorApi, ctx: ProbeContext, id: string): Promise<SetupRun> {
  const res = await api.call('GET', `/api/v0/repository-setups/${id}`);
  // A token is shown once with a snippet: it joins the redaction table before anything can print it.
  ctx.redaction.secrets.push(...tokensIn(res.json));
  return shape(SetupRunSchema, res.json, 'setup run');
}

// ---------------------------------------------------------------------------------------------

export const item: ProbeItem = {
  id: 27,
  title:
    'a repository set up end to end on Azure DevOps Services: the setup pull request, the pipeline, the merge, the Build validation policy and a decorated pull request',
  async run(ctx) {
    if (ctx.target !== 'services') {
      return result(
        ctx,
        'no',
        'item 27 runs on the Services target only (the bench Qualor is mapped to it)',
      );
    }
    const qualorUrl = needEnv('AZURE_PROBE_QUALOR_URL');
    const adminPassword = needEnv('AZURE_PROBE_QUALOR_ADMIN_PASSWORD');
    const servicesUrl = needEnv('AZURE_PROBE_SERVICES_URL').replace(/\/+$/, '');
    const checks: Check[] = [];
    const notes: string[] = [];
    const finish = () => done(ctx, checks, notes);

    // The service principal's names join the redaction table before anything is recorded: the
    // setup's pull request, pipeline and policy are its.
    const spId = await servicePrincipalId(ctx);

    // ---- The bench Qualor: organisation `bench`, its Azure connection, CI setup available.
    const api = new QualorApi(qualorUrl);
    await api.login(adminPassword);
    const org = (
      await api.items(
        '/api/v0/organizations',
        z.object({ id: z.string(), key: z.string() }).loose(),
      )
    ).find((o) => o.key === 'bench');
    if (!org) throw new Error('the bench Qualor has no organisation `bench` (run seed-qualor.mjs)');
    const connection = (
      await api.items(`/api/v0/scm-connections?organizationId=${org.id}`, ConnectionItem)
    ).find((c) => c.provider === 'azure' && c.baseUrl.replace(/\/+$/, '') === servicesUrl);
    if (!connection)
      throw new Error('the bench Qualor has no Azure DevOps connection (run seed-qualor.mjs)');
    if (!connection.ciSetup.available) {
      return result(
        ctx,
        'no',
        `CI setup is not available on the bench Azure connection (${connection.ciSetup.reason ?? 'no reason'}): run seed-qualor.mjs --setup`,
      );
    }

    // ---- The repository, what an earlier run left removed, main as each run starts it.
    const created = await ensureRepository(ctx, notes, SETUP_REPOSITORY);
    await clearEarlierRun(ctx, created.id, notes);
    await resetMain(ctx, created.id, notes);
    const setupCtx: ProbeContext = { ...ctx, repo: SETUP_REPOSITORY };
    const repo = await repoInfo(setupCtx);
    // A run that stops before the merge leaves no open setup pull request or branch.
    ctx.cleanup.add(
      `abandon the setup pull request and delete ${SETUP_BRANCH} if left`,
      async () => {
        for (const pr of await activePrsFrom(setupCtx, repo, SETUP_REF)) {
          await abandonPr(setupCtx, pr.pullRequestId);
        }
        await deleteBranch(setupCtx, SETUP_REF);
      },
    );

    // ---- 1. The setup, on the bench's self-hosted pool.
    const posted = await api.send('POST', '/api/v0/repository-setups', {
      organizationId: org.id,
      connectionId: connection.id,
      repositories: [repo.id],
      ciSetup: true,
      azurePool: POOL,
    });
    if (posted.status !== 202) {
      checks.push(
        check(
          'the setup run is accepted (202)',
          false,
          `HTTP ${posted.status} ${problemText(posted.json)}`,
        ),
      );
      return finish();
    }
    const runId = shape(z.object({ id: z.string() }).loose(), posted.json, 'setup run').id;
    const doneRun = await waitFor(
      async () => {
        const run = await readRun(api, ctx, runId);
        return run.status === 'done' ? run : undefined;
      },
      { timeoutMs: SETUP_WAIT_MS, intervalMs: 3000 },
    );
    const run = doneRun ?? (await readRun(api, ctx, runId));
    checks.push(judgeSetupItem(run));
    const setupItem = run.items[0];
    if (!doneRun || setupItem?.ciOutcome !== 'merge_request' || !setupItem.project) {
      return finish();
    }
    const project = setupItem.project;
    notes.push(
      `setup run: project ${setupItem.projectOutcome} with key ${project.key}; azure.queue ${setupItem.azure?.queue ?? 'absent'}`,
    );

    // ---- 2. The pipeline first: its QUALOR_URL's host joins the redaction table before any recording.
    const queueId = await defaultQueueId(ctx);
    const listed = setupDefinitions(
      ok(
        await ctx.bot.request(
          'GET',
          `/${ctx.project}/_apis/build/definitions?repositoryId=${repo.id}&repositoryType=TfsGit&includeAllProperties=true`,
        ),
        'definitions of the repository',
      ).json,
      repo.id,
    );
    const defId = definitionIdOf(setupItem.azure?.pipelineUrl) ?? listed.own[0]?.id;
    if (defId === undefined) {
      checks.push(
        check(
          "the setup's pipeline is found",
          false,
          'no pipelineUrl and no pipeline named Qualor',
        ),
      );
      return finish();
    }
    const defRes = ok(
      await ctx.bot.request('GET', `/${ctx.project}/_apis/build/definitions/${defId}`),
      'definition',
    );
    const def = shape(DefinitionSchema, defRes.json, 'definition');
    const urlValue = def.variables?.['QUALOR_URL']?.value;
    if (urlValue) addHosts(ctx.redaction, hostsOf(urlValue));
    await rec(ctx, 'definition', { ...answerOf(defRes), body: definitionRecording(defRes.json) });
    notes.push(`the setup's pipeline: "${def.name}" (definition ${def.id})`);

    // ---- 3. The setup's pull request as it opened it.
    const setupPr = (await activePrsFrom(setupCtx, repo, SETUP_REF))[0];
    if (!setupPr) {
      checks.push(check(`an active pull request from ${SETUP_BRANCH}`, false, 'none found'));
      return finish();
    }
    const prId = setupPr.pullRequestId;
    const prRes = ok(
      await ctx.bot.request('GET', gitPath(setupCtx, repo, `/pullrequests/${prId}`)),
      'setup pull request',
    );
    await rec(ctx, 'setup-pr', answerOf(prRes));
    const changes = await iterationChanges(setupCtx, repo, prId);
    await rec(ctx, 'setup-pr-changes', answerOf(changes));
    const setupHead = await refHead(setupCtx, SETUP_REF);
    const yaml = setupHead ? await fileText(ctx, repo.id, PIPELINE_PATH, setupHead) : null;
    checks.push(...judgeSetupPr(setupPr, changedFiles(changes.json), yaml));
    notes.push(
      `setup pull request ${prId}: created by ${sameId(setupPr.createdBy?.id, spId) ? 'the service principal' : 'another identity'}; the run's ciUrl ${setupItem.ciUrl === `${repo.webUrl}/pullrequest/${prId}` ? 'is its web URL' : 'differs from its web URL'}; the file's image ${imageOf(yaml) ?? 'line missing'}`,
    );

    // ---- 4. The pipeline's variables, its queue, the pending policy.
    checks.push(...judgeDefinition(def, { repositoryId: repo.id, queueId, qualorUrl }));
    const perms = await queuePermissions(ctx, queueId);
    await rec(ctx, 'queue-permissions', answerOf(perms.res));
    checks.push(
      judgeQueue(setupItem.azure?.queue, { open: perms.open, authorized: perms.authorized(defId) }),
    );
    checks.push(judgePending(setupItem));

    // ---- 5. What a person does on the bench: the image pinned to the bench's tag in the pull request.
    const pinned = yaml === null ? null : pinBenchImage(yaml);
    if (!setupHead || pinned === null) {
      checks.push(
        check(
          `the pipeline file's image can be pinned to qualor/scanner:${BENCH_IMAGE_TAG}`,
          false,
          setupHead ? 'no QUALOR_SCANNER_IMAGE line' : `${SETUP_BRANCH} has no head`,
        ),
      );
      return finish();
    }
    const imagePush = await pushPipelineEdit(setupCtx, repo, setupHead, pinned);
    await rec(ctx, 'push-image', answerOf(imagePush));
    const imageCommit = pushedCommit(imagePush, 'push the image commit').toLowerCase();

    // ---- 6. Complete the pull request (merge into main).
    const current = await waitFor(
      async () => {
        const got = await getPr(setupCtx, prId);
        return sameId(got.pr.lastMergeSourceCommit?.commitId, imageCommit) ? got : undefined;
      },
      { timeoutMs: SOURCE_WAIT_MS, intervalMs: 3000 },
    );
    const before = (await qualorMain(api, project.id))?.lastAnalysisId ?? null;
    const completeRes = await ctx.bot.request(
      'PATCH',
      gitPath(setupCtx, repo, `/pullrequests/${prId}`),
      {
        status: 'completed',
        lastMergeSourceCommit: {
          commitId: current?.pr.lastMergeSourceCommit?.commitId ?? imageCommit,
        },
        completionOptions: { deleteSourceBranch: true, mergeStrategy: 'noFastForward' },
      },
    );
    await rec(ctx, 'pr-complete', answerOf(completeRes));
    const completed =
      completeRes.status < 300
        ? await waitFor(
            async () => {
              const got = await getPr(setupCtx, prId);
              return got.pr.status === 'completed' ? got : undefined;
            },
            { timeoutMs: MERGE_WAIT_MS, intervalMs: 5000 },
          )
        : undefined;
    const afterComplete = completed ?? (await getPr(setupCtx, prId));
    checks.push(
      check(
        'the setup pull request is completed (merged into main) through REST',
        completed !== undefined,
        completeRes.status >= 300
          ? describeAnswer(completeRes.status, completeRes.json)
          : `${afterComplete.pr.status}, mergeStatus ${mergeStatusOf(afterComplete.res.json)}`,
      ),
    );
    if (!completed) return finish();
    const mergeCommit = (await refHead(setupCtx, MAIN))?.toLowerCase();

    // ---- 7. The main build and the main analysis, 15 minutes for both.
    ctx.log(
      `setup pull request ${prId} merged: the main build and analysis (up to ${MAIN_WAIT_MS / 60000} min), then the policy`,
    );
    const mainDeadline = Date.now() + MAIN_WAIT_MS;
    let cancelledSetup = 0;
    const queued = await waitFor(
      async () => {
        // The image commit's CI build of the setup branch is not needed: the one agent goes to main.
        cancelledSetup += await cancelBranchBuilds(ctx, defId, SETUP_REF);
        return mainBuildOf((await definitionBuilds(ctx, defId)).list, mergeCommit);
      },
      { timeoutMs: MAIN_QUEUED_MS, intervalMs: 10_000 },
    );
    if (cancelledSetup > 0) {
      notes.push(`${cancelledSetup} CI build(s) of ${SETUP_BRANCH} cancelled (not needed)`);
    }
    if (!queued) {
      checks.push(
        check(
          'a build of main by the pipeline completed',
          false,
          `none queued within ${MAIN_QUEUED_MS / 60000} min`,
        ),
      );
      return finish();
    }
    const mainBuild = await waitBuild(ctx, queued.id, {
      timeoutMs: Math.max(0, mainDeadline - Date.now()),
    });
    await rec(ctx, 'build-main', answerOf(mainBuild.res));
    checks.push(
      check(
        'a build of main by the pipeline completed',
        mainBuild.build.status === 'completed',
        `build ${queued.id} ${mainBuild.build.status} ${mainBuild.build.result ?? ''}`.trim() +
          (sameId(mainBuild.build.sourceVersion, mergeCommit ?? '') ? ', of the merge commit' : ''),
      ),
    );
    const analysed = await waitFor(
      async () => {
        const b = await qualorMain(api, project.id);
        return b?.lastAnalysisId && b.lastAnalysisId !== before ? b : undefined;
      },
      {
        timeoutMs: Math.max(mainDeadline - Date.now(), ANALYSIS_GRACE_MS),
        intervalMs: 10_000,
      },
    );
    checks.push(
      check(
        'Qualor analysed main (a new main analysis of the project)',
        analysed !== undefined,
        analysed
          ? 'a new main analysis'
          : `none within ${MAIN_WAIT_MS / 60000} min${mainBuild.build.status === 'completed' && mainBuild.build.result !== 'succeeded' ? `; ${await buildProblem(ctx, queued.id)}` : ''}`,
      ),
    );
    if (!analysed) return finish();

    // ---- 8. The Build validation policy: the run's item turns `on`, Azure DevOps has it on main.
    const settled = await waitFor(
      async () => {
        const got = (await readRun(api, ctx, runId)).items[0];
        return got && got.azure?.policy !== 'pending' ? got : undefined;
      },
      { timeoutMs: POLICY_WAIT_MS, intervalMs: 10_000 },
    );
    checks.push(judgePolicyOn(settled ?? (await readRun(api, ctx, runId)).items[0]));
    const policiesRes = ok(
      await ctx.bot.request(
        'GET',
        `/${ctx.project}/_apis/policy/configurations?repositoryId=${repo.id}&refName=${enc(MAIN)}&policyType=${BUILD_POLICY}`,
      ),
      'policies on main',
    );
    await rec(ctx, 'policies-main', answerOf(policiesRes));
    const policy = judgeMainPolicy(policiesRes.json, {
      definitionId: defId,
      repositoryId: repo.id,
    });
    checks.push(policy.check);
    if (policy.policyId === null) return finish();

    // ---- 9. A probe pull request: the policy's build, then Qualor's status on it.
    const base = await refHead(setupCtx, MAIN);
    if (!base) throw new Error('main has no head after the merge');
    const pushed = await pushFiles(
      setupCtx,
      `probe/27-${ctx.stamp}`,
      [{ path: `/src/probe-27-${ctx.stamp}.js`, content: probeSource(ctx.stamp) }],
      { base },
    );
    const probe = await createPr(setupCtx, pushed.refName);
    const probeId = probe.pr.pullRequestId;
    const statusDeadline = Date.now() + STATUS_WAIT_MS;
    const { pr: probePr } = await prWithMerge(setupCtx, probeId);
    const prBuildNow = async () => {
      const b = await definitionBuilds(ctx, defId);
      const e = await evaluations(setupCtx, probePr);
      const c = judgePrBuild(b.list, e.list.value, { prId: probeId, policyId: policy.policyId });
      return { b, e, c };
    };
    const built = await waitFor(
      async () => {
        const now = await prBuildNow();
        return now.c.pass ? now : undefined;
      },
      { timeoutMs: PR_BUILD_WAIT_MS, intervalMs: 10_000 },
    );
    const prBuild = built ?? (await prBuildNow());
    await rec(ctx, 'builds-pr', answerOf(prBuild.b.res));
    await rec(ctx, 'evaluations-pr', answerOf(prBuild.e.res));
    checks.push(prBuild.c);
    const cancelledProbe = await cancelBranchBuilds(ctx, defId, pushed.refName);
    if (cancelledProbe > 0) {
      notes.push(`${cancelledProbe} CI build(s) of the probe branch cancelled (not needed)`);
    }
    if (!built) return finish();
    ctx.log(
      `probe pull request ${probeId}: Qualor's status (up to ${STATUS_WAIT_MS / 60000} min from its creation)`,
    );
    const status = await waitFor(() => prStatus(setupCtx, repo, probeId, project.key), {
      timeoutMs: Math.max(0, statusDeadline - Date.now()),
      intervalMs: 15_000,
    });
    if (status) await rec(ctx, 'iteration-statuses-pr', answerOf(status.res));
    checks.push(
      check(
        "Qualor's status (genre qualor, the project key as its name) on the probe pull request",
        status !== undefined,
        status
          ? `${status.status.state ?? '?'} on iteration ${status.iterationId}; author ${status.status.createdBy ? (sameId(status.status.createdBy.id, spId) ? 'the service principal' : 'another identity') : 'not listed'}`
          : `none within ${STATUS_WAIT_MS / 60000} min; ${await prBuildState(ctx, prBuild.b.list, probeId)}`,
      ),
    );
    return finish();
  },
};

/**
 * The checks the full flow makes: the run, 3 on the setup's pull request, 2 on the pipeline, the
 * queue, the pending policy, the merge, the main build, the main analysis, the policy `on`, the
 * policy on main, the pull request build, Qualor's status.
 */
const ALL_CHECKS = 15;

function done(ctx: ProbeContext, checks: Check[], notes: string[]) {
  for (const c of checks) ctx.log(`${c.pass ? 'yes' : 'NO '} ${c.what}: ${c.got}`);
  const pass = checks.length >= ALL_CHECKS && checks.every((c) => c.pass);
  const detail = [
    `repository ${SETUP_REPOSITORY}; setup on the agent pool ${POOL}; the item pins the image to qualor/scanner:${BENCH_IMAGE_TAG} in the setup pull request`,
    ...checks.map((c) => `${c.pass ? 'yes' : 'NO'} - ${c.what}: ${c.got}`),
    ...notes.map((n) => `note: ${n}`),
  ].join('\n\n');
  return Promise.resolve(result(ctx, pass ? 'yes' : 'no', detail));
}
