import { z } from 'zod';
import { azureStatusName } from '../../../server/src/scm/render';
import type { AzureClient, AzureResponse } from '../client.js';
import { BENCH_IMAGE_TAG } from './18-ci.js';
import {
  BENCH_ORG,
  benchScmUrl,
  check,
  needEnv,
  qualorIdentityId,
  qualorIdentityName,
  rec,
  type Check,
} from './19-decoration.js';
import { QualorApi } from './21-review.js';
import { qualorConnectionRecord, recordedResult, setupRights } from './identity.js';
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
  CallError,
  cancelBuilds,
  createPr,
  defaultQueueId,
  deleteBranch,
  deleteRefWith,
  evaluations,
  getBuild,
  getPr,
  gitPath,
  hostsOf,
  ok,
  prWithMerge,
  pushFiles,
  queueBuild,
  queuePermissions,
  RefUpdateError,
  refHead,
  remove,
  repoInfo,
  result,
  shape,
  waitBuild,
  waitFor,
  type ProbeContext,
  type ProbeItem,
  type ProbeResult,
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
/** The reset's temporary refs (one per run, deleted by it; an interrupted run may leave one). */
const TMP_PREFIX = 'refs/qualor/probe-tmp/27-';
const MAIN = 'refs/heads/main';
const SETUP_REF = `refs/heads/${SETUP_BRANCH}`;
const ZEROS = '0'.repeat(40);
const RESET_COMMENT = 'Qualor probe item 27: main as each run starts it';
/** The setup run itself: a few Azure DevOps calls. */
const SETUP_WAIT_MS = 5 * 60_000;
/** Azure DevOps takes the image commit into the pull request, then completes it. */
const SOURCE_WAIT_MS = 2 * 60_000;
const MERGE_WAIT_MS = 3 * 60_000;
/**
 * Ruling: the main build and the main analysis together, 15 minutes. CI must queue the build
 * within 5 (else the item queues it by hand); the last 2 are kept for the analysis.
 */
const MAIN_WAIT_MS = 15 * 60_000;
const MAIN_QUEUED_MS = 5 * 60_000;
const ANALYSIS_SHARE_MS = 2 * 60_000;
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

/**
 * The refs an earlier run may have left: the setup's branch, the item's probe branches and the
 * reset's temporary refs.
 */
export function staleRefs(refs: readonly Ref[]): Ref[] {
  return refs.filter(
    (r) => r.name === SETUP_REF || r.name.startsWith(PROBE_PREFIX) || r.name.startsWith(TMP_PREFIX),
  );
}

/** The name a pipeline of an earlier run gets before it is deleted. */
export const retiredName = (stamp: string, id: number): string => `Qualor deleted ${stamp} ${id}`;

export type RetireOps = {
  get: (id: number) => Promise<Record<string, unknown>>;
  put: (id: number, body: Record<string, unknown>) => Promise<void>;
  remove: (id: number) => Promise<void>;
};

/**
 * Renames a pipeline, then deletes it: Azure DevOps soft-deletes a build definition and may keep
 * its name taken, which would leave a later setup without `Qualor` and its fallback name. The
 * definition is read and PUT back whole with the new name (item 26's GET+PUT); a refused rename
 * deletes nothing. The new name.
 */
export async function retireDefinition(ops: RetireOps, id: number, stamp: string): Promise<string> {
  const current = await ops.get(id);
  const name = retiredName(stamp, id);
  await ops.put(id, { ...current, name });
  await ops.remove(id);
  return name;
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

const appliesTo = (p: Policy, repositoryId: string): boolean =>
  (p.settings.scope ?? []).some((s) => sameId(s.repositoryId, repositoryId));

/**
 * The Build validation policies an earlier run left on main: those of the setup's pipelines, and
 * those named `Qualor` that apply to this repository (the list may hold other repositories').
 */
export function policiesToRemove(
  json: unknown,
  definitionIds: readonly number[],
  repositoryId: string,
): number[] {
  return shape(PolicyListSchema, json, 'policies')
    .value.filter(
      (p) =>
        isBuildPolicy(p) &&
        ((p.settings.buildDefinitionId !== undefined &&
          definitionIds.includes(p.settings.buildDefinitionId)) ||
          (p.settings.displayName === POLICY_NAME && appliesTo(p, repositoryId))),
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
  let got = `run ${run.status}; no item`;
  if (item) {
    const reason = item.ciReason ? ` (${item.ciReason})` : '';
    const error = item.error ? `; error ${item.error.code}: ${item.error.message}` : '';
    got = `run ${run.status}; ciOutcome ${item.ciOutcome}${reason}; project ${item.projectOutcome}${error}`;
  }
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
  const policyError = item?.azure?.policyError ? `: ${item.azure.policyError}` : '';
  return check(
    "the run's item has azure.policy `on` after the main analysis",
    policy === 'on',
    `${policy}${policyError}`,
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
    triggers: z
      .array(
        z
          .object({ triggerType: z.string().optional(), settingsSourceType: z.number().optional() })
          .loose(),
      )
      .nullish(),
  })
  .loose();
export type Definition = z.infer<typeof DefinitionSchema>;

/** A definition's triggers in words: the CI trigger says where its settings come from. */
export function triggersText(triggers: Definition['triggers']): string {
  if (!triggers || triggers.length === 0) return 'none';
  return triggers
    .map((t) => {
      const type = t.triggerType ?? 'unknown';
      if (type !== 'continuousIntegration') return type;
      return `${type} (settings ${t.settingsSourceType === 2 ? 'from the YAML' : 'in the definition'})`;
    })
    .join(', ');
}

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
  let urlText = 'absent';
  if (url && urlSet) {
    const address = sameUrl(urlValue, want.qualorUrl)
      ? "the probe's Qualor address"
      : 'another address than the probe uses';
    urlText = `set (${address})`;
  } else if (url) {
    urlText = 'without a value';
  }
  let tokenText = 'absent';
  if (token) {
    const readBack =
      token.value === null || token.value === undefined
        ? 'no value read back'
        : 'a value read back';
    tokenText = `isSecret ${String(token.isSecret === true)}, ${readBack}`;
  }
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

/**
 * The pipeline runs on pushes: CI (not a person) queued the main build after the merge. Whether the
 * image commit's push to the setup branch started a build too is told alongside.
 */
export function judgeCiQueued(build: Build | undefined, setupBranchBuilt: boolean): Check {
  let setup = 'started no CI build either';
  if (setupBranchBuilt) setup = 'started a CI build';
  else if (build) setup = 'started no CI build';
  const mainBuild = build
    ? `build ${build.id}, reason ${build.reason ?? 'unknown'}`
    : `no build of main within ${MAIN_QUEUED_MS / 60000} min`;
  return check(
    'CI queued the main build (the pipeline runs on pushes)',
    build !== undefined && build.reason !== 'manual',
    `${mainBuild}; the image commit on ${SETUP_BRANCH} ${setup}`,
  );
}

/** How long the main build may take within the 15 minutes: what is left, less the analysis's share. */
export function mainWaits(deadline: number, now: number): { buildMs: number } {
  return { buildMs: Math.max(0, deadline - ANALYSIS_SHARE_MS - now) };
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
  const prResult = prBuild?.result ? ` ${prBuild.result}` : '';
  const prText = prBuild
    ? `build ${prBuild.id} (reason pullRequest, ${prBuild.status}${prResult})`
    : 'no pullRequest build of the pipeline';
  const withBuild = typeof evBuild === 'number' ? ` with build ${evBuild}` : ' without a build';
  const evText = ev ? `evaluation ${ev.status}${withBuild}` : 'no evaluation of the policy';
  return check(
    'the policy queued a build of the pipeline for the probe pull request',
    prBuild !== undefined || typeof evBuild === 'number',
    `${prText}; ${evText}`,
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
  const name = azureStatusName(projectKey);
  return statuses
    .filter(
      (s) =>
        s.context.genre === 'qualor' &&
        s.context.name === name &&
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
  let message = '';
  if (first && typeof first.message === 'string') {
    const at = typeof first.path === 'string' ? `${first.path}: ` : '';
    message = `${at}${first.message}`;
  } else if (typeof p.detail === 'string') {
    message = p.detail;
  } else if (typeof p.title === 'string') {
    message = p.title;
  }
  const shown = message ? ` (${message.slice(0, 200)})` : '';
  return `${codeOf(json)}${shown}`;
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

/**
 * Deletes `name` (a full ref name) of a repository read by id by its current head, when it is
 * there ({@link deleteRefWith}: a stale head is read again once; a refusal says Azure's word).
 */
async function deleteRef(
  ctx: ProbeContext,
  repoId: string,
  name: string,
  client: AzureClient = ctx.bot,
): Promise<boolean> {
  return deleteRefWith(
    {
      head: () => headOf(ctx, repoId, name),
      remove: (oldObjectId) =>
        client.request('POST', gitById(ctx, repoId, '/refs'), [
          { name, oldObjectId, newObjectId: ZEROS },
        ]),
    },
    name,
  );
}

const refusal = (err: unknown): string | null => {
  if (err instanceof RefUpdateError) return err.updateStatus;
  if (err instanceof CallError) return `HTTP ${err.status}`;
  return null;
};

/**
 * Deletes the setup branch an earlier run left. It is Qualor's: when the probe's identity may not
 * delete it, Qualor's own (the service principal, which pushed it) tries. A branch still there is
 * no stop: the setup reuses a `qualor/setup` it finds (product behaviour). The note says why.
 */
async function deleteSetupBranch(
  ctx: ProbeContext,
  repoId: string,
  notes: string[],
): Promise<boolean> {
  const words: string[] = [];
  for (const [who, client] of [
    ['the probe', ctx.bot],
    ["Qualor's service principal", ctx.entra?.('secret')],
  ] as const) {
    if (!client) continue;
    try {
      const deleted = await deleteRef(ctx, repoId, SETUP_REF, client);
      if (words.length > 0) notes.push(`${SETUP_BRANCH} deleted by ${who} (${words.join('; ')})`);
      return deleted;
    } catch (err) {
      const word = refusal(err);
      if (word === null) throw err;
      words.push(`${who}: ${word}`);
    }
  }
  notes.push(
    `${SETUP_BRANCH} of an earlier run could not be deleted (${words.join('; ')}); the run goes on and the setup reuses the branch`,
  );
  return false;
}

/**
 * What an earlier run left, before the setup: every active pull request of the repository (the
 * item's alone) abandoned, the setup's pipelines (renamed first: {@link retireDefinition}) and
 * their Build validation policies on main removed, the setup branch, the item's probe branches and
 * the reset's temporary refs deleted.
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
    repoId,
  );
  for (const id of policies) await remove(ctx.bot, `${root}/policy/configurations/${id}`, 'policy');
  const definitionPath = (id: number) => `${root}/build/definitions/${id}`;
  const retired: string[] = [];
  for (const d of defs.own) {
    await cancelBuilds(ctx, d.id);
    const name = await retireDefinition(
      {
        get: async (id) =>
          shape(
            z.record(z.string(), z.unknown()),
            ok(await ctx.bot.request('GET', definitionPath(id)), `definition ${id}`).json,
            'definition',
          ),
        put: async (id, body) => {
          ok(await ctx.bot.request('PUT', definitionPath(id), body), `rename definition ${id}`);
        },
        remove: (id) => remove(ctx.bot, definitionPath(id), `definition ${id}`),
      },
      d.id,
      ctx.stamp,
    );
    retired.push(`"${d.name}" ${d.id} as "${name}"`);
  }
  const listRefs = async (filter: string) =>
    shape(
      RefListSchema,
      ok(await ctx.bot.request('GET', gitById(ctx, repoId, `/refs?filter=${filter}`)), 'refs').json,
      'refs',
    ).value;
  const stale = staleRefs([
    ...(await listRefs('heads/')),
    ...(await listRefs(TMP_PREFIX.slice('refs/'.length))),
  ]);
  // Only the refs this run deleted count: a setup branch that stays, or a ref already gone, does not.
  let deleted = 0;
  for (const r of stale) {
    const gone =
      r.name === SETUP_REF
        ? await deleteSetupBranch(ctx, repoId, notes)
        : await deleteRef(ctx, repoId, r.name);
    if (gone) deleted++;
  }
  const retiredText = retired.length ? ` (${retired.join(', ')})` : '';
  notes.push(
    `before the setup: ${prs.length} active pull request(s) abandoned, ${policies.length} Build validation policy(ies) removed, ${defs.own.length} pipeline(s) of an earlier run renamed and deleted${retiredText}, ${deleted} ref(s) deleted`,
  );
  if (defs.others.length > 0) {
    const others = defs.others.map((d) => `"${d.name}" ${d.id}`).join(', ');
    notes.push(
      `other pipelines on ${PIPELINE_PATH.slice(1)} stay (the setup will call them foreign): ${others}`,
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
  const tmp = `${TMP_PREFIX}${ctx.stamp}`;
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
    try {
      await deleteRef(ctx, repoId, tmp);
    } catch (err) {
      // The reset does not depend on it: the clean-up step tries again.
      notes.push(`the temporary ref was not deleted at once (${(err as Error).message})`);
    }
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
    `reset main (fast-forward, after the force-move was refused: ${refused})`,
  );
  await rec(ctx, 'push-reset-ff', answerOf(ff));
  const changed = changes.map((c) => `${c.changeType} ${c.path}`).join(', ');
  notes.push(
    `refused: ${refused}; main of ${SETUP_REPOSITORY} reset by a fast-forward commit instead (${changed})`,
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

/** Asks to cancel each build (best effort); how many Azure DevOps took. */
async function cancelEach(ctx: ProbeContext, builds: readonly Build[]): Promise<number> {
  let n = 0;
  for (const b of builds) {
    const res = await ctx.bot.request('PATCH', `/${ctx.project}/_apis/build/builds/${b.id}`, {
      status: 'cancelling',
    });
    if (res.status < 300) n++;
  }
  return n;
}

/** Cancels the pipeline's unfinished builds of `sourceBranch`; how many it asked to cancel. */
async function cancelBranchBuilds(
  ctx: ProbeContext,
  definitionId: number,
  sourceBranch: string,
): Promise<number> {
  return cancelEach(ctx, toCancel((await definitionBuilds(ctx, definitionId)).list, sourceBranch));
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
  const result = build.result ? ` ${build.result}` : '';
  const state = `build ${build.id} ${build.status}${result}`;
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

/** What every phase of the item shares: the checks and notes so far and the bench Qualor's login. */
interface Flow {
  ctx: ProbeContext;
  api: QualorApi;
  checks: Check[];
  notes: string[];
  spId: string;
  who: string;
}

type Connection = z.infer<typeof ConnectionItem>;
type SetupProject = NonNullable<SetupItem['project']>;

/** The organisation `bench` and its Azure connection on the bench Qualor. */
async function findBenchConnection(
  api: QualorApi,
  scmUrl: string,
): Promise<{ orgId: string; connection: Connection }> {
  const org = (
    await api.items('/api/v0/organizations', z.object({ id: z.string(), key: z.string() }).loose())
  ).find((o) => o.key === BENCH_ORG);
  if (!org) throw new Error('the bench Qualor has no organisation `bench` (run seed-qualor.mjs)');
  const connection = (
    await api.items(`/api/v0/scm-connections?organizationId=${org.id}`, ConnectionItem)
  ).find((c) => c.provider === 'azure' && c.baseUrl.replace(/\/+$/, '') === scmUrl);
  if (!connection)
    throw new Error('the bench Qualor has no Azure DevOps connection (run seed-qualor.mjs)');
  return { orgId: org.id, connection };
}

/** A run that stops before the merge leaves no open setup pull request or branch. */
async function abandonSetupLeftovers(ctx: ProbeContext, setupCtx: ProbeContext, repo: Repo) {
  for (const pr of await activePrsFrom(setupCtx, repo, SETUP_REF)) {
    await abandonPr(setupCtx, pr.pullRequestId);
  }
  try {
    await deleteBranch(setupCtx, SETUP_REF);
  } catch (err) {
    // Qualor's service principal pushed the branch: it tries when the probe may not.
    const sp = ctx.entra?.('secret');
    if (!sp || refusal(err) === null) throw err;
    await deleteBranch(setupCtx, SETUP_REF, sp);
  }
}

/** The repository, what an earlier run left removed, main as each run starts it. */
async function prepareRepository(ctx: ProbeContext, notes: string[], seen: WeakerSeen) {
  const created = await ensureRepository(ctx, notes, SETUP_REPOSITORY);
  await clearEarlierRun(ctx, created.id, notes);
  await resetMain(ctx, created.id, notes);
  const setupCtx: ProbeContext = { ...ctx, repo: SETUP_REPOSITORY };
  const repo = await repoInfo(setupCtx);
  seen.repo = repo;
  ctx.cleanup.add(`abandon the setup pull request and delete ${SETUP_BRANCH} if left`, () =>
    abandonSetupLeftovers(ctx, setupCtx, repo),
  );
  return { setupCtx, repo };
}

/** 1. The setup, on the bench's self-hosted pool; undefined when it did not end in a pull request. */
async function runSetup(flow: Flow, ids: { orgId: string; connectionId: string }, repo: Repo) {
  const { ctx, api, checks, notes } = flow;
  const posted = await api.send('POST', '/api/v0/repository-setups', {
    organizationId: ids.orgId,
    connectionId: ids.connectionId,
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
    return undefined;
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
  if (!doneRun || setupItem?.ciOutcome !== 'merge_request' || !setupItem.project) return undefined;
  const project: SetupProject = setupItem.project;
  notes.push(
    `setup run: project ${setupItem.projectOutcome} with key ${project.key}; azure.queue ${setupItem.azure?.queue ?? 'absent'}`,
  );
  return { runId, setupItem, project };
}

/** 2. The pipeline first: its QUALOR_URL's host joins the redaction table before any recording. */
async function readPipeline(flow: Flow, repo: Repo, setupItem: SetupItem) {
  const { ctx, checks, notes } = flow;
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
      check("the setup's pipeline is found", false, 'no pipelineUrl and no pipeline named Qualor'),
    );
    return undefined;
  }
  // The pipeline stays for the next run, but none of its builds may hold the bench's one agent.
  ctx.cleanup.add(`cancel the unfinished builds of the setup's pipeline ${defId} (it stays)`, () =>
    cancelBuilds(ctx, defId),
  );
  const defRes = ok(
    await ctx.bot.request('GET', `/${ctx.project}/_apis/build/definitions/${defId}`),
    'definition',
  );
  const def = shape(DefinitionSchema, defRes.json, 'definition');
  const urlValue = def.variables?.['QUALOR_URL']?.value;
  if (urlValue) addHosts(ctx.redaction, hostsOf(urlValue));
  await rec(ctx, 'definition', { ...answerOf(defRes), body: definitionRecording(defRes.json) });
  notes.push(
    `the setup's pipeline: "${def.name}" (definition ${def.id}); triggers ${triggersText(def.triggers)}`,
  );
  return { queueId, defId, def };
}

/** 3. and 4. The setup's pull request as it opened it, the pipeline's variables, queue and pending policy. */
async function judgeSetupState(
  flow: Flow,
  setupCtx: ProbeContext,
  repo: Repo,
  state: {
    setupItem: SetupItem;
    qualorUrl: string;
    pipeline: { queueId: number; defId: number; def: Definition };
  },
) {
  const { ctx, checks, notes, spId, who } = flow;
  const { setupItem, qualorUrl } = state;
  const { queueId, defId, def } = state.pipeline;
  const setupPr = (await activePrsFrom(setupCtx, repo, SETUP_REF))[0];
  if (!setupPr) {
    checks.push(check(`an active pull request from ${SETUP_BRANCH}`, false, 'none found'));
    return undefined;
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
  const createdBy = sameId(setupPr.createdBy?.id, spId) ? who : 'another identity';
  const ciUrl =
    setupItem.ciUrl === `${repo.webUrl}/pullrequest/${prId}`
      ? 'is its web URL'
      : 'differs from its web URL';
  notes.push(
    `setup pull request ${prId}: created by ${createdBy}; the run's ciUrl ${ciUrl}; the file's image ${imageOf(yaml) ?? 'line missing'}`,
  );

  checks.push(...judgeDefinition(def, { repositoryId: repo.id, queueId, qualorUrl }));
  const perms = await queuePermissions(ctx, queueId);
  await rec(ctx, 'queue-permissions', answerOf(perms.res));
  checks.push(
    judgeQueue(setupItem.azure?.queue, { open: perms.open, authorized: perms.authorized(defId) }),
  );
  checks.push(judgePending(setupItem));
  return { prId, yaml, setupHead };
}

/** 5. What a person does on the bench: the image pinned to the bench's tag in the pull request. */
async function pinImageInPr(
  flow: Flow,
  setupCtx: ProbeContext,
  repo: Repo,
  seen: { yaml: string | null; setupHead: string | undefined },
) {
  const { ctx, checks } = flow;
  const { yaml, setupHead } = seen;
  const pinned = yaml === null ? null : pinBenchImage(yaml);
  if (!setupHead || pinned === null) {
    checks.push(
      check(
        `the pipeline file's image can be pinned to qualor/scanner:${BENCH_IMAGE_TAG}`,
        false,
        setupHead ? 'no QUALOR_SCANNER_IMAGE line' : `${SETUP_BRANCH} has no head`,
      ),
    );
    return undefined;
  }
  const imagePush = await pushPipelineEdit(setupCtx, repo, setupHead, pinned);
  await rec(ctx, 'push-image', answerOf(imagePush));
  return pushedCommit(imagePush, 'push the image commit').toLowerCase();
}

/** 6. Complete the pull request (merge into main); the merge commit, or undefined when it did not complete. */
async function completeSetupPr(
  flow: Flow,
  setupCtx: ProbeContext,
  repo: Repo,
  merge: { prId: number; imageCommit: string; projectId: string },
) {
  const { ctx, api, checks } = flow;
  const { prId, imageCommit } = merge;
  const current = await waitFor(
    async () => {
      const got = await getPr(setupCtx, prId);
      return sameId(got.pr.lastMergeSourceCommit?.commitId, imageCommit) ? got : undefined;
    },
    { timeoutMs: SOURCE_WAIT_MS, intervalMs: 3000 },
  );
  const before = (await qualorMain(api, merge.projectId))?.lastAnalysisId ?? null;
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
  const got =
    completeRes.status >= 300
      ? describeAnswer(completeRes.status, completeRes.json)
      : `${afterComplete.pr.status}, mergeStatus ${mergeStatusOf(afterComplete.res.json)}`;
  checks.push(
    check(
      'the setup pull request is completed (merged into main) through REST',
      completed !== undefined,
      got,
    ),
  );
  if (!completed) return undefined;
  return { mergeCommit: (await refHead(setupCtx, MAIN))?.toLowerCase(), before };
}

/** 7a. The main build: CI's, or one queued by hand when CI did not queue it; its id and the shared deadline. */
async function queueMainBuild(
  flow: Flow,
  defId: number,
  mergeCommit: string | undefined,
): Promise<{ mainId: number; mainDeadline: number }> {
  const { ctx, checks, notes } = flow;
  const mainDeadline = Date.now() + MAIN_WAIT_MS;
  let cancelledSetup = 0;
  let setupBranchBuilt = false;
  const ciBuild = await waitFor(
    async () => {
      const { list } = await definitionBuilds(ctx, defId);
      setupBranchBuilt ||= list.some((b) => b.sourceBranch === SETUP_REF);
      // The image commit's CI build of the setup branch is not needed: the one agent goes to main.
      cancelledSetup += await cancelEach(ctx, toCancel(list, SETUP_REF));
      return mainBuildOf(list, mergeCommit);
    },
    { timeoutMs: MAIN_QUEUED_MS, intervalMs: 10_000 },
  );
  if (cancelledSetup > 0) {
    notes.push(`${cancelledSetup} CI build(s) of ${SETUP_BRANCH} cancelled (not needed)`);
  }
  checks.push(judgeCiQueued(ciBuild, setupBranchBuilt));
  if (ciBuild) return { mainId: ciBuild.id, mainDeadline };
  // Without CI the policy and the decoration still get checked: main is queued by hand.
  const manual = await queueBuild(ctx, defId, MAIN);
  await rec(ctx, 'build-main-queued', answerOf(manual.res));
  notes.push(
    `no CI build of main within ${MAIN_QUEUED_MS / 60000} min: the item queued build ${manual.id} by hand to go on`,
  );
  return { mainId: manual.id, mainDeadline };
}

/** 7b. The main build's end and the main analysis, within the shared 15 minutes; true when analysed. */
async function checkMainAnalysis(
  flow: Flow,
  main: { mainId: number; mainDeadline: number; mergeCommit: string | undefined },
  analysis: { projectId: string; before: string | null },
): Promise<boolean> {
  const { ctx, api, checks } = flow;
  const { mainId, mainDeadline, mergeCommit } = main;
  const mainBuild = await waitBuild(ctx, mainId, {
    timeoutMs: mainWaits(mainDeadline, Date.now()).buildMs,
  });
  await rec(ctx, 'build-main', answerOf(mainBuild.res));
  const ofMerge = sameId(mainBuild.build.sourceVersion, mergeCommit ?? '')
    ? ', of the merge commit'
    : '';
  checks.push(
    check(
      'a build of main by the pipeline completed',
      mainBuild.build.status === 'completed',
      `build ${mainId} ${mainBuild.build.status} ${mainBuild.build.result ?? ''}`.trim() + ofMerge,
    ),
  );
  // Within the same 15 minutes: the build's wait left the analysis its share.
  const analysed = await waitFor(
    async () => {
      const b = await qualorMain(api, analysis.projectId);
      return b?.lastAnalysisId && b.lastAnalysisId !== analysis.before ? b : undefined;
    },
    { timeoutMs: Math.max(0, mainDeadline - Date.now()), intervalMs: 10_000 },
  );
  let got = 'a new main analysis';
  if (!analysed) {
    const failed =
      mainBuild.build.status === 'completed' && mainBuild.build.result !== 'succeeded'
        ? `; ${await buildProblem(ctx, mainId)}`
        : '';
    got = `none within ${MAIN_WAIT_MS / 60000} min${failed}`;
  }
  checks.push(
    check('Qualor analysed main (a new main analysis of the project)', analysed !== undefined, got),
  );
  return analysed !== undefined;
}

/** 8. The Build validation policy: the run's item turns `on`, Azure DevOps has it on main. */
async function checkMainPolicy(flow: Flow, runId: string, repo: Repo, defId: number) {
  const { ctx, api, checks } = flow;
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
  const policy = judgeMainPolicy(policiesRes.json, { definitionId: defId, repositoryId: repo.id });
  checks.push(policy.check);
  return policy.policyId;
}

/** Who wrote Qualor's status on the probe pull request, as the item reports it. */
function statusAuthor(flow: Flow, status: { createdBy?: { id: string } | null }): string {
  if (!status.createdBy) return 'not listed';
  return sameId(status.createdBy.id, flow.spId) ? flow.who : 'another identity';
}

/** 9. A probe pull request: the policy's build, then Qualor's status on it. */
async function checkProbePr(
  flow: Flow,
  setupCtx: ProbeContext,
  repo: Repo,
  probe: { defId: number; policyId: number; projectKey: string },
): Promise<void> {
  const { ctx, checks, notes } = flow;
  const { defId, policyId } = probe;
  const base = await refHead(setupCtx, MAIN);
  if (!base) throw new Error('main has no head after the merge');
  const pushed = await pushFiles(
    setupCtx,
    `probe/27-${ctx.stamp}`,
    [{ path: `/src/probe-27-${ctx.stamp}.js`, content: probeSource(ctx.stamp) }],
    { base },
  );
  const created = await createPr(setupCtx, pushed.refName);
  const probeId = created.pr.pullRequestId;
  const statusDeadline = Date.now() + STATUS_WAIT_MS;
  const { pr: probePr } = await prWithMerge(setupCtx, probeId);
  const prBuildNow = async () => {
    const b = await definitionBuilds(ctx, defId);
    const e = await evaluations(setupCtx, probePr);
    const c = judgePrBuild(b.list, e.list.value, { prId: probeId, policyId });
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
  if (!built) return;
  ctx.log(
    `probe pull request ${probeId}: Qualor's status (up to ${STATUS_WAIT_MS / 60000} min from its creation)`,
  );
  const status = await waitFor(() => prStatus(setupCtx, repo, probeId, probe.projectKey), {
    timeoutMs: Math.max(0, statusDeadline - Date.now()),
    intervalMs: 15_000,
  });
  if (status) await rec(ctx, 'iteration-statuses-pr', answerOf(status.res));
  const got = status
    ? `${status.status.state ?? '?'} on iteration ${status.iterationId}; author ${statusAuthor(flow, status.status)}`
    : `none within ${STATUS_WAIT_MS / 60000} min; ${await prBuildState(ctx, prBuild.b.list, probeId)}`;
  checks.push(
    check(
      "Qualor's status (genre qualor, the project key as its name) on the probe pull request",
      status !== undefined,
      got,
    ),
  );
}

/** Steps 3 to 9 once the setup's pull request exists; the verdict is in the flow's checks. */
async function judgeMergedSetup(
  flow: Flow,
  repoOf: { setupCtx: ProbeContext; repo: Repo },
  setup: {
    runId: string;
    setupItem: SetupItem;
    project: SetupProject;
    pipeline: { queueId: number; defId: number; def: Definition };
    qualorUrl: string;
  },
): Promise<void> {
  const { ctx } = flow;
  const { setupCtx, repo } = repoOf;
  const { defId } = setup.pipeline;
  const state = await judgeSetupState(flow, setupCtx, repo, setup);
  if (!state) return;
  const imageCommit = await pinImageInPr(flow, setupCtx, repo, state);
  if (imageCommit === undefined) return;
  const { prId } = state;
  const merged = await completeSetupPr(flow, setupCtx, repo, {
    prId,
    imageCommit,
    projectId: setup.project.id,
  });
  if (!merged) return;
  const { mergeCommit, before } = merged;

  ctx.log(
    `setup pull request ${prId} merged: the main build and analysis (up to ${MAIN_WAIT_MS / 60000} min), then the policy`,
  );
  const { mainId, mainDeadline } = await queueMainBuild(flow, defId, mergeCommit);
  const analysed = await checkMainAnalysis(
    flow,
    { mainId, mainDeadline, mergeCommit },
    { projectId: setup.project.id, before },
  );
  if (!analysed) return;
  const policyId = await checkMainPolicy(flow, setup.runId, repo, defId);
  if (policyId === null) return;
  await checkProbePr(flow, setupCtx, repo, { defId, policyId, projectKey: setup.project.key });
}

export const item: ProbeItem = {
  id: 27,
  title:
    'a repository set up end to end on Azure DevOps: the setup pull request, the pipeline, the merge, the Build validation policy and a decorated pull request',
  async run(ctx) {
    const qualorUrl = needEnv('AZURE_PROBE_QUALOR_URL');
    const adminPassword = needEnv('AZURE_PROBE_QUALOR_ADMIN_PASSWORD');
    // The bench Qualor's connection of the target (Server: the collection, a PAT).
    const scmUrl = benchScmUrl(ctx.target);
    const checks: Check[] = [];
    const notes: string[] = [];
    // What a weaker identity's verdict needs, as far as the run got (--qualor-identity).
    const seen: WeakerSeen = {};
    const finish = () =>
      ctx.qualorAs ? weakerDone(ctx, checks, notes, seen) : done(ctx, checks, notes);

    // Qualor's identity's names (the service principal; Server: the PAT's owner) join the
    // redaction table before anything is recorded: the setup's pull request, pipeline and policy
    // are its.
    const spId = await qualorIdentityId(ctx);
    const who = qualorIdentityName(ctx.target, ctx.qualorAs?.identity);

    // ---- The bench Qualor: organisation `bench`, its Azure connection, CI setup available.
    const api = new QualorApi(qualorUrl);
    await api.login(adminPassword);
    const flow: Flow = { ctx, api, checks, notes, spId, who };
    const { orgId, connection } = await findBenchConnection(api, scmUrl);
    seen.bench = { api, orgId, connectionId: connection.id };
    if (!connection.ciSetup.available) {
      return result(
        ctx,
        'no',
        `CI setup is not available on the bench Azure connection (${connection.ciSetup.reason ?? 'no reason'}): run seed-qualor.mjs --setup`,
      );
    }

    const repoOf = await prepareRepository(ctx, notes, seen);
    const setup = await runSetup(flow, { orgId, connectionId: connection.id }, repoOf.repo);
    if (!setup) return finish();
    const pipeline = await readPipeline(flow, repoOf.repo, setup.setupItem);
    if (!pipeline) return finish();
    await judgeMergedSetup(flow, repoOf, { ...setup, pipeline, qualorUrl });
    return finish();
  },
};

type WeakerSeen = {
  repo?: Repo;
  bench?: { api: QualorApi; orgId: string; connectionId: string };
};

/**
 * A weaker identity's verdict: the steps as they went (the run's error, ciReason, queue and policy
 * state are Qualor's own texts), the identity's own calls of the setup's writes, and Qualor's record
 * of the connection.
 */
async function weakerDone(
  ctx: ProbeContext,
  checks: Check[],
  notes: string[],
  seen: WeakerSeen,
): Promise<ProbeResult> {
  const record: string[] = [];
  if (seen.repo) {
    record.push(
      ...(await setupRights(ctx, seen.repo, await defaultQueueId(ctx), PIPELINE_PATH.slice(1))),
    );
  }
  if (seen.bench) {
    record.push(
      ...(await qualorConnectionRecord(
        seen.bench.api,
        seen.bench.orgId,
        seen.bench.connectionId,
        seen.repo?.id,
      )),
    );
  }
  return recordedResult(
    ctx,
    `repository ${SETUP_REPOSITORY}; setup on the agent pool ${POOL}; the item pins the image to qualor/scanner:${BENCH_IMAGE_TAG} in the setup pull request`,
    checks,
    notes,
    record,
  );
}

/**
 * The checks the full flow makes: the run, 3 on the setup's pull request, 2 on the pipeline, the
 * queue, the pending policy, the merge, CI queuing main, the main build, the main analysis, the
 * policy `on`, the policy on main, the pull request build, Qualor's status.
 */
const ALL_CHECKS = 16;

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
