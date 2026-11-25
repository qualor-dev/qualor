import { compareSemver } from '@qualor/shared/fix';
import { z } from 'zod';
import type { AzureClient } from '../client.js';
import {
  authorizeDefinitions,
  BENCH_IMAGE_TAG,
  BENCH_SWAPS,
  example,
  failedSteps,
  swapped,
  timeline,
} from './18-ci.js';
import {
  BENCH_ORG,
  benchProject,
  benchScmUrl,
  benchUploadYaml,
  check,
  DOCKER_PATH,
  listThreads,
  needEnv,
  qualorIdentityId,
  rec,
  threadStatusName,
  type Check,
  type Thr,
} from './19-decoration.js';
import { QualorApi } from './21-review.js';
import { DESCRIPTION_LIMIT } from './22-fix-writes.js';
import {
  abandonPr,
  answerOf,
  buildLogs,
  createDefinition,
  defaultQueueId,
  deleteBranch,
  excerpt,
  gitPath,
  ok,
  queueBuild,
  refHead,
  repoInfo,
  result,
  shape,
  sleep,
  waitBuild,
  waitFor,
  type NewFile,
  type ProbeContext,
  type ProbeItem,
  type Repo,
} from './common.js';

/** Ruling 12: the second repository of the bench project, kept between runs. */
export const FIX_REPOSITORY = 'qualor-probe-fix';
export const FIX_DOCKER_PATH = '.azure-pipelines/qualor-fix-docker.yml';
const PACKAGE = 'lodash';
/** lodash 4.17.20: CVE-2021-23337 and the advisories published since (the fix's target is judged against them). */
export const INSTALLED = '4.17.20';
const LODASH_RESOLVED = 'https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz';
const LODASH_INTEGRITY =
  'sha512-PlhdFcillOINfeV7Ni6oF1TAEayyZBoZ8bcshTHqOYJYlrqzRK5hagpagky5o4HfCzzd1TRkXPMFq6cKk9rGmA==';
/** The last sentence of every fix pull request's description (server/src/fixes/body.ts, Azure: "PR"). */
export const CLOSING_SENTENCE =
  'Qualor keeps this PR current and closes it when the vulnerability is gone. Push to this branch to take it over.';
/** The comment of the closed thread Qualor leaves on a cancelled fix's pull request (`cancelComment('azure')`). */
export const CANCEL_TEXT = 'Qualor closed this PR: a member cancelled the fix in Qualor.';
const BUILD_WAIT_MS = 15 * 60_000;
/** The commit job, after the fix pipeline ended. */
const COMMIT_WAIT_MS = 5 * 60_000;
/** The main analysis, then its lodash vulnerability (the vulnerability database's re-check). */
const ANALYSIS_WAIT_MS = 10 * 60_000;
/** The close job: the pull request abandoned and the branch deleted. */
const CLOSE_WAIT_MS = 5 * 60_000;
const ZEROS = '0'.repeat(40);
const ACTIVE_STATES = ['requested', 'preparing', 'committing', 'open'];

// ---------------------------------------------------------------------------------------------
// Pure helpers (unit-tested)

/** The manifest of the fix repository: lodash pinned exactly, so the fix must change it. */
export function fixPackageJson(): string {
  return `${JSON.stringify(
    {
      name: FIX_REPOSITORY,
      version: '1.0.0',
      private: true,
      description: 'Qualor Azure DevOps probe, item 24: a dependency fix pull request',
      dependencies: { [PACKAGE]: INSTALLED },
    },
    null,
    2,
  )}\n`;
}

/** An npm v3 lockfile for exactly lodash 4.17.20, written as data (npm is never run here). */
export function fixPackageLock(): string {
  return `${JSON.stringify(
    {
      name: FIX_REPOSITORY,
      version: '1.0.0',
      lockfileVersion: 3,
      requires: true,
      packages: {
        '': {
          name: FIX_REPOSITORY,
          version: '1.0.0',
          dependencies: { [PACKAGE]: INSTALLED },
        },
        [`node_modules/${PACKAGE}`]: {
          version: INSTALLED,
          resolved: LODASH_RESOLVED,
          integrity: LODASH_INTEGRITY,
        },
      },
    },
    null,
    2,
  )}\n`;
}

/**
 * integrations/azure-devops/qualor-fix-docker.yml as the bench runs it: the bench pool and image,
 * no CI trigger and no schedule (the item queues each build).
 */
export function benchFixYaml(exampleText: string): string {
  return swapped(
    'qualor-fix-docker.yml',
    exampleText,
    [
      ...BENCH_SWAPS,
      [/^schedules:\n(?: {2}.*\n)+\n?/m, () => ''],
      [
        /^( {2}QUALOR_SCANNER_IMAGE: )qualor\/scanner:\S+$/m,
        (_m, key) => `${key}qualor/scanner:${BENCH_IMAGE_TAG}`,
      ],
    ],
    null,
  );
}

/** What main of the fix repository holds: the manifest, the lockfile and both pipelines. */
export function seedFiles(scanExample: string, fixExample: string): NewFile[] {
  return [
    { path: '/package.json', content: fixPackageJson() },
    { path: '/package-lock.json', content: fixPackageLock() },
    { path: `/${DOCKER_PATH}`, content: benchUploadYaml(scanExample) },
    { path: `/${FIX_DOCKER_PATH}`, content: benchFixYaml(fixExample) },
  ];
}

export type SeedChange = NewFile & { changeType: 'add' | 'edit' };

const lf = (text: string): string => text.replace(/\r\n/g, '\n');

/**
 * The changes that bring main to `wanted`: a missing file is added, one with other content is
 * edited back, one already there as wanted is skipped (none: main is left alone).
 */
export function seedChanges(
  wanted: readonly NewFile[],
  current: ReadonlyMap<string, string | null>,
): SeedChange[] {
  const out: SeedChange[] = [];
  for (const f of wanted) {
    const now = current.get(f.path) ?? null;
    if (now === null) out.push({ ...f, changeType: 'add' });
    else if (lf(now) !== lf(f.content)) out.push({ ...f, changeType: 'edit' });
  }
  return out;
}

const VERSION_CORE = /^[\^~=v]?(\d+\.\d+\.\d+)$/;

/** The version a spec pins (`4.17.21`, `^4.17.21`, `=4.17.21`), or the spec itself. */
export function versionCore(spec: string | null): string | null {
  if (spec === null) return null;
  return VERSION_CORE.exec(spec.trim())?.[1] ?? spec;
}

const parseJson = (text: string | null): unknown => {
  if (text === null) return null;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return null;
  }
};

const stringAt = (value: unknown, ...keys: string[]): string | null => {
  let at: unknown = value;
  for (const k of keys) {
    if (!at || typeof at !== 'object') return null;
    at = (at as Record<string, unknown>)[k];
  }
  return typeof at === 'string' ? at : null;
};

/** lodash as the manifest asks for it and as the lockfile's root and entry pin it; null where absent. */
export function lodashIn(
  packageJson: string | null,
  lockfile: string | null,
): { manifest: string | null; lockRoot: string | null; locked: string | null } {
  const manifest = parseJson(packageJson);
  const lock = parseJson(lockfile);
  return {
    manifest: stringAt(manifest, 'dependencies', PACKAGE),
    lockRoot: stringAt(lock, 'packages', '', 'dependencies', PACKAGE),
    locked: stringAt(lock, 'packages', `node_modules/${PACKAGE}`, 'version'),
  };
}

/** Whether both files carry `target`: the manifest's spec, the lockfile's root spec and its entry. */
export function judgeFiles(found: ReturnType<typeof lodashIn>, target: string): Check {
  const pass =
    versionCore(found.manifest) === target &&
    versionCore(found.lockRoot) === target &&
    found.locked === target;
  return check(
    `the fix branch has ${PACKAGE} ${target} in package.json and package-lock.json`,
    pass,
    `package.json ${found.manifest ?? 'absent'}; package-lock.json root ${found.lockRoot ?? 'absent'}, node_modules/${PACKAGE} ${found.locked ?? 'absent'}`,
  );
}

/** An advisory of lodash on main as the vulnerability list gives it. */
export type Advisory = { vulnerabilityId: string; fixedVersion: string | null };

/**
 * The version an advisory is fixed in for the installed lodash: the lowest of its fixed versions
 * (Trivy may list several, comma separated) above {@link INSTALLED}; null when it has none.
 */
export function fixedFor(advisory: Advisory): string | null {
  const above = (advisory.fixedVersion ?? '')
    .split(/[,\s]+/)
    .filter((v) => v !== '' && (compareSemver(v, INSTALLED) ?? 0) > 0)
    .toSorted((a, b) => compareSemver(a, b) ?? 0);
  return above[0] ?? null;
}

/**
 * The fix's target against the advisories listed for lodash 4.17.20: at least the highest version
 * any of them is fixed in. Qualor takes the greatest fixed version the vulnerabilities of main need
 * (on the 2026-11-24 bench, CVE-2026-4800's 4.18.0).
 */
export function judgeTarget(target: string | null, advisories: readonly Advisory[]): Check {
  const fixed = advisories.flatMap((a) => {
    const v = fixedFor(a);
    return v === null ? [] : [{ id: a.vulnerabilityId, version: v }];
  });
  const highest = fixed.reduce<{ id: string; version: string } | null>(
    (best, f) => (best === null || (compareSemver(f.version, best.version) ?? 0) > 0 ? f : best),
    null,
  );
  const atLeast =
    target !== null && highest !== null ? compareSemver(target, highest.version) : null;
  const listed = fixed.map((f) => `${f.id} ${f.version}`).join(', ');
  return check(
    `the fix's target is at least the highest fixed version among the advisories listed for ${PACKAGE} ${INSTALLED}`,
    atLeast !== null && atLeast >= 0,
    highest === null
      ? `target ${target ?? 'none'}; no listed advisory has a fixed version above ${INSTALLED}`
      : `target ${target ?? 'none'}; highest fixed version ${highest.version} (${highest.id}) among ${listed}`,
  );
}

export const fixTitleOf = (target: string): string =>
  `Bump ${PACKAGE} from ${INSTALLED} to ${target}`;

/** Whether a description ends with the closing sentence (trailing white space and CRLF aside). */
export function endsWithClosing(description: string | null | undefined): boolean {
  return lf(description ?? '')
    .trimEnd()
    .endsWith(CLOSING_SENTENCE);
}

export const FixPrSchema = z
  .object({
    pullRequestId: z.number(),
    status: z.string(),
    title: z.string(),
    description: z.string().nullish(),
    sourceRefName: z.string(),
    targetRefName: z.string(),
    createdBy: z.object({ id: z.string() }).loose(),
  })
  .loose();
export type FixPr = z.infer<typeof FixPrSchema>;

const sameId = (a: string | undefined, b: string): boolean =>
  (a ?? '').toLowerCase() === b.toLowerCase();

/** The open pull request as the brief asks for it. */
export function judgeOpenPr(
  pr: FixPr,
  want: { branch: string; target: string; spId: string },
): Check[] {
  const description = pr.description ?? '';
  return [
    check(
      'an active pull request from the fix branch into main',
      pr.status === 'active' &&
        pr.sourceRefName === `refs/heads/${want.branch}` &&
        pr.targetRefName === 'refs/heads/main',
      `${pr.status}, ${pr.sourceRefName} into ${pr.targetRefName}`,
    ),
    check(`titled "${fixTitleOf(want.target)}"`, pr.title === fixTitleOf(want.target), pr.title),
    check(
      `a description of at most ${DESCRIPTION_LIMIT} characters that ends with the closing sentence`,
      description.length <= DESCRIPTION_LIMIT && endsWithClosing(description),
      `${description.length} characters; ${endsWithClosing(description) ? 'ends with' : 'does not end with'} the closing sentence`,
    ),
    check(
      'created by the service principal',
      sameId(pr.createdBy.id, want.spId),
      sameId(pr.createdBy.id, want.spId) ? "the service principal's id" : 'another identity',
    ),
  ];
}

/** Qualor's closed thread on a cancelled fix's pull request: on the PR as a whole, by the service principal. */
export function closedThread(threads: Thr[], spId: string): Thr | undefined {
  return threads.find((t) => {
    const first = t.comments[0];
    return (
      first !== undefined &&
      first.isDeleted !== true &&
      sameId(first.author.id, spId) &&
      lf(first.content ?? '').trim() === CANCEL_TEXT &&
      !t.threadContext?.filePath
    );
  });
}

/** The pull request, Qualor's closed thread and the branch after the cancel. */
export function judgeClosed(
  pr: FixPr,
  threads: Thr[],
  branchHead: string | undefined,
  spId: string,
): Check[] {
  const t = closedThread(threads, spId);
  return [
    check('the pull request is abandoned', pr.status === 'abandoned', pr.status),
    check(
      "Qualor's closed comment thread on the pull request",
      t !== undefined && threadStatusName(t.status) === 'closed',
      t
        ? `thread ${t.id}, ${threadStatusName(t.status)}`
        : `no thread of the service principal says "${CANCEL_TEXT}"`,
    ),
    check(
      'the fix branch is deleted',
      branchHead === undefined,
      branchHead === undefined ? 'gone' : 'still there',
    ),
  ];
}

/** What the clean-up knows of a fix: its row as last read. */
export type KnownFix = { id: string; state: string; branch: string; mrNumber: number | null };

/** The calls the clean-up makes: the bench Qualor's (reread, cancel), then Azure DevOps's. */
export type ClearOps = {
  reread: () => Promise<KnownFix | undefined>;
  cancel: (id: string) => Promise<void>;
  /** The ids of the active pull requests from `branch` into main. */
  activePrs: (branch: string) => Promise<number[]>;
  isActive: (prId: number) => Promise<boolean>;
  abandon: (prId: number) => Promise<void>;
  deleteBranch: (branch: string) => Promise<void>;
};

const why = (err: unknown): string => (err instanceof Error ? err.message : String(err));

/**
 * Whatever a fix left. Qualor first: the fix read again and cancelled when it is in flight, so
 * Qualor's own close path runs when it can. Then Azure DevOps, whatever Qualor answered: every
 * active pull request from the fix's branch abandoned (and its known pull request, when it is
 * still active), and the branch deleted, by the row last read or, when the read fails, `fix`.
 * Each step runs even when one before it failed; the failures are thrown together at the end.
 */
export async function clearFixWith(ops: ClearOps, fix: KnownFix): Promise<void> {
  const failures: string[] = [];
  let known = fix;
  try {
    known = (await ops.reread()) ?? fix;
    if (ACTIVE_STATES.includes(known.state)) await ops.cancel(known.id);
  } catch (err) {
    failures.push(`the bench Qualor: ${why(err)}`);
  }
  const ids = new Set<number>();
  try {
    for (const id of await ops.activePrs(known.branch)) ids.add(id);
  } catch (err) {
    failures.push(`the pull requests of ${known.branch}: ${why(err)}`);
  }
  if (known.mrNumber !== null && !ids.has(known.mrNumber)) {
    try {
      if (await ops.isActive(known.mrNumber)) ids.add(known.mrNumber);
    } catch (err) {
      failures.push(`pull request ${known.mrNumber}: ${why(err)}`);
    }
  }
  for (const id of ids) {
    try {
      await ops.abandon(id);
    } catch (err) {
      failures.push(`abandon pull request ${id}: ${why(err)}`);
    }
  }
  try {
    await ops.deleteBranch(known.branch);
  } catch (err) {
    failures.push(`delete ${known.branch}: ${why(err)}`);
  }
  if (failures.length > 0) throw new Error(failures.join('; '));
}

// ---------------------------------------------------------------------------------------------
// The fix repository (Azure DevOps)

const RepoAnswer = z
  .object({ id: z.string(), name: z.string(), defaultBranch: z.string().optional() })
  .loose();

const enc = encodeURIComponent;
const repoPath = (ctx: ProbeContext, repoId: string, rest: string): string =>
  `/${ctx.project}/_apis/git/repositories/${repoId}${rest}`;

/**
 * A kept repository of the bench project (the fix repository by default), created when missing
 * (the service principal is a Project Administrator).
 */
export async function ensureRepository(
  ctx: ProbeContext,
  notes: string[],
  name: string = FIX_REPOSITORY,
): Promise<z.infer<typeof RepoAnswer>> {
  const got = await ctx.bot.request('GET', `/${ctx.project}/_apis/git/repositories/${name}`);
  if (got.status === 200) return shape(RepoAnswer, got.json, `repository ${name}`);
  if (got.status !== 404) ok(got, `repository ${name}`);
  const probe = await repoInfo(ctx);
  const client: AzureClient = ctx.entra?.('secret') ?? ctx.bot;
  const res = ok(
    await client.request('POST', `/${ctx.project}/_apis/git/repositories`, {
      name,
      project: { id: probe.project.id },
    }),
    `create the repository ${name}`,
  );
  await rec(ctx, 'repository-create', answerOf(res));
  notes.push(`repository ${name} created (kept between runs)`);
  return shape(RepoAnswer, res.json, 'created repository');
}

/** The head of `refName` in a repository read by id (one without a default branch yet too). */
export async function headOf(
  ctx: ProbeContext,
  repoId: string,
  refName: string,
): Promise<string | undefined> {
  const res = ok(
    await ctx.bot.request(
      'GET',
      repoPath(ctx, repoId, `/refs?filter=${enc(refName.replace(/^refs\//, ''))}`),
    ),
    'refs',
  );
  return shape(
    z.object({ value: z.array(z.object({ name: z.string(), objectId: z.string() })) }),
    res.json,
    'refs',
  ).value.find((r) => r.name === refName)?.objectId;
}

/** A file's text at a commit (`$format=json`: a raw read of a JSON file would come back parsed); null when absent. */
export async function fileText(
  ctx: ProbeContext,
  repoId: string,
  filePath: string,
  commit: string,
): Promise<string | null> {
  const res = await ctx.bot.request(
    'GET',
    repoPath(
      ctx,
      repoId,
      `/items?path=${enc(filePath)}&versionDescriptor.version=${commit}` +
        '&versionDescriptor.versionType=commit&includeContent=true&$format=json',
    ),
  );
  if (res.status === 404) return null;
  return shape(
    z.object({ content: z.string() }).loose(),
    ok(res, `read ${filePath}`).json,
    filePath,
  ).content;
}

/** Main of the fix repository as {@link seedFiles} says, in one push when anything differs. */
async function seedMain(ctx: ProbeContext, repoId: string, notes: string[]): Promise<void> {
  const wanted = seedFiles(example('qualor-docker.yml'), example('qualor-fix-docker.yml'));
  const head = await headOf(ctx, repoId, 'refs/heads/main');
  const current = new Map<string, string | null>();
  for (const f of wanted)
    current.set(f.path, head ? await fileText(ctx, repoId, f.path, head) : null);
  const changes = seedChanges(wanted, current);
  if (changes.length === 0) {
    notes.push(`main of ${FIX_REPOSITORY} already as wanted`);
    return;
  }
  const res = ok(
    await ctx.bot.request('POST', repoPath(ctx, repoId, '/pushes'), {
      refUpdates: [{ name: 'refs/heads/main', oldObjectId: head ?? ZEROS }],
      commits: [
        {
          comment: `Qualor probe item 24: the vulnerable ${PACKAGE} and the bench pipelines`,
          // A first commit of an empty repository has no parents.
          ...(head ? { parents: [head] } : {}),
          changes: changes.map((c) => ({
            changeType: c.changeType,
            item: { path: c.path },
            newContent: { content: c.content, contentType: 'rawtext' },
          })),
        },
      ],
    }),
    'seed main of the fix repository',
  );
  await rec(ctx, 'push-seed', answerOf(res));
  notes.push(
    `main of ${FIX_REPOSITORY} seeded: ${changes.map((c) => `${c.changeType} ${c.path}`).join(', ')}`,
  );
}

const PrListSchema = z.object({ value: z.array(FixPrSchema) });

async function readPr(ctx: ProbeContext, repo: Repo, id: number) {
  const res = ok(await ctx.bot.request('GET', gitPath(ctx, repo, `/pullrequests/${id}`)), 'pr');
  return { res, pr: shape(FixPrSchema, res.json, 'pull request') };
}

/** The active pull requests from `branch` into main. */
async function activePrsFrom(ctx: ProbeContext, repo: Repo, branch: string): Promise<FixPr[]> {
  const res = ok(
    await ctx.bot.request(
      'GET',
      gitPath(
        ctx,
        repo,
        `/pullrequests?searchCriteria.sourceRefName=${enc(`refs/heads/${branch}`)}` +
          `&searchCriteria.targetRefName=${enc('refs/heads/main')}&searchCriteria.status=active`,
      ),
    ),
    'pull requests from the fix branch',
  );
  return shape(PrListSchema, res.json, 'pull requests').value;
}

// ---------------------------------------------------------------------------------------------
// The bench Qualor

const FixItem = z
  .object({
    id: z.string(),
    state: z.string(),
    packageName: z.string(),
    branch: z.string(),
    installedVersion: z.string().nullable(),
    targetVersion: z.string().nullable(),
    mrNumber: z.number().nullable(),
    mrUrl: z.string().nullable(),
    failure: z.object({ code: z.string(), message: z.string() }).nullable(),
  })
  .loose();
type Fix = z.infer<typeof FixItem>;

const BranchItem = z
  .object({
    id: z.string(),
    kind: z.string(),
    name: z.string(),
    isMain: z.boolean(),
    lastAnalysisId: z.string().nullable(),
  })
  .loose();

const VulnerabilityItem = z
  .object({
    vulnerabilityId: z.string(),
    packageName: z.string(),
    ecosystem: z.string(),
    fixedVersion: z.string().nullable(),
    fixable: z.boolean(),
  })
  .loose();

export const codeOf = (json: unknown): string =>
  json && typeof json === 'object' && typeof (json as { code?: unknown }).code === 'string'
    ? (json as { code: string }).code
    : 'no code';

async function fixById(api: QualorApi, projectId: string, id: string): Promise<Fix | undefined> {
  return (await api.all(`/api/v0/projects/${projectId}/fixes`, FixItem)).find((f) => f.id === id);
}

/** DELETE /fixes/:id, again while the server writes the branch (409 FIX_BUSY), for a minute at most. */
async function cancelFix(api: QualorApi, id: string): Promise<void> {
  for (let i = 0; i < 12; i++) {
    const res = await api.send('DELETE', `/api/v0/fixes/${id}`);
    if (res.status === 204) return;
    if (res.status !== 409 || codeOf(res.json) !== 'FIX_BUSY') {
      throw new Error(`cancel the fix: HTTP ${res.status} ${codeOf(res.json)}`);
    }
    await sleep(5000);
  }
  throw new Error('cancel the fix: still FIX_BUSY after a minute');
}

/** {@link clearFixWith} on the bench Qualor and the fix repository. */
function clearFix(
  api: QualorApi,
  projectId: string,
  fixCtx: ProbeContext,
  repo: Repo,
  fix: Fix,
): Promise<void> {
  return clearFixWith(
    {
      reread: () => fixById(api, projectId, fix.id),
      cancel: (id) => cancelFix(api, id),
      activePrs: async (branch) =>
        (await activePrsFrom(fixCtx, repo, branch)).map((pr) => pr.pullRequestId),
      isActive: async (id) => {
        const res = await fixCtx.bot.request('GET', gitPath(fixCtx, repo, `/pullrequests/${id}`));
        return res.status === 200 && (res.json as { status?: unknown } | null)?.status === 'active';
      },
      abandon: (id) => abandonPr(fixCtx, id),
      deleteBranch: (branch) => deleteBranch(fixCtx, `refs/heads/${branch}`),
    },
    fix,
  );
}

/** The main branch of the Qualor project; undefined before its first analysis. */
export async function qualorMain(api: QualorApi, projectId: string) {
  return (await api.all(`/api/v0/projects/${projectId}/branches?kind=branch`, BranchItem)).find(
    (b) => b.isMain,
  );
}

async function vulndbStatus(api: QualorApi): Promise<string> {
  const res = await api.send('GET', '/api/v0/system/vulnerability-db');
  const s = res.json as { status?: unknown; lastError?: { code?: unknown } | null } | null;
  return `vulnerability database ${String(s?.status ?? `HTTP ${res.status}`)}${s?.lastError?.code ? ` (last error ${String(s.lastError.code)})` : ''}`;
}

/** Why a build did not succeed: its failed steps and their log tails (the detail only, redacted). */
export async function buildProblem(ctx: ProbeContext, buildId: number): Promise<string> {
  return failedSteps(await timeline(ctx, buildId), await buildLogs(ctx, buildId));
}

// ---------------------------------------------------------------------------------------------

export const item: ProbeItem = {
  id: 24,
  title:
    'a dependency fix pull request on Azure DevOps: Qualor opens it from the fix pipeline, and a cancel closes it',
  async run(ctx) {
    // The bench Qualor's fix project and connection of the target (Server: bench-server-fix).
    const bench = benchProject(ctx.target, 'fix');
    const qualorUrl = needEnv('AZURE_PROBE_QUALOR_URL');
    const fixToken = needEnv(bench.tokenEnv);
    const adminPassword = needEnv('AZURE_PROBE_QUALOR_ADMIN_PASSWORD');
    const scmUrl = benchScmUrl(ctx.target);
    const projectKey = bench.key;
    const checks: Check[] = [];
    const notes: string[] = [];
    const finish = () => done(ctx, checks, notes);

    // Qualor's identity's names (the service principal; Server: the PAT's owner) join the
    // redaction table before anything is recorded.
    const spId = await qualorIdentityId(ctx);

    // ---- The fix repository and its main (never the probe repository's main).
    const created = await ensureRepository(ctx, notes);
    await seedMain(ctx, created.id, notes);
    const fixCtx: ProbeContext = { ...ctx, repo: FIX_REPOSITORY };
    const repo = await repoInfo(fixCtx);

    // ---- The bench Qualor: project bench-fix mapped to the repository, fixes usable.
    const api = new QualorApi(qualorUrl);
    await api.login(adminPassword);
    const org = (
      await api.items(
        '/api/v0/organizations',
        z.object({ id: z.string(), key: z.string() }).loose(),
      )
    ).find((o) => o.key === BENCH_ORG);
    if (!org) throw new Error('the bench Qualor has no organisation `bench` (run seed-qualor.mjs)');
    const connection = (
      await api.items(
        `/api/v0/scm-connections?organizationId=${org.id}`,
        z.object({ id: z.string(), provider: z.string(), baseUrl: z.string() }).loose(),
      )
    ).find((c) => c.provider === 'azure' && c.baseUrl.replace(/\/+$/, '') === scmUrl);
    if (!connection)
      throw new Error('the bench Qualor has no Azure DevOps connection (run seed-qualor.mjs)');
    const project = (
      await api.items(
        `/api/v0/projects?organizationId=${org.id}`,
        z
          .object({
            id: z.string(),
            key: z.string(),
            scmConnectionId: z.string().nullable(),
            scmProjectRef: z.string().nullable(),
          })
          .loose(),
      )
    ).find((p) => p.key === projectKey);
    if (!project) {
      throw new Error(
        `the bench Qualor has no project ${projectKey} (run seed-qualor.mjs --fixes)`,
      );
    }
    const ref = repo.id.toLowerCase();
    if (project.scmConnectionId !== connection.id || project.scmProjectRef?.toLowerCase() !== ref) {
      // The seed runs before this item made the repository on the first run: the item maps it then.
      await api.call('PATCH', `/api/v0/projects/${project.id}`, {
        scmConnectionId: connection.id,
        scmProjectRef: ref,
      });
      notes.push(`project ${projectKey} mapped to ${FIX_REPOSITORY} by the item`);
    }
    const settings = shape(
      z
        .object({
          settings: z.object({ enabled: z.boolean() }).loose(),
          preconditions: z
            .object({
              scmBound: z.boolean(),
              fixMrsAllowed: z.boolean(),
              monitoringOn: z.boolean(),
            })
            .loose(),
        })
        .loose(),
      (await api.call('GET', `/api/v0/projects/${project.id}/fixes/settings`)).json,
      'fix settings',
    );
    const missing = [
      ...(settings.settings.enabled ? [] : ['fixes are off for the project']),
      ...(settings.preconditions.scmBound ? [] : ['the project is not mapped']),
      ...(settings.preconditions.fixMrsAllowed ? [] : ["the connection's fixMrsAllowed is off"]),
      ...(settings.preconditions.monitoringOn ? [] : ['vulnerability monitoring is off']),
    ];
    if (missing.length > 0) {
      return result(
        ctx,
        'no',
        `fixes are not usable on ${projectKey}: ${missing.join('; ')} (run seed-qualor.mjs --fixes)`,
      );
    }

    // ---- What an earlier run left: a lodash fix in flight is cancelled and its PR and branch go.
    for (const old of (await api.all(`/api/v0/projects/${project.id}/fixes`, FixItem)).filter(
      (f) => f.packageName === PACKAGE && ACTIVE_STATES.includes(f.state),
    )) {
      await clearFix(api, project.id, fixCtx, repo, old);
      notes.push(`an earlier run's ${PACKAGE} fix (${old.state}) cancelled and cleared first`);
    }

    // ---- Definitions: the scan (uploads) and the fix pipeline, on the bench queue.
    const queueId = await defaultQueueId(ctx);
    const variables = {
      QUALOR_URL: { value: qualorUrl, allowOverride: false },
      QUALOR_PROJECT_KEY: { value: projectKey, allowOverride: false },
      QUALOR_TOKEN: { value: fixToken, isSecret: true, allowOverride: false },
    };
    const definition = (name: string, yamlFilename: string) =>
      createDefinition(ctx, {
        name: `Qualor probe item 24 ${name} ${ctx.stamp}`,
        path: '\\',
        type: 'build',
        queue: { id: queueId },
        process: { type: 2, yamlFilename },
        repository: {
          id: repo.id,
          name: repo.name,
          type: 'TfsGit',
          defaultBranch: 'refs/heads/main',
        },
        variables,
      });
    const scanDef = await definition('scan', DOCKER_PATH);
    const fixDef = await definition('fix', FIX_DOCKER_PATH);
    notes.push(await authorizeDefinitions(ctx, queueId, [scanDef.id, fixDef.id]));

    // ---- 1. Scan main; wait for the analysis and its fixable lodash vulnerability.
    const before = (await qualorMain(api, project.id))?.lastAnalysisId ?? null;
    ctx.log(`scan of main, then the fix pipeline (builds up to ${BUILD_WAIT_MS / 60000} min each)`);
    const scan = await queueBuild(ctx, scanDef.id, 'refs/heads/main');
    const scanned = await waitBuild(ctx, scan.id, { timeoutMs: BUILD_WAIT_MS });
    await rec(ctx, 'build-scan', answerOf(scanned.res));
    notes.push(`scan build ${scan.id}: ${scanned.build.status} ${scanned.build.result ?? '?'}`);
    if (scanned.build.status !== 'completed') {
      checks.push(
        check(
          'the scan of main completed',
          false,
          `${scanned.build.status} after ${BUILD_WAIT_MS / 60000} min`,
        ),
      );
      return finish();
    }
    const main = await waitFor(
      async () => {
        const b = await qualorMain(api, project.id);
        return b?.lastAnalysisId && b.lastAnalysisId !== before ? b : undefined;
      },
      { timeoutMs: ANALYSIS_WAIT_MS, intervalMs: 10_000 },
    );
    checks.push(
      check(
        'Qualor analysed the scan of main',
        main !== undefined,
        main
          ? 'a new main analysis'
          : `none within ${ANALYSIS_WAIT_MS / 60000} min${scanned.build.result === 'succeeded' ? '' : `; ${await buildProblem(ctx, scan.id)}`}`,
      ),
    );
    if (!main) return finish();
    const vulnerable = await waitFor(
      async () => {
        const res = await api.call(
          'GET',
          `/api/v0/projects/${project.id}/vulnerabilities?target=branch:${main.id}&pageSize=100`,
        );
        const items = shape(
          z.object({ items: z.array(VulnerabilityItem) }).loose(),
          res.json,
          'vulnerabilities',
        ).items;
        const mine = items.filter((v) => v.packageName === PACKAGE && v.ecosystem === 'npm');
        return mine.some((v) => v.fixable) ? mine : undefined;
      },
      { timeoutMs: ANALYSIS_WAIT_MS, intervalMs: 15_000 },
    );
    checks.push(
      check(
        `${PACKAGE} ${INSTALLED} is a fixable vulnerability of main`,
        vulnerable !== undefined,
        vulnerable
          ? vulnerable
              .map((v) => `${v.vulnerabilityId} fixed in ${v.fixedVersion ?? '?'}`)
              .join(', ')
          : `not within ${ANALYSIS_WAIT_MS / 60000} min; ${await vulndbStatus(api)}`,
      ),
    );
    if (!vulnerable) return finish();

    // ---- 2. Request the fix.
    const requested = await api.send('POST', `/api/v0/projects/${project.id}/fixes`, {
      ecosystem: 'npm',
      packageName: PACKAGE,
    });
    if (requested.status !== 202) {
      checks.push(
        check(
          'the fix request is accepted (202)',
          false,
          `HTTP ${requested.status} ${codeOf(requested.json)}`,
        ),
      );
      return finish();
    }
    const fix = shape(FixItem, requested.json, 'requested fix');
    // The clean-up uses the row last read: once the fix is open it knows the pull request's id too.
    let latest: Fix = fix;
    ctx.cleanup.add(`cancel the ${PACKAGE} fix, abandon its pull request, delete its branch`, () =>
      clearFix(api, project.id, fixCtx, repo, latest),
    );

    // ---- 3. The fix pipeline, then the commit job: the fix becomes open.
    const fixBuild = await queueBuild(ctx, fixDef.id, 'refs/heads/main');
    const built = await waitBuild(ctx, fixBuild.id, { timeoutMs: BUILD_WAIT_MS });
    await rec(ctx, 'build-fix', answerOf(built.res));
    notes.push(`fix build ${fixBuild.id}: ${built.build.status} ${built.build.result ?? '?'}`);
    if (built.build.status === 'completed' && built.build.result !== 'succeeded') {
      notes.push(`fix build: ${await buildProblem(ctx, fixBuild.id)}`);
    }
    const settled = await waitFor(
      async () => {
        const f = await fixById(api, project.id, fix.id);
        return f && !['requested', 'preparing', 'committing'].includes(f.state) ? f : undefined;
      },
      { timeoutMs: COMMIT_WAIT_MS, intervalMs: 10_000 },
    );
    const opened = settled ?? (await fixById(api, project.id, fix.id));
    if (opened) latest = opened;
    checks.push(
      check(
        'the fix is open (the fix pipeline uploaded, the commit job opened the pull request)',
        opened?.state === 'open' && opened.mrNumber !== null,
        opened
          ? `${opened.state}${opened.failure ? `: ${opened.failure.code} ${excerpt(opened.failure.message, ctx.redaction, 300)}` : ''}`
          : 'the fix is gone',
      ),
    );
    if (opened?.state !== 'open' || opened.mrNumber === null) return finish();
    const prId = opened.mrNumber;

    // ---- 4. Azure DevOps: the branch, both files, the pull request.
    const target = opened.targetVersion;
    checks.push(judgeTarget(target, vulnerable));
    const branchRef = `refs/heads/${opened.branch}`;
    const head = await refHead(fixCtx, branchRef);
    checks.push(
      check(
        'the fix branch qualor/fix/js/… exists',
        opened.branch.startsWith('qualor/fix/js/') && head !== undefined,
        `${opened.branch} ${head ? 'exists' : 'missing'}`,
      ),
    );
    if (head && target) {
      checks.push(
        judgeFiles(
          lodashIn(
            await fileText(fixCtx, repo.id, '/package.json', head),
            await fileText(fixCtx, repo.id, '/package-lock.json', head),
          ),
          target,
        ),
      );
    }
    const open = await readPr(fixCtx, repo, prId);
    await rec(ctx, 'pr-open', answerOf(open.res));
    checks.push(...judgeOpenPr(open.pr, { branch: opened.branch, target: target ?? 'none', spId }));
    notes.push(
      `installed version ${opened.installedVersion ?? '?'}; the fix's mrUrl ${opened.mrUrl === `${repo.webUrl}/pullrequest/${prId}` ? "is the pull request's web URL" : 'differs from the pull request web URL'}`,
    );

    // ---- 5. Cancel; 6. the pull request abandoned with Qualor's closed thread, the branch deleted.
    await cancelFix(api, fix.id);
    const cancelled = await waitFor(
      async () => {
        const f = await fixById(api, project.id, fix.id);
        return f?.state === 'cancelled' ? f : undefined;
      },
      { timeoutMs: 60_000, intervalMs: 5000 },
    );
    checks.push(
      check(
        'the fix is cancelled',
        cancelled !== undefined,
        cancelled ? 'cancelled' : 'not within a minute',
      ),
    );
    const closed = await waitFor(
      async () => {
        const got = await readPr(fixCtx, repo, prId);
        const threads = await listThreads(fixCtx, repo, prId);
        const gone = (await refHead(fixCtx, branchRef)) === undefined;
        return got.pr.status === 'abandoned' && gone && closedThread(threads.threads, spId)
          ? { got, threads }
          : undefined;
      },
      { timeoutMs: CLOSE_WAIT_MS, intervalMs: 10_000 },
    );
    const after = closed ?? {
      got: await readPr(fixCtx, repo, prId),
      threads: await listThreads(fixCtx, repo, prId),
    };
    await rec(ctx, 'pr-closed', answerOf(after.got.res));
    await rec(ctx, 'threads-closed', answerOf(after.threads.res));
    checks.push(
      ...judgeClosed(after.got.pr, after.threads.threads, await refHead(fixCtx, branchRef), spId),
    );
    return finish();
  },
};

/** The checks the full flow makes: analysis, vulnerability, open, target, branch, files, 4 on the PR, cancel, 3 after it. */
const ALL_CHECKS = 14;

function done(ctx: ProbeContext, checks: Check[], notes: string[]) {
  for (const c of checks) ctx.log(`${c.pass ? 'yes' : 'NO '} ${c.what}: ${c.got}`);
  const pass = checks.length >= ALL_CHECKS && checks.every((c) => c.pass);
  const detail = [
    `repository ${FIX_REPOSITORY}; image qualor/scanner:${BENCH_IMAGE_TAG}`,
    ...checks.map((c) => `${c.pass ? 'yes' : 'NO'} - ${c.what}: ${c.got}`),
    ...notes.map((n) => `note: ${n}`),
  ].join('\n\n');
  return Promise.resolve(result(ctx, pass ? 'yes' : 'no', detail));
}
