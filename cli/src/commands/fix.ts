import { existsSync } from 'node:fs';
import os from 'node:os';
import { setTimeout as sleep } from 'node:timers/promises';
import {
  FIX_LIMITS,
  fixResultBodySchema,
  fixUploadSchema,
  scrubToolOutput,
  utf8Head,
  type FixClaimItem,
  type FixClaimReason,
  type FixFamily,
  type FixResultBody,
} from '@qualor/shared/fix';
import type { FixFlags } from '../args';
import type { CiInfo } from '../config/ci';
import { loadSettings, requireServer, type ConfigFlags } from '../config/settings';
import { CliError, EXIT, type ExitCode } from '../errors';
import type { FixAdapter, FixWorkspace } from '../fix/adapter';
import { fixJobSecrets, fixToolEnv } from '../fix/env';
import { goAdapter } from '../fix/go';
import { jsAdapter } from '../fix/js';
import { muslProblem } from '../fix/musl';
import { prepareFix, type FixOutcome } from '../fix/run';
import { createToolRunner, type ToolRunner } from '../fix/runner';
import { resolveTool } from '../fix/shim';
import { familyFiles, familyTools, missingTools, servedFamilies } from '../fix/tools';
import { openScratch } from '../fix/workspace';
import { createGit, gitText, type Git } from '../git/git';
import type { CliIO } from '../io';
import type { Logger } from '../log';
import { claimFix, sendFixResult, type FixSendAnswer } from '../server/fix-client';
import { serverEndpoint } from '../server/endpoint';
import { clean, type ServerEndpoint } from '../server/http';

/**
 * The package managers of each family (Tasks 13–16 register theirs here). A family without an
 * adapter is never claimed.
 */
const ADAPTERS: Partial<Record<FixFamily, FixAdapter>> = { js: jsAdapter, go: goAdapter };

export interface FixDeps {
  adapters?: Partial<Record<FixFamily, FixAdapter>>;
  /**
   * Where a tool is; null when it is not. By default the runner's own lookup (`resolveTool` on the
   * tool environment's `PATH`, npm's node shims included, ruling T12a).
   */
  resolve?: (tool: string) => string | null;
  /** One fix's time (10 minutes, §6.5). */
  perFixMs?: number;
  now?: () => number;
  tempRoot?: string;
  wait?: (ms: number) => Promise<unknown>;
}

/** R4, ruling T12g: no claim with less of the job's `--timeout` left than this. */
const MIN_CLAIM_MS = 60_000;
/** How long a fix that ran out of time may take to stop before its scratch copy goes. */
const STOP_GRACE_MS = 5000;
/** A timer may fire this much before its time; a deadline this close counts as reached. */
const DEADLINE_SLACK_MS = 100;

/** R4: why a claim handed out nothing on a project the job cannot serve now. */
const REASON_TEXT: Readonly<Record<FixClaimReason, string>> = {
  disabled: 'Fix merge requests are off for this project',
  not_allowed: "The project's SCM connection does not allow fix merge requests",
  not_bound: 'The project is not bound to a repository (an SCM connection)',
  monitoring_off: 'Vulnerability monitoring is off for this project',
};

/** One run of `qualor fix`. */
interface FixJob {
  flags: FixFlags;
  log: Logger;
  endpoint: ServerEndpoint;
  projectKey: string;
  git: Git;
  checkout: { branch: string; revision: string };
  tracked: readonly string[];
  families: Map<FixFamily, string[]>;
  served: FixFamily[];
  adapters: Partial<Record<FixFamily, FixAdapter>>;
  resolve: (tool: string) => string | null;
  /** Why `resolve` finds no tool: not installed, or a `.cmd` it will not start (ruling T12a). */
  whyMissing: (tool: string) => string;
  runner: ToolRunner;
  /** The environment `runner` starts every tool with (`fixToolEnv`, B9). */
  toolEnv: Readonly<Record<string, string>>;
  /** What messages and log lines are scrubbed of (B9, ruling T12b). */
  secrets: readonly string[];
  /** What no uploaded file may gain (B9, I1). */
  credentials: readonly string[];
  /** When the job's `--timeout` ends (ms, on `now`'s clock). */
  deadline: number;
  perFixMs: number;
  now: () => number;
  tempRoot: string;
  wait: (ms: number) => Promise<unknown>;
}

/** B8, R20: the compiled binary refuses a musl system (exit 2). */
function refuseMusl(): void {
  const problem = muslProblem({
    platform: process.platform,
    compiled: process.versions['bun'] !== undefined,
    exists: existsSync,
  });
  if (problem !== null) throw new CliError(EXIT.USAGE, problem);
}

/** The server, its token and the project, as `qualor upload-sbom` reads them. */
function serverOf(
  flags: FixFlags,
  io: CliIO,
  log: Logger,
): { endpoint: ServerEndpoint; projectKey: string; ci: CiInfo } {
  const configFlags: ConfigFlags = {
    ...(flags.config !== undefined && { config: flags.config }),
    ...(flags.projectKey !== undefined && { projectKey: flags.projectKey }),
    ...(flags.tokenFile !== undefined && { tokenFile: flags.tokenFile }),
    ...(flags.serverUrl !== undefined && { serverUrl: flags.serverUrl }),
    ...(flags.caFile !== undefined && { caFile: flags.caFile }),
  };
  const settings = loadSettings({ cwd: io.cwd, env: io.env, flags: configFlags, log });
  const projectKey = settings.config.project.key;
  if (projectKey === undefined || projectKey === '') {
    throw new CliError(
      EXIT.USAGE,
      'a project key is required: pass --project-key, set QUALOR_PROJECT_KEY or project.key in qualor.yml',
    );
  }
  requireServer(settings);
  const endpoint = serverEndpoint(settings, { upload: true, log, env: io.env });
  if (endpoint === null) throw new Error('internal error: requireServer passed without a server');
  return { endpoint, projectKey, ci: settings.ci };
}

/** §6.9, B9: every log line of the job, scrubbed of the job's secrets and the B9 shapes. */
function scrubbedLogger(log: Logger, secrets: readonly string[]): Logger {
  const scrub = (message: string) => scrubToolOutput(message, secrets);
  return {
    level: log.level,
    error: (m) => log.error(scrub(m)),
    warn: (m) => log.warn(scrub(m)),
    info: (m) => log.info(scrub(m)),
    debug: (m) => log.debug(scrub(m)),
  };
}

/**
 * §6.5: the checked-out branch and commit. In CI the branch is the job's and HEAD must be the
 * job's commit; elsewhere the branch HEAD points at. A detached HEAD outside CI, a tag pipeline or
 * another commit than the job's exits 2 before any request.
 */
async function checkoutOf(git: Git, ci: CiInfo): Promise<{ branch: string; revision: string }> {
  const revision = (await gitText(git, ['rev-parse', '--verify', 'HEAD^{commit}'])).trim();
  if (ci.provider === 'none') {
    const branch = (await git(['symbolic-ref', '--quiet', '--short', 'HEAD'])).stdout.trim();
    if (branch === '') {
      throw new CliError(
        EXIT.USAGE,
        'qualor fix needs a checkout of the main branch; HEAD is detached',
      );
    }
    return { branch, revision };
  }
  if (ci.revision !== null && ci.revision !== revision) {
    throw new CliError(
      EXIT.USAGE,
      `HEAD is ${revision}, not the CI job's commit ${clean(ci.revision)}; qualor fix runs on the job's own checkout of the main branch`,
    );
  }
  if (ci.branch === null) {
    throw new CliError(
      EXIT.USAGE,
      'qualor fix runs in a pipeline of the main branch, not of a tag',
    );
  }
  return { branch: ci.branch, revision };
}

/** HEAD's files, repository-relative (`ls-tree`, so the checkout's index plays no part). */
async function trackedFiles(git: Git): Promise<string[]> {
  const out = await gitText(git, ['ls-tree', '-r', '-z', '--name-only', '--full-tree', 'HEAD']);
  return out.split('\0').filter((p) => p !== '');
}

/**
 * Ruling F6: one info line naming the families the repository has that this job cannot serve,
 * with the tools it misses; families without an adapter in this CLI are named at debug level.
 */
function reportUnserved(job: FixJob): void {
  const lacking: string[] = [];
  for (const [family, paths] of job.families) {
    // A family with manifests only has no lockfile to regenerate, so nothing to fix.
    if (job.served.includes(family) || familyTools(paths).length === 0) continue;
    const missing = missingTools(paths, job.resolve);
    if (missing.length === 0) job.log.debug(`this qualor has no ${family} fixes yet`);
    else lacking.push(`${family} (${missing.map(job.whyMissing).join('; ')})`);
  }
  if (lacking.length > 0) {
    job.log.info(
      `not claiming fixes of ${lacking.join('; ')}: install the package managers in the fix job's image`,
    );
  }
}

/**
 * Where the job finds a tool and why it does not: the runner's own lookup (ruling T12a), so the
 * families claimed are those the runner can start; or a test's `resolve`.
 */
function toolLookup(
  root: string,
  env: Record<string, string>,
  resolve: FixDeps['resolve'],
): Pick<FixJob, 'resolve' | 'whyMissing'> {
  const notInstalled = (tool: string) =>
    `${tool} is not installed (on PATH, outside the repository)`;
  if (resolve !== undefined) return { resolve, whyMissing: notInstalled };
  const lookup = (tool: string) => resolveTool(tool, { root, env });
  return {
    resolve: (tool) => {
      const found = lookup(tool);
      return found === null || 'problem' in found ? null : found.command;
    },
    whyMissing: (tool) => {
      const found = lookup(tool);
      return found !== null && 'problem' in found ? found.problem : notInstalled(tool);
    },
  };
}

async function startJob(flags: FixFlags, io: CliIO, log: Logger, deps: FixDeps): Promise<FixJob> {
  const now = deps.now ?? Date.now;
  const started = now();
  const { endpoint, projectKey, ci } = serverOf(flags, io, log);
  const { scrub: secrets, credentials } = fixJobSecrets(io.env, endpoint.token);
  const scrubbed = scrubbedLogger(log, secrets);
  const git = createGit(io.cwd, io.env);
  const checkout = await checkoutOf(git, ci);
  const tracked = await trackedFiles(git);
  const toolEnv = fixToolEnv(io.env);
  const tools = toolLookup(io.cwd, toolEnv, deps.resolve);
  const adapters = deps.adapters ?? ADAPTERS;
  const families = familyFiles(tracked);
  return {
    flags,
    log: scrubbed,
    endpoint,
    projectKey,
    git,
    checkout,
    tracked,
    families,
    served: servedFamilies(families, tools.resolve).filter((f) => adapters[f] !== undefined),
    adapters,
    ...tools,
    runner: createToolRunner({ env: toolEnv, root: io.cwd, log: scrubbed, secrets }),
    toolEnv,
    secrets,
    credentials,
    deadline: started + flags.timeoutSeconds * 1000,
    perFixMs: deps.perFixMs ?? FIX_LIMITS.perFixMinutes * 60_000,
    now,
    tempRoot: deps.tempRoot ?? os.tmpdir(),
    wait: deps.wait ?? ((ms: number) => sleep(ms)),
  };
}

// ─── One fix ────────────────────────────────────────────────────────────────

const RELEASED = 'released';
type Outcome = FixOutcome | typeof RELEASED;

/** `work`, or 'timeout' once `ms` have passed (the work goes on; its result is then dropped). */
async function within<T>(work: Promise<T>, ms: number): Promise<T | 'timeout'> {
  let timer: NodeJS.Timeout | undefined;
  const expired = new Promise<'timeout'>((resolve) => {
    timer = setTimeout(() => resolve('timeout'), Math.max(0, ms));
  });
  try {
    return await Promise.race([work, expired]);
  } finally {
    clearTimeout(timer);
  }
}

/** The job's runner, each call bounded by the fix's deadline. */
function boundedRunner(job: FixJob, deadline: number): ToolRunner {
  return (tool, args, o) =>
    job.runner(tool, args, { ...o, timeoutMs: Math.min(o.timeoutMs, deadline - job.now()) });
}

const isTimeoutFailure = (outcome: FixOutcome): boolean =>
  'failure' in outcome && outcome.failure.code === 'timeout';

/**
 * The fix in its scratch copy, within its budget: `min(perFixMs, time left)`. Past a budget set by
 * the job's `--timeout` the fix is handed back (R4); past its own 10 minutes it fails `timeout`.
 */
async function preparedWithin(
  job: FixJob,
  item: FixClaimItem,
  adapter: FixAdapter,
  budget: number,
): Promise<Outcome> {
  const deadline = job.now() + budget;
  const scratch = await openScratch(job.git, job.tempRoot);
  try {
    const ws: FixWorkspace = {
      root: scratch.root,
      files: job.tracked,
      env: job.toolEnv,
      run: boundedRunner(job, deadline),
      deadline,
      log: job.log,
    };
    const work = prepareFix(item, adapter, ws, job.git, { credentials: job.credentials });
    const outcome = await within(work, budget);
    // Its tools stop at the deadline too; give them a moment before the scratch copy goes.
    if (outcome === 'timeout') await within(work, STOP_GRACE_MS);
    else if (!isTimeoutFailure(outcome)) return outcome;
    // The job's --timeout set this budget and has run out: the claim goes back (R4).
    if (budget < job.perFixMs && job.now() >= deadline - DEADLINE_SLACK_MS) return RELEASED;
    if (outcome !== 'timeout') return outcome;
    const seconds = Math.round(budget / 1000);
    return { failure: { code: 'timeout', message: `The fix took longer than ${seconds} s.` } };
  } finally {
    await scratch.close();
  }
}

/** What to send for a claimed fix: its outcome, a missing tool (B7), or the claim handed back. */
async function outcomeOf(job: FixJob, item: FixClaimItem): Promise<Outcome> {
  const adapter = job.adapters[item.family];
  if (adapter === undefined) {
    return {
      failure: { code: 'missing_tool', message: `This qualor cannot fix ${item.family} packages.` },
    };
  }
  const missing = missingTools(job.families.get(item.family) ?? [], job.resolve);
  if (missing.length > 0) {
    return {
      failure: { code: 'missing_tool', message: `${missing.map(job.whyMissing).join('; ')}.` },
    };
  }
  const budget = Math.min(job.perFixMs, job.deadline - job.now());
  if (budget <= 0) return RELEASED;
  return preparedWithin(job, item, adapter, budget);
}

/** The result body: the claim's generation and lease, the messages scrubbed again (§6.9, B9). */
function bodyOf(job: FixJob, item: FixClaimItem, outcome: Outcome): FixResultBody {
  const lease = { generation: item.generation, leaseToken: item.leaseToken };
  if (outcome === RELEASED) return { ...lease, released: true };
  if ('failure' in outcome) {
    const message = scrubToolOutput(outcome.failure.message, job.secrets);
    return { ...lease, failure: { code: outcome.failure.code, message } };
  }
  if ('noFix' in outcome) {
    const message = scrubToolOutput(outcome.noFix.message, job.secrets);
    return { ...lease, noFix: { reason: outcome.noFix.reason, message } };
  }
  return { ...lease, ...outcome };
}

/**
 * What the server made of an accepted result, with the state it answered: for files, the merge
 * request on its way (`committing`) or the state the fix ended in instead (ruling T9d).
 */
function acceptedLine(body: FixResultBody, state: string): string {
  if ('released' in body) return `handed back, the job's time is up (now ${state})`;
  if ('failure' in body) {
    return `failed, ${body.failure.code} (now ${state}): ${clean(body.failure.message)}`;
  }
  if ('noFix' in body)
    return `no fix, ${body.noFix.reason} (now ${state}): ${clean(body.noFix.message)}`;
  const sent = `${clean(body.installedVersion)} to ${clean(body.targetVersion)} sent`;
  return state === 'committing'
    ? `${sent}; the server opens the merge request`
    : `${sent}, but the fix is now ${state}`;
}

/** What happened to a fix, in one log line. */
function report(job: FixJob, item: FixClaimItem, body: FixResultBody, answer: FixSendAnswer): void {
  const name = `${clean(item.family)} ${clean(item.packageName)}`;
  if (typeof answer === 'object' && 'stopped' in answer) {
    job.log.info(`${name}: the project cannot take fixes now (${answer.stopped}); stopping`);
    return;
  }
  if (answer === 'lease_lost') {
    job.log.warn(`${name}: the server no longer holds this job's claim (FIX_LEASE_LOST); going on`);
    return;
  }
  if ('refused' in answer) {
    job.log.warn(`${name}: the server refused the upload (${answer.refused})`);
    return;
  }
  job.log.info(`${name}: ${acceptedLine(body, answer.accepted)}`);
}

/**
 * The body as the route reads it (`fixResultBodySchema`, strict): a body that would not parse is a
 * CLI bug, sent as `failure unplanned_change` naming the field instead of being refused as
 * `VALIDATION_FAILED` while the fix waits out its lease.
 */
function checkedBody(body: FixResultBody): FixResultBody {
  // The files form against its own schema, so the first issue names a field, not the union.
  const schema = 'files' in body ? fixUploadSchema : fixResultBodySchema;
  const parsed = schema.safeParse(body);
  if (parsed.success) return body;
  const issue = parsed.error.issues[0];
  const field =
    issue === undefined ? '' : ` (${issue.path.map(String).join('.')}: ${issue.message})`;
  return {
    generation: body.generation,
    leaseToken: body.leaseToken,
    failure: {
      code: 'unplanned_change',
      // Ruling T12h: the schema counts characters; the server keeps 2 KiB of UTF-8.
      message: utf8Head(
        `The fix's result does not match the result schema${field}.`,
        FIX_LIMITS.messageBytes,
      ),
    },
  };
}

/**
 * Sends a fix's result and logs what came of it. False when the run stops: the project can take no
 * fixes now (ruling T12f, 409 `SCM_NOT_BOUND` or `FIX_MRS_NOT_ALLOWED`, as the claim's reasons).
 */
async function send(job: FixJob, item: FixClaimItem, outcome: Outcome): Promise<boolean> {
  const body = checkedBody(bodyOf(job, item, outcome));
  const answer = await sendFixResult(job.endpoint, item.id, body, { wait: job.wait, log: job.log });
  report(job, item, body, answer);
  return !(typeof answer === 'object' && 'stopped' in answer);
}

/** One claimed fix, prepared and sent; one the job cannot even start on is handed back. */
async function runOne(job: FixJob, item: FixClaimItem): Promise<boolean> {
  job.log.info(`preparing the fix of ${clean(item.family)} ${clean(item.packageName)}`);
  let outcome: Outcome;
  try {
    outcome = await outcomeOf(job, item);
  } catch (err) {
    await send(job, item, RELEASED).catch(() => undefined);
    throw err;
  }
  return send(job, item, outcome);
}

// ─── The claim loop ─────────────────────────────────────────────────────────

const timeLeft = (job: FixJob): number => job.deadline - job.now();

/**
 * One claim (R4): its fixes, or null when the run ends: the time is up, the project's fixes cannot
 * run now (the reason, exit 0) or none is waiting.
 */
async function claimNext(job: FixJob, done: number): Promise<FixClaimItem[] | null> {
  if (timeLeft(job) < MIN_CLAIM_MS) {
    job.log.info("less than a minute of the job's --timeout is left; no further claim");
    return null;
  }
  const answer = await claimFix(job.endpoint, {
    projectKey: job.projectKey,
    families: job.served,
    branch: job.checkout.branch,
    revision: job.checkout.revision,
  });
  if (answer.reason !== null) {
    job.log.info(REASON_TEXT[answer.reason]);
    return null;
  }
  if (answer.items.length === 0) {
    job.log.info(done === 0 ? 'no fix is waiting' : 'no further fix is waiting');
    return null;
  }
  return answer.items;
}

/**
 * R4: one fix per claim, up to `--max` in all, while time remains. A fix the server hands out
 * beyond `--max` is handed back at once.
 */
async function claimLoop(job: FixJob): Promise<void> {
  let done = 0;
  while (done < job.flags.max) {
    const items = await claimNext(job, done);
    if (items === null) return;
    for (const item of items) {
      const goOn = done < job.flags.max ? await runOne(job, item) : await send(job, item, RELEASED);
      done += 1;
      if (!goOn) return;
    }
  }
}

/**
 * `qualor fix` (0.16 fix MRs §6.5, R4, R35): claims requested fixes one at a time and prepares each
 * in a scratch copy of HEAD with the package managers of its family, then uploads the files, a
 * failure or a no-fix. It never changes the checkout. Exit 0 also when fixes fail; 2 for a
 * configuration problem (not the main branch, not a checkout, musl, flags), 4 when the server
 * cannot be reached or errs, 5 when it refuses the token.
 */
export async function runFix(
  flags: FixFlags,
  io: CliIO,
  log: Logger,
  deps: FixDeps = {},
): Promise<ExitCode> {
  refuseMusl();
  const job = await startJob(flags, io, log, deps);
  reportUnserved(job);
  if (job.served.length === 0) {
    job.log.info(
      'nothing to claim: the repository has no lockfile whose package manager this job has',
    );
    return EXIT.OK;
  }
  await claimLoop(job);
  return EXIT.OK;
}
