// The repository-setup run (onboarding): each repository of a run gets its project (created, or an
// existing one adopted) mapped to it, then its CI: a merge request that adds the Qualor job and
// keeps the project's token in the repository's CI secrets, or a snippet and the token to copy.
// Every step's outcome is saved as soon as it is known, so a retried job resumes where it stopped.
import { and, asc, eq, inArray, isNull, sql } from 'drizzle-orm';
import { z } from 'zod';
import { canonicalJson } from '../audit/canonical';
import { PROJECT_CHANGE_FIELDS } from '../audit/catalogue';
import { SYSTEM_ACTOR, type AuditActorContext, type AuditRecorder } from '../audit/recorder';
import { projectRefs } from '../audit/refs';
import { encryptionKey, encryptSecret } from '../crypto/secrets';
import type { Db, Executor } from '../db/client';
import { PG_UNIQUE_VIOLATION, pgErrorCode } from '../db/errors';
import { first } from '../db/rows';
import {
  apiTokens,
  projects,
  repositorySetupItems,
  repositorySetupRuns,
  scmConnections,
  users,
  type EncryptedValue,
  type SetupCiOutcome,
  type SetupProjectOutcome,
} from '../db/schema';
import { VERSION } from '../index';
import { PROJECT_KEY_PATTERN } from '../patterns';
import type { ProjectRow } from '../projects/access';
import { createProject, type AuditedActor } from '../projects/create';
import { createProjectToken, revokeProjectToken } from '../projects/tokens';
import { enqueue } from '../queue/queue';
import type { JobHandlers, WorkerLogger } from '../queue/worker';
import { queueRemapPurgeIfCopies } from '../review/jobs';
import { readCiSetupStatus, type CiSetupStatus } from '../scm/ci-setup-status';
import {
  forgetForeignMergeRequestUrls,
  gitlabClientFor,
  type ScmConnectionRow,
  type ScmDeps,
} from '../scm/connections';
import type { InstallationTokenCache, MutationPacer } from '../scm/github/app-auth';
import type { GitHubClient } from '../scm/github/client';
import { githubClientFor } from '../scm/github/connections';
import { githubHostKind, parseRepoRef } from '../scm/github/url';
import type { GitLabClient } from '../scm/gitlab/client';
import { gitlabHostKind } from '../scm/gitlab/url';
import { ScmError } from '../scm/provider';
import { planCiSetup, type CiPlan, type CiSetupInput, type CiSnippetReason } from './ci-setup';

export const REPOSITORY_SETUP_QUEUE = 'repository-setup';
/** Repositories one run takes at most. */
export const MAX_SETUP_REPOSITORIES = 50;
export const SETUP_BRANCH = 'qualor/setup';
/** The merge request's title, and the message of its commit. */
export const SETUP_TITLE = 'Add Qualor code analysis';
/** The name of the project analysis token a run makes. */
export const SETUP_TOKEN_NAME = 'CI setup';
/** The AAD of `repository_setup_items.token_enc`. */
export const SETUP_TOKEN_AAD = 'repository_setup_items.token_enc';
/** A repository's name is its project's key; when taken, `-2` … `-20` are tried. */
const MAX_KEY_SUFFIX = 20;
/** Where a snippet points while the server has no public URL: the address the guide uses. */
const URL_PLACEHOLDER = 'https://qualor.example.com';
const PROJECT_NAME_MAX = 255;
/**
 * A rate-limited provider, or a failed read of the connection's CI-setup status, pauses the run:
 * its job is queued again for when the provider says (a minute when it does not), at most this
 * many times; after that the error fails the repository's CI.
 */
const MAX_PAUSES = 5;
const DEFAULT_PAUSE_SECONDS = 60;

/**
 * Why a repository got a snippet instead of a merge request: the planner's reasons, the
 * connection's CI-setup status when it changed after the run started (`not_allowed`,
 * `missing_permissions` for the repository's own installation, `no_public_url`), or a repository
 * without a commit to branch from.
 */
export const SETUP_CI_REASONS = [
  'already_set_up',
  'yaml_unsupported',
  'custom_ci_path',
  'no_public_url',
  'not_allowed',
  'missing_permissions',
  'empty_repository',
] as const;
export type SetupCiReason = (typeof SETUP_CI_REASONS)[number];

export const SETUP_ERROR_CODES = [
  'not_found',
  'key_taken',
  'connection_gone',
  'connection_unusable',
  'project_gone',
  'permission',
  'rate_limited',
  'unavailable',
  'refused',
  'bad_answer',
  'budget',
  'internal',
  'abandoned',
] as const;
export type SetupErrorCode = (typeof SETUP_ERROR_CODES)[number];

/** The fixed texts of the item errors: never the provider's words, which could quote a secret. */
const ERROR_TEXT: Record<Exclude<SetupErrorCode, 'permission'>, string> = {
  not_found: 'The repository was not found, or the connection cannot reach it',
  key_taken: 'Every project key Qualor would give this repository is taken',
  connection_gone: 'The SCM connection was deleted',
  connection_unusable: 'The SCM connection cannot be used; test it in the settings',
  project_gone: 'The project was deleted',
  rate_limited: 'The provider is rate limiting Qualor; try again later',
  unavailable: 'The provider could not be reached; try again later',
  refused: 'The provider refused the change',
  bad_answer: "The provider's answer was not understood",
  budget: 'Too many provider requests for one repository',
  internal: 'Something went wrong; the server log has the details',
  abandoned: 'The run stopped before this repository',
};
/** A refused permission while reading the repository, or while changing it for CI setup. */
const PERMISSION_TEXT = {
  read: 'The connection was refused access to the repository',
  github: 'The GitHub App needs Workflows and Secrets write',
  gitlab: 'The GitLab token needs the api scope and the Maintainer role',
} as const;

export interface SetupRunDeps {
  db: Db;
  scm: ScmDeps;
  /** The `scm` worker's GitHub token cache and mutation pacer (scm/runtime.ts). */
  runtime?: { githubTokens: InstallationTokenCache; githubPacer: MutationPacer };
  publicUrl: string | null;
  audit: AuditRecorder;
  logger?: WorkerLogger;
  /** Where the connection's CI runs; {@link ciHostOf} unless a test stands a fake for github.com. */
  host?: (row: ScmConnectionRow) => 'cloud' | 'self-hosted';
}

/**
 * github.com, GHE.com and gitlab.com run the Qualor Action or CI/CD component; GitHub Enterprise
 * Server and self-managed GitLab get the plain job on the scanner image.
 */
export function ciHostOf(row: {
  provider: 'github' | 'gitlab';
  baseUrl: string;
}): 'cloud' | 'self-hosted' {
  if (row.provider === 'github') {
    return githubHostKind(row.baseUrl) === 'cloud' ? 'cloud' : 'self-hosted';
  }
  return gitlabHostKind(row.baseUrl) === 'gitlab.com' ? 'cloud' : 'self-hosted';
}

const payloadSchema = z.object({
  runId: z.uuid(),
  /** How often the run paused already ({@link MAX_PAUSES}). */
  pauses: z.number().int().min(0).default(0),
});

/**
 * The connection's credentials no longer decrypt, or its address is no longer allowed: every
 * repository of the run fails alike (the connection test says why).
 */
class UnusableConnection extends Error {
  constructor() {
    super('unusable SCM connection');
  }
}

/** The provider is rate limiting: the run stops here and its job comes back in `seconds`. */
class RateLimitPause extends Error {
  constructor(readonly seconds: number) {
    super('rate limited');
  }
}

type RunRow = typeof repositorySetupRuns.$inferSelect;
type ItemRow = typeof repositorySetupItems.$inferSelect;
interface ItemError {
  code: SetupErrorCode;
  message: string;
}

function errorOf(code: Exclude<SetupErrorCode, 'permission'>): ItemError {
  return { code, message: ERROR_TEXT[code] };
}

/** An SCM failure as an item error: a fixed text per kind. */
function scmErrorOf(
  err: ScmError,
  provider: 'github' | 'gitlab',
  stage: 'read' | 'change',
): ItemError {
  switch (err.kind) {
    case 'not_found':
      return errorOf('not_found');
    case 'auth':
      return {
        code: 'permission',
        message: stage === 'read' ? PERMISSION_TEXT.read : PERMISSION_TEXT[provider],
      };
    case 'rate_limited':
      return errorOf('rate_limited');
    case 'transient':
      return errorOf('unavailable');
    case 'refused':
      return errorOf('refused');
    case 'bad_answer':
      return errorOf('bad_answer');
    case 'budget':
      return errorOf('budget');
  }
}

/** Whether the provider answered a refusal (4xx): then the write it refused stored nothing. */
function definitelyRefused(err: unknown): boolean {
  return err instanceof ScmError && err.status !== null && err.status >= 400 && err.status < 500;
}

async function updateItem(
  db: Executor,
  item: Pick<ItemRow, 'runId' | 'position'>,
  values: Partial<typeof repositorySetupItems.$inferInsert>,
): Promise<void> {
  await db
    .update(repositorySetupItems)
    .set(values)
    .where(
      and(
        eq(repositorySetupItems.runId, item.runId),
        eq(repositorySetupItems.position, item.position),
      ),
    );
}

/** The item failed as a whole: no project, so no CI either. */
function failItem(db: Executor, item: ItemRow, error: ItemError): Promise<void> {
  return updateItem(db, item, {
    projectOutcome: item.projectOutcome === 'pending' ? 'failed' : item.projectOutcome,
    ciOutcome: 'failed',
    errorCode: error.code,
    errorMessage: error.message,
  });
}

/** Whom the run's events name: its creator, as a user; the system once the user is gone. */
async function actorOf(db: Executor, userId: string | null): Promise<AuditActorContext> {
  if (userId === null) return SYSTEM_ACTOR;
  const [user] = await db
    .select({ id: users.id, username: users.username })
    .from(users)
    .where(eq(users.id, userId));
  return user
    ? {
        actor: { type: 'user', userId: user.id, username: user.username, tokenId: null },
        ip: null,
        userAgent: null,
      }
    : SYSTEM_ACTOR;
}

// ─── The repository, as the provider names it ─────────────────────────────────────────────

/** What a CI change does on either provider, on the branch {@link SETUP_BRANCH}. */
interface CiRepository {
  /** Whether C# is the repository's main language (GitHub: or a .sln or .csproj at the root). */
  csharp(): Promise<boolean>;
  /** What the planner needs, read from the default branch; `empty`: no commit to branch from. */
  read(): Promise<{
    csharp: boolean;
    empty: boolean;
    customCiPath: boolean;
    existing: CiSetupInput['existing'];
  }>;
  branchExists(): Promise<boolean>;
  createBranch(): Promise<void>;
  /** Writes the files on the branch, skipping those it already holds as planned. */
  writeFiles(
    files: { path: string; content: string; update: boolean }[],
    reused: boolean,
  ): Promise<void>;
  storeToken(token: string): Promise<void>;
  setVariables(variables: { key: string; value: string }[]): Promise<void>;
  findMergeRequest(): Promise<string | null>;
  openMergeRequest(description: string): Promise<string>;
}

interface OpenedRepository {
  /** `owner/repo`, or the GitLab project's full path: the project's key and name. */
  name: string;
  /** What the project maps to: GitHub `owner/repo`, the GitLab project id. */
  mappingRef: string;
  /** Null: an empty GitLab project. */
  defaultBranch: string | null;
  /** The GitHub installation grants what a CI change needs (always true on GitLab). */
  mayChange: boolean;
  ci: CiRepository;
}

const WORKFLOWS = '.github/workflows';
const GITLAB_CI = '.gitlab-ci.yml';

function githubRepository(
  client: GitHubClient,
  found: { full_name: string; default_branch: string },
): OpenedRepository {
  const defaultBranch = found.default_branch;
  const granted = client.installationAccess?.permissions ?? {};
  let baseSha: string | null = null;
  // C#: the main language (the most bytes), or a solution or project file at the root.
  const csharp = async () => {
    if ((await client.languages())[0] === 'C#') return true;
    return (await client.listDirectory('')).some((f) => /\.(sln|csproj)$/i.test(f));
  };
  return {
    name: found.full_name,
    mappingRef: found.full_name,
    defaultBranch,
    mayChange: ['contents', 'workflows', 'secrets'].every((p) => granted[p] === 'write'),
    ci: {
      csharp,
      async read() {
        baseSha = await client.branchSha(defaultBranch);
        const workflowFiles = await client.listDirectory(WORKFLOWS);
        const qualor = workflowFiles.find((f) => /^qualor[^/]*\.ya?ml$/i.test(f));
        return {
          csharp: await csharp(),
          empty: baseSha === null,
          customCiPath: false,
          existing: {
            gitlabCi: null,
            workflowFiles,
            workflowQualor:
              qualor === undefined ? null : await client.fileText(`${WORKFLOWS}/${qualor}`),
            tokenSecretSet: await client.hasActionsSecret('QUALOR_TOKEN'),
          },
        };
      },
      branchExists: async () => (await client.branchSha(SETUP_BRANCH)) !== null,
      async createBranch() {
        const from = baseSha ?? (await client.branchSha(defaultBranch));
        if (from === null) throw new ScmError('not_found', ERROR_TEXT.not_found);
        await client.createBranch(SETUP_BRANCH, from);
      },
      async writeFiles(files, reused) {
        for (const file of files) {
          let sha: string | null = null;
          if (reused || file.update) {
            sha = await client.fileSha(file.path, SETUP_BRANCH);
            if (sha !== null && (await client.fileText(file.path, SETUP_BRANCH)) === file.content) {
              continue;
            }
          }
          await client.putFile({
            path: file.path,
            branch: SETUP_BRANCH,
            content: file.content,
            message: SETUP_TITLE,
            ...(sha === null ? {} : { sha }),
          });
        }
      },
      storeToken: (token) => client.putActionsSecret('QUALOR_TOKEN', token),
      // The server address is in the workflow file: GitHub gets no variable.
      setVariables: async () => undefined,
      findMergeRequest: async () => (await client.findOpenPullRequest(SETUP_BRANCH))?.url ?? null,
      openMergeRequest: async (description) =>
        (
          await client.openPullRequest({
            head: SETUP_BRANCH,
            base: defaultBranch,
            title: SETUP_TITLE,
            body: description,
          })
        ).url,
    },
  };
}

function gitlabRepository(
  client: GitLabClient,
  found: {
    id: number;
    path_with_namespace: string;
    default_branch?: string | null;
    ci_config_path?: string | null;
  },
): OpenedRepository {
  const ref = String(found.id);
  const defaultBranch = found.default_branch ?? null;
  const configPath = found.ci_config_path ?? '';
  // C#: the main language only; the GitLab client lists no tree to look for a .sln or .csproj.
  const csharp = async () => (await client.languages(ref))[0] === 'C#';
  return {
    name: found.path_with_namespace,
    mappingRef: ref,
    defaultBranch,
    mayChange: true,
    ci: {
      csharp,
      async read() {
        return {
          csharp: await csharp(),
          empty: defaultBranch === null,
          // GitLab answers an empty path (or none) for its default file.
          customCiPath: configPath !== '' && configPath !== GITLAB_CI,
          existing: {
            gitlabCi:
              defaultBranch === null ? null : await client.fileText(ref, GITLAB_CI, defaultBranch),
            workflowFiles: [],
            workflowQualor: null,
            tokenSecretSet: (await client.variable(ref, 'QUALOR_TOKEN')) !== null,
          },
        };
      },
      branchExists: () => client.branchExists(ref, SETUP_BRANCH),
      async createBranch() {
        if (defaultBranch === null) throw new ScmError('not_found', ERROR_TEXT.not_found);
        await client.createBranch(ref, SETUP_BRANCH, defaultBranch);
      },
      async writeFiles(files, reused) {
        const actions = [];
        for (const file of files) {
          const current =
            reused || file.update ? await client.fileText(ref, file.path, SETUP_BRANCH) : null;
          if (current === file.content) continue;
          actions.push({
            action: current === null ? ('create' as const) : ('update' as const),
            path: file.path,
            content: file.content,
          });
        }
        if (actions.length > 0) {
          await client.commitFiles(ref, { branch: SETUP_BRANCH, message: SETUP_TITLE, actions });
        }
      },
      // Masked, and not protected: merge request pipelines must read it.
      storeToken: (token) =>
        client.putVariable(ref, {
          key: 'QUALOR_TOKEN',
          value: token,
          masked: true,
          protected: false,
        }),
      async setVariables(variables) {
        for (const v of variables) {
          await client.putVariable(ref, {
            key: v.key,
            value: v.value,
            masked: false,
            protected: false,
          });
        }
      },
      findMergeRequest: async () =>
        (await client.findOpenMergeRequest(ref, SETUP_BRANCH))?.url ?? null,
      async openMergeRequest(description) {
        if (defaultBranch === null) throw new ScmError('not_found', ERROR_TEXT.not_found);
        return (
          await client.openMergeRequest(ref, {
            source: SETUP_BRANCH,
            target: defaultBranch,
            title: SETUP_TITLE,
            description,
          })
        ).url;
      },
    },
  };
}

/**
 * One client for the repository (the request budget is per client), and what the provider calls
 * it. GitHub's token asks for Workflows and Secrets (write) only when the run changes CI.
 */
async function openRepository(
  deps: SetupRunDeps,
  connection: ScmConnectionRow,
  ref: string,
  changesCi: boolean,
): Promise<OpenedRepository> {
  if (connection.provider === 'github') {
    const repo = parseRepoRef(ref);
    if (repo === null) throw new ScmError('not_found', ERROR_TEXT.not_found);
    const made = githubClientFor(connection, deps.scm, deps.runtime);
    if ('problem' in made) throw new UnusableConnection();
    const found = await made.client.useRepository(repo, changesCi ? { ciSetup: true } : {});
    return githubRepository(made.client, found);
  }
  const made = gitlabClientFor(connection, deps.scm);
  if ('problem' in made) throw new UnusableConnection();
  return gitlabRepository(made.client, await made.client.project(ref));
}

// ─── The project ───────────────────────────────────────────────────────────────────────────

/**
 * Maps the project to the repository as `PATCH /projects/:id` does, with its `project.updated`
 * event. An adopted project may still hold review copies of an earlier mapping (an unmap whose
 * purge has not run yet): they go, as `PATCH` has them go (R41).
 */
async function mapProject(
  tx: Executor,
  project: ProjectRow,
  connectionId: string,
  ref: string,
  by: AuditedActor,
): Promise<ProjectRow> {
  const saved = first(
    await tx
      .update(projects)
      .set({ scmConnectionId: connectionId, scmProjectRef: ref, updatedAt: new Date() })
      .where(eq(projects.id, project.id))
      .returning(),
  );
  // scm.md §8: merge request links are kept only on the mapped connection's address.
  if (project.scmConnectionId !== connectionId) {
    await forgetForeignMergeRequestUrls(tx, { projectId: saved.id });
  }
  await queueRemapPurgeIfCopies(tx, project, saved);
  const changes = PROJECT_CHANGE_FIELDS.filter(
    (field) => canonicalJson(project[field]) !== canonicalJson(saved[field]),
  ).map((field) => ({ field, from: project[field], to: saved[field] }));
  if (changes.length > 0 && by.audit.active()) {
    const refs = await projectRefs(tx, saved.id);
    await by.audit.record(tx, by.actor, [
      {
        action: 'project.updated',
        organization: refs.organization,
        project: refs.project,
        target: { type: 'project', id: saved.id, label: saved.name },
        details: { changes },
      },
    ]);
  }
  return saved;
}

/**
 * The item's project, in one transaction with its outcome: the project of the organisation that
 * already maps this repository through this connection (a second run, a retry), else the unmapped
 * project whose key is the repository's name (adopted), else a new one with the first free key of
 * `name`, `name-2` … `name-20`. Null when the item failed (saved too).
 */
async function settleProject(
  deps: SetupRunDeps,
  run: RunRow,
  item: ItemRow,
  connectionId: string,
  repo: OpenedRepository,
  by: AuditedActor,
): Promise<ProjectRow | null> {
  return deps.db.transaction(async (tx) => {
    // Locked as PATCH /projects locks it, before any project: a concurrent DELETE waits.
    const [connection] = await tx
      .select({ id: scmConnections.id })
      .from(scmConnections)
      .where(
        and(
          eq(scmConnections.id, connectionId),
          eq(scmConnections.organizationId, run.organizationId),
        ),
      )
      .for('key share');
    if (!connection) {
      await failItem(tx, item, errorOf('connection_gone'));
      return null;
    }
    const settled = async (outcome: SetupProjectOutcome, project: ProjectRow) => {
      await updateItem(tx, item, {
        projectOutcome: outcome,
        projectId: project.id,
        repositoryName: repo.name,
      });
      return project;
    };
    // GitHub names and GitLab paths compare without case; a GitLab id as written.
    const refs = [...new Set([repo.mappingRef, repo.name].map((r) => r.toLowerCase()))];
    const [mapped] = await tx
      .select()
      .from(projects)
      .where(
        and(
          eq(projects.organizationId, run.organizationId),
          eq(projects.scmConnectionId, connection.id),
          inArray(sql`lower(${projects.scmProjectRef})`, refs),
        ),
      )
      .orderBy(asc(projects.createdAt))
      .limit(1);
    if (mapped) return settled('adopted', mapped);
    const [free] = await tx
      .select()
      .from(projects)
      .where(
        and(
          eq(projects.organizationId, run.organizationId),
          eq(projects.key, repo.name),
          isNull(projects.scmConnectionId),
        ),
      )
      .for('no key update');
    if (free) {
      return settled('adopted', await mapProject(tx, free, connection.id, repo.mappingRef, by));
    }
    const candidates = [
      repo.name,
      ...Array.from({ length: MAX_KEY_SUFFIX - 1 }, (_, i) => `${repo.name}-${i + 2}`),
    ].filter((key) => PROJECT_KEY_PATTERN.test(key));
    const taken = new Set(
      candidates.length === 0
        ? []
        : (
            await tx
              .select({ key: projects.key })
              .from(projects)
              .where(inArray(projects.key, candidates))
          ).map((p) => p.key),
    );
    for (const key of candidates) {
      if (taken.has(key)) continue;
      let created: ProjectRow;
      try {
        // A savepoint: a key taken meanwhile fails it alone, and the next key is tried.
        created = await tx.transaction((sp) =>
          createProject(sp, {
            organizationId: run.organizationId,
            key,
            name: repo.name.slice(0, PROJECT_NAME_MAX),
            mainBranchName: repo.defaultBranch ?? 'main',
            createdBy: by,
          }),
        );
      } catch (err) {
        if (pgErrorCode(err) === PG_UNIQUE_VIOLATION) continue;
        throw err;
      }
      return settled('created', await mapProject(tx, created, connection.id, repo.mappingRef, by));
    }
    await failItem(tx, item, errorOf('key_taken'));
    return null;
  });
}

// ─── CI ────────────────────────────────────────────────────────────────────────────────────

/** Whether the project has a live CI setup token already: a snippet then gets no second one. */
async function hasSetupToken(db: Executor, projectId: string): Promise<boolean> {
  const [row] = await db
    .select({ id: apiTokens.id })
    .from(apiTokens)
    .where(
      and(
        eq(apiTokens.projectId, projectId),
        eq(apiTokens.name, SETUP_TOKEN_NAME),
        isNull(apiTokens.revokedAt),
      ),
    )
    .limit(1);
  return row !== undefined;
}

function createSetupToken(
  tx: Executor,
  projectId: string,
  by: AuditedActor,
  userId: string | null,
) {
  return createProjectToken(tx, {
    projectId,
    name: SETUP_TOKEN_NAME,
    scopes: ['analysis:write'],
    expiresAt: null,
    createdBy: { ...by, userId },
  });
}

/** The snippet a repository without CI would get: the planner's change for a fresh repository. */
function freshSnippet(input: Omit<CiSetupInput, 'existing'>): string {
  const plan = planCiSetup({
    ...input,
    existing: { gitlabCi: null, workflowFiles: [], workflowQualor: null, tokenSecretSet: false },
  });
  return plan.kind === 'change' ? (plan.files[0]?.content ?? '') : plan.snippet;
}

interface ItemContext {
  deps: SetupRunDeps;
  run: RunRow;
  item: ItemRow;
  connection: ScmConnectionRow;
  status: CiSetupStatus | null;
  by: AuditedActor;
  /** The CI-setup status could not be read, and the run paused as often as it may. */
  statusFailure: ScmError | null;
  /** A rate limit pauses the run (rather than failing the repository). */
  mayPause: boolean;
}

/**
 * The item's CI outcome with a snippet to copy, and the token revealed once with it: a new CI
 * setup token, unless the project already has a live one (a second run of the same repository).
 */
async function finishWithSnippet(
  ctx: ItemContext,
  projectId: string,
  outcome: Extract<SetupCiOutcome, 'snippet' | 'skipped'>,
  reason: SetupCiReason | null,
  snippet: string,
): Promise<void> {
  const key = encryptionKey(ctx.deps.scm.secretKey);
  await ctx.deps.db.transaction(async (tx) => {
    let tokenEnc: EncryptedValue | null = null;
    if (!(await hasSetupToken(tx, projectId))) {
      const { token } = await createSetupToken(tx, projectId, ctx.by, ctx.run.createdBy);
      tokenEnc = encryptSecret(key, token, SETUP_TOKEN_AAD);
    }
    await updateItem(tx, ctx.item, { ciOutcome: outcome, ciReason: reason, snippet, tokenEnc });
  });
}

/**
 * CI setup for one repository: the plan, then for a change the branch, the files, the token in
 * the CI secrets and the merge request, in that order (the pipeline the merge request starts
 * finds the token). A token whose write failed is revoked; one that may be stored stays.
 */
async function setUpCi(ctx: ItemContext, repo: OpenedRepository, projectId: string): Promise<void> {
  const { deps, run, connection, status, item } = ctx;
  const base = {
    provider: connection.provider,
    host: (deps.host ?? ciHostOf)(connection),
    serverUrl: deps.publicUrl ?? URL_PLACEHOLDER,
    version: VERSION,
    defaultBranch: repo.defaultBranch ?? 'main',
  };
  const snippet = async (
    outcome: 'snippet' | 'skipped',
    reason: SetupCiReason | null,
    csharp?: boolean,
  ) => {
    let isCsharp = csharp ?? false;
    if (csharp === undefined) {
      try {
        isCsharp = await repo.ci.csharp();
      } catch (err) {
        // The snippet is still worth giving without the language.
        if (!(err instanceof ScmError)) throw err;
      }
    }
    await finishWithSnippet(
      ctx,
      projectId,
      outcome,
      reason,
      freshSnippet({ ...base, csharp: isCsharp }),
    );
  };
  if (!run.ciSetup) return snippet('skipped', null);
  if (status === null || !status.available) {
    return snippet('snippet', status?.reason ?? 'not_allowed');
  }
  if (!repo.mayChange) return snippet('snippet', 'missing_permissions');
  if (repo.defaultBranch === null) return snippet('snippet', 'empty_repository');

  const read = await repo.ci.read();
  if (read.empty) return snippet('snippet', 'empty_repository', read.csharp);
  if (read.customCiPath) return snippet('snippet', 'custom_ci_path', read.csharp);
  const input: CiSetupInput = { ...base, csharp: read.csharp, existing: read.existing };
  const plan: CiPlan = planCiSetup(input);
  if (plan.kind === 'snippet') {
    if (plan.reason !== 'already_set_up') {
      return finishWithSnippet(ctx, projectId, 'snippet', plan.reason, plan.snippet);
    }
    const open = await repo.ci.findMergeRequest();
    if (open !== null) {
      return updateItem(deps.db, item, { ciOutcome: 'merge_request', ciUrl: open });
    }
    // A run that stored the token and then could not open the merge request: open it now.
    if (read.existing.tokenSecretSet) {
      const resumed = planCiSetup({
        ...input,
        existing: { ...input.existing, tokenSecretSet: false },
      });
      if (resumed.kind === 'change' && (await repo.ci.branchExists())) {
        // What failed after the token may be a variable: set them again (an upsert) first.
        await repo.ci.setVariables(resumed.variables);
        const url = await repo.ci.openMergeRequest(resumed.description);
        return updateItem(deps.db, item, { ciOutcome: 'merge_request', ciUrl: url });
      }
    }
    return updateItem(deps.db, item, {
      ciOutcome: 'already',
      ciReason: 'already_set_up' satisfies CiSnippetReason,
      snippet: plan.snippet,
    });
  }

  const reused = await repo.ci.branchExists();
  if (!reused) await repo.ci.createBranch();
  await repo.ci.writeFiles(plan.files, reused);
  // Made only now, committed before it is written: the token is never stored in Qualor.
  const { row, token } = await deps.db.transaction((tx) =>
    createSetupToken(tx, projectId, ctx.by, run.createdBy),
  );
  let stored = false;
  try {
    try {
      await repo.ci.storeToken(token);
    } catch (err) {
      // A refusal stored nothing; a lost answer may have stored it.
      stored = !definitelyRefused(err);
      throw err;
    }
    stored = true;
    await repo.ci.setVariables(plan.variables);
    const url =
      (await repo.ci.findMergeRequest()) ?? (await repo.ci.openMergeRequest(plan.description));
    await updateItem(deps.db, item, { ciOutcome: 'merge_request', ciUrl: url });
  } catch (err) {
    if (!stored) {
      await deps.db.transaction((tx) =>
        revokeProjectToken(tx, { projectId, tokenId: row.id, revokedBy: ctx.by }),
      );
    }
    throw err;
  }
}

// ─── The run ───────────────────────────────────────────────────────────────────────────────

function pauseFor(err: ScmError): RateLimitPause {
  return new RateLimitPause(err.retryAfterSeconds ?? DEFAULT_PAUSE_SECONDS);
}

async function setUpRepository(ctx: ItemContext): Promise<void> {
  const { deps, run, connection, status, item } = ctx;
  const provider = connection.provider;
  const changesCi = run.ciSetup && status?.available === true;
  const log = { runId: run.id, position: item.position };
  let repo: OpenedRepository;
  try {
    repo = await openRepository(deps, connection, item.repositoryRef, changesCi);
  } catch (err) {
    let error: ItemError;
    if (err instanceof UnusableConnection) {
      error = errorOf('connection_unusable');
    } else if (err instanceof ScmError) {
      if (err.kind === 'rate_limited' && ctx.mayPause) throw pauseFor(err);
      deps.logger?.warn(
        { ...log, kind: err.kind, reason: err.reason, status: err.status },
        'repository setup could not read the repository',
      );
      error = scmErrorOf(err, provider, 'read');
    } else {
      throw err;
    }
    if (item.projectOutcome === 'pending') return failItem(deps.db, item, error);
    return updateItem(deps.db, item, {
      ciOutcome: 'failed',
      errorCode: error.code,
      errorMessage: error.message,
    });
  }

  let projectId = item.projectId;
  if (item.projectOutcome === 'pending') {
    const project = await settleProject(deps, run, item, connection.id, repo, ctx.by);
    if (project === null) return;
    projectId = project.id;
  } else if (projectId === null) {
    return updateItem(deps.db, item, {
      ciOutcome: 'failed',
      errorCode: 'project_gone',
      errorMessage: ERROR_TEXT.project_gone,
    });
  }
  if (run.ciSetup && ctx.statusFailure !== null) {
    // Never a snippet for want of an answer: the CI setup fails, with why.
    const error = scmErrorOf(ctx.statusFailure, provider, 'read');
    return updateItem(deps.db, item, {
      ciOutcome: 'failed',
      errorCode: error.code,
      errorMessage: error.message,
    });
  }

  try {
    await setUpCi(ctx, repo, projectId);
  } catch (err) {
    if (!(err instanceof ScmError)) throw err;
    // The item stays pending: the next job resumes it (the branch is reused, the files kept).
    if (err.kind === 'rate_limited' && ctx.mayPause) throw pauseFor(err);
    deps.logger?.warn(
      { ...log, kind: err.kind, reason: err.reason, status: err.status },
      'repository setup could not set up CI',
    );
    const error = scmErrorOf(err, provider, 'change');
    await updateItem(deps.db, item, {
      ciOutcome: 'failed',
      errorCode: error.code,
      errorMessage: error.message,
    });
  }
}

/** The same run, later: the job is queued again, under the same key (one job per connection). */
async function pauseRun(
  deps: SetupRunDeps,
  run: RunRow,
  connectionId: string,
  pauses: number,
  seconds: number,
): Promise<void> {
  await enqueue(deps.db, {
    queue: REPOSITORY_SETUP_QUEUE,
    payload: { runId: run.id, pauses: pauses + 1 },
    concurrencyKey: connectionId,
    runAt: sql`now() + make_interval(secs => ${seconds})`,
  });
}

async function runSetup(deps: SetupRunDeps, payload: z.infer<typeof payloadSchema>): Promise<void> {
  const { runId, pauses } = payload;
  const [run] = await deps.db
    .select()
    .from(repositorySetupRuns)
    .where(eq(repositorySetupRuns.id, runId));
  if (!run || run.status === 'done') return;
  if (run.status === 'queued') {
    await deps.db
      .update(repositorySetupRuns)
      .set({ status: 'running' })
      .where(eq(repositorySetupRuns.id, run.id));
  }
  const [connection] =
    run.connectionId === null
      ? []
      : await deps.db
          .select()
          .from(scmConnections)
          .where(
            and(
              eq(scmConnections.id, run.connectionId),
              eq(scmConnections.organizationId, run.organizationId),
            ),
          );
  const by: AuditedActor = { audit: deps.audit, actor: await actorOf(deps.db, run.createdBy) };
  // Read once per run, uncached: the GitHub installations' permissions, the GitLab setting, the
  // URL. Only a definite "not available" turns the repositories' CI into snippets; a failed read
  // pauses the run and reads again later.
  let status: CiSetupStatus | null = null;
  let statusFailure: ScmError | null = null;
  if (connection && run.ciSetup) {
    try {
      status = await readCiSetupStatus(connection, deps.scm, deps.publicUrl);
    } catch (err) {
      if (!(err instanceof ScmError)) throw err;
      deps.logger?.warn(
        { runId: run.id, kind: err.kind, reason: err.reason, status: err.status },
        'repository setup could not read the CI-setup status',
      );
      // An unusable connection (its key, its address) does not get better: each repository
      // fails on it at once.
      if (err.reason !== 'invalid_input' && pauses < MAX_PAUSES) {
        const seconds = err.retryAfterSeconds ?? DEFAULT_PAUSE_SECONDS;
        await pauseRun(deps, run, connection.id, pauses, seconds);
        deps.logger?.info(
          { runId: run.id, retryInSeconds: seconds },
          'repository setup paused: the CI-setup status could not be read',
        );
        return;
      }
      statusFailure = err;
    }
  }
  const items = await deps.db
    .select()
    .from(repositorySetupItems)
    .where(eq(repositorySetupItems.runId, run.id))
    .orderBy(asc(repositorySetupItems.position));
  for (const item of items) {
    if (item.projectOutcome !== 'pending' && item.ciOutcome !== 'pending') continue;
    if (!connection) {
      await failItem(deps.db, item, errorOf('connection_gone'));
      continue;
    }
    try {
      await setUpRepository({
        deps,
        run,
        item,
        connection,
        status,
        statusFailure,
        by,
        mayPause: pauses < MAX_PAUSES,
      });
    } catch (err) {
      if (err instanceof RateLimitPause) {
        await pauseRun(deps, run, connection.id, pauses, err.seconds);
        deps.logger?.info(
          { runId: run.id, position: item.position, retryInSeconds: err.seconds },
          'repository setup paused: the provider is rate limiting',
        );
        return;
      }
      // One repository's failure never loses the others (no token is in this error: the clients'
      // errors are ScmErrors, handled above, and the token never reaches a query).
      deps.logger?.error(
        { err, runId: run.id, position: item.position },
        'repository setup failed',
      );
      const [now] = await deps.db
        .select()
        .from(repositorySetupItems)
        .where(
          and(
            eq(repositorySetupItems.runId, item.runId),
            eq(repositorySetupItems.position, item.position),
          ),
        );
      await failItem(deps.db, now ?? item, errorOf('internal'));
    }
  }
  await deps.db
    .update(repositorySetupRuns)
    .set({ status: 'done', finishedAt: new Date() })
    .where(eq(repositorySetupRuns.id, run.id));
}

/** The `repository-setup` queue's handler; the `scm` worker runs it (main.ts). */
export function repositorySetupHandlers(deps: SetupRunDeps): JobHandlers {
  return {
    [REPOSITORY_SETUP_QUEUE]: async (job) => {
      const parsed = payloadSchema.safeParse(job.payload);
      if (!parsed.success) {
        deps.logger?.warn({ jobId: job.id }, 'malformed repository-setup job payload; completing');
        return;
      }
      await runSetup(deps, parsed.data);
    },
  };
}

/**
 * Finishes the runs whose job is gone (dead after its attempts, or lost): their unfinished
 * repositories fail as `abandoned`, so the page polling them stops. The `scm` worker runs it after
 * every reap. Returns the number of runs finished.
 */
export async function reconcileStuckSetupRuns(db: Executor): Promise<number> {
  const result = await db.execute(sql`
    WITH stuck AS (
      SELECT r.id FROM repository_setup_runs r
       WHERE r.status <> 'done'
         AND NOT EXISTS (
               SELECT 1 FROM jobs j
                WHERE j.queue = ${REPOSITORY_SETUP_QUEUE} AND j.status IN ('queued', 'running')
                  -- Compared as text: a malformed payload must not make the sweep fail.
                  AND j.payload ->> 'runId' = r.id::text)
    ), items AS (
      UPDATE repository_setup_items i
         SET project_outcome = CASE WHEN i.project_outcome = 'pending' THEN 'failed'
                                    ELSE i.project_outcome END,
             ci_outcome = 'failed',
             error_code = 'abandoned',
             error_message = ${ERROR_TEXT.abandoned}
        FROM stuck
       WHERE i.run_id = stuck.id AND (i.project_outcome = 'pending' OR i.ci_outcome = 'pending')
    )
    UPDATE repository_setup_runs r
       SET status = 'done', finished_at = now()
      FROM stuck
     WHERE r.id = stuck.id`);
  return result.rowCount ?? 0;
}
